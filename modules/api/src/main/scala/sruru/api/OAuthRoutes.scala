package sruru.api

import cats.effect.*
import cats.syntax.all.*
import io.circe.Json
import io.circe.syntax.*
import org.http4s.*
import org.http4s.circe.CirceEntityCodec.*
import org.http4s.headers.{Authorization, Location}
import sruru.db.*
import sruru.security.*
import sruru.shared.*

import java.net.URLDecoder
import java.nio.charset.StandardCharsets

/**
 * 兄弟のサービス（skakapo など）への OAuth 2.0（認可コード + PKCE（S256）. RFC 6749・7636・7009）.
 *
 * OIDC（OidcRoutes の /oauth2/…）は「applications に登録したアプリへのログイン」で、クライアントも同意も DB で管理する.
 * こちらは「兄弟のサービスが、利用者の権限で sruru の API・MCP を使う」ためのもので、クライアントは環境変数 OAUTH_CLIENTS で登録する.
 * 発行するアクセストークンは、その利用者の API トークン（read だけ・1時間）なので、REST・MCP の権限の判定（Principal）がそのまま効く.
 * 管理の API は admin スコープが要るので、このトークンでは使えない. 連携は個人設定の「API トークン」の画面から確かめ・取り消せる.
 */
final class OAuthRoutes(store: OAuthStore, dir: Directory, val auth: SessionAuth, audit: AuditService, cfg: ApiConfig) extends RouteSupport:

  private val CodeTtlSeconds    = 60L
  private val AccessTtlSeconds  = 3600L
  private val RefreshTtlSeconds = 90L * 24 * 3600
  private val CsrfCookie        = "sruru_oauth_csrf"

  private def client(id: String): Option[OAuthClient] = cfg.oauthClients.find(_.id == id)

  // ------------------------------------------------------------------ 補助

  /** redirect_uri に結果を付けて戻す. */
  private def back(uri: String, params: (String, Option[String])*): IO[Response[IO]] =
    val target = params.collect { case (k, Some(v)) => k -> v }.foldLeft(Uri.unsafeFromString(uri))((u, kv) => u.withQueryParam(kv._1, kv._2))
    IO.pure(Response[IO](Status.Found).putHeaders(Location(target), "Cache-Control" -> "no-store"))

  private val Csp = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'"

  /**
   * 許可の画面. CSP の form-action は付けない（送信後のリダイレクトの連鎖にも効くため、連携元が callback の後に別の origin へ戻すと止まる）.
   * CSRF は Cookie と hidden の値の照合で防ぐ.
   */
  private def page(title: String, body: String, status: Status = Status.Ok): IO[Response[IO]] =
    val html = s"""<!DOCTYPE html><html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
      |<title>${Html.escape(title)} | sruru</title><style>
      |:root{color-scheme:light dark}body{margin:0;font-family:system-ui,-apple-system,"Hiragino Sans","Noto Sans JP",sans-serif;background:#f1f5f9;color:#1e293b;
      |display:flex;min-height:100vh;align-items:center;justify-content:center;padding:1rem;box-sizing:border-box}
      |@media(prefers-color-scheme:dark){body{background:#0f172a;color:#e2e8f0}.card{background:#1c273d!important;border-color:#283548!important}}
      |.card{background:#fff;border:1px solid #e2e8f0;border-radius:14px;padding:1.6rem 1.8rem;max-width:460px;width:100%;box-sizing:border-box;
      |box-shadow:0 11px 15px -7px rgba(0,0,0,.2),0 24px 38px 3px rgba(0,0,0,.14)}
      |h1{font-size:1.15rem;margin:0 0 .8rem}p{line-height:1.7;margin:.4rem 0}.muted{color:#64748b;font-size:.85rem}.logo{color:#2563eb;font-weight:800}
      |.actions{display:flex;gap:.6rem;justify-content:flex-end;margin-top:1.2rem}button{font:inherit;border-radius:8px;padding:.5rem 1.1rem;cursor:pointer;
      |border:1px solid #cbd5e1;background:transparent;color:inherit}button.primary{background:#2563eb;border-color:#2563eb;color:#fff}
      |ul{padding-left:1.2rem;margin:.4rem 0;line-height:1.7}code{font-size:.85em}</style></head><body><div class="card"><div class="logo">sruru</div>$body</div></body></html>""".stripMargin
    IO.pure(Html.response(html, Csp, status))

  private def errorPage(msg: String): IO[Response[IO]] =
    page("連携できません", s"""<h1>連携できません</h1><p>${Html.escape(msg)}</p><p class="muted">連携元のサービスの設定を確かめてください。</p>""",
      Status.BadRequest)

  /** スコープの説明（許可の画面）. */
  private def describe(scope: String): String = scope match
    case TokenScopes.Read => "あなたの情報・所属グループ・使えるアプリ（ポータル）などを読み取ります"
    case other            => other

  private def scopeList(raw: Option[String]): List[String] =
    raw.map(_.split(' ').map(_.trim).filter(_.nonEmpty).toList.distinct).filter(_.nonEmpty).getOrElse(List(TokenScopes.Read))

  /** クライアントに許した範囲（かつ read だけ）に収まっているか. */
  private def scopesFor(c: OAuthClient, raw: Option[String]): Option[List[String]] =
    val rs = scopeList(raw)
    Option.when(rs.forall(s => c.scopes.contains(s) && OAuthClient.Allowed(s)))(rs)

  private final case class AuthzReq(client: OAuthClient, redirectUri: String, state: Option[String], challenge: String, scopes: List[String])

  /** 認可の要求の確認. client_id・redirect_uri が正しくなければ（戻し先を信用できないので）リダイレクトせずに 400 の画面. */
  private def validate(p: String => Option[String]): Either[IO[Response[IO]], AuthzReq] =
    (p("client_id").flatMap(client), p("redirect_uri")) match
      case (None, _) => Left(errorPage("登録されていないクライアントです（client_id）"))
      case (Some(c), r) if !r.contains(c.redirectUri) => Left(errorPage("戻り先（redirect_uri）が登録されたものと一致しません"))
      case (Some(c), _) =>
        val state = p("state")
        def fail(e: String, d: String) = Left(back(c.redirectUri, "error" -> Some(e), "error_description" -> Some(d), "state" -> state))
        if !p("response_type").contains("code") then fail("unsupported_response_type", "response_type は code だけです")
        else if !p("code_challenge_method").contains("S256") || !p("code_challenge").exists(_.matches("^[A-Za-z0-9_-]{43}$")) then
          fail("invalid_request", "PKCE（code_challenge_method=S256）が必要です")
        else
          scopesFor(c, p("scope")) match
            case None     => fail("invalid_scope", "このクライアントに許していないスコープです（渡せるのは read だけです）")
            case Some(ss) => Right(AuthzReq(c, c.redirectUri, state, p("code_challenge").get, ss))

  /** ブラウザでログインしている利用者（IP 制限も確かめる. Bearer では許可させない）. */
  private def webUser(req: Request[IO]): IO[Option[Principal]] =
    if req.headers.get[Authorization].isDefined then IO.pure(None)
    else auth.principal(req).map(_.filter(_.via.isInstanceOf[Via.Web]))

  private def oauthError(status: Status, code: String, desc: String): IO[Response[IO]] =
    IO.pure(Response[IO](status).withEntity(Json.obj("error" -> code.asJson, "error_description" -> desc.asJson))
      .putHeaders("Cache-Control" -> "no-store", "Pragma" -> "no-cache")
      .putHeaders((if status == Status.Unauthorized then List[Header.ToRaw]("WWW-Authenticate" -> "Basic realm=\"sruru\"") else Nil)*))

  /** クライアントの認証（Basic. RFC 6749 2.3.1 のとおり、ID とシークレットは form-urlencoded で符号化されている）. */
  private def basicClient(req: Request[IO]): Option[OAuthClient] =
    req.headers.get[Authorization].collect { case Authorization(BasicCredentials(id, secret)) =>
      (URLDecoder.decode(id, StandardCharsets.UTF_8), URLDecoder.decode(secret, StandardCharsets.UTF_8))
    }.flatMap((id, secret) => client(id).filter(c => Crypto.constantTimeEquals(c.secret, secret)))

  private def form(req: Request[IO])(f: Map[String, String] => IO[Response[IO]]): IO[Response[IO]] =
    req.as[UrlForm].attempt.flatMap {
      case Left(_)  => oauthError(Status.BadRequest, "invalid_request", "application/x-www-form-urlencoded で送ってください")
      case Right(u) => f(u.values.view.mapValues(_.headOption.map(_.trim).getOrElse("")).filter(_._2.nonEmpty).toMap)
    }

  /** アクセストークン（API トークン）とリフレッシュトークンを作る. */
  private def newTokens(c: OAuthClient, scopes: List[String], now: java.time.Instant): (String, NewApiToken, String) =
    val (at, prefix) = ApiTokens.generate()
    (at, NewApiToken(s"${c.name} 連携（OAuth）", prefix, Crypto.sha256(at), scopes, now.plusSeconds(AccessTtlSeconds)), Crypto.randomToken())

  private def tokenJson(at: String, rt: String, scopes: List[String]): IO[Response[IO]] =
    Ok(Json.obj("access_token" -> at.asJson, "token_type" -> "Bearer".asJson, "expires_in" -> AccessTtlSeconds.asJson,
      "refresh_token" -> rt.asJson, "scope" -> scopes.mkString(" ").asJson)).map(_.putHeaders("Cache-Control" -> "no-store", "Pragma" -> "no-cache"))

  // ------------------------------------------------------------------ 認可

  private def authorizePage(req: Request[IO]): IO[Response[IO]] =
    val p = (k: String) => req.params.get(k).map(_.trim).filter(_.nonEmpty)
    validate(p) match
      case Left(r) => r
      case Right(a) =>
        webUser(req).flatMap {
          case None =>
            // ログインしてから、この要求に戻る
            IO.pure(Response[IO](Status.Found).putHeaders(Location(Uri.unsafeFromString("/login").withQueryParam("returnTo", req.uri.renderString)),
              "Cache-Control" -> "no-store"))
          case Some(u) =>
            val csrf   = Crypto.randomToken(24)
            val hidden = List("client_id", "redirect_uri", "state", "code_challenge", "code_challenge_method", "response_type", "scope")
              .flatMap(k => p(k).map(v => s"""<input type="hidden" name="$k" value="${Html.escape(v)}">""")).mkString
            val name   = Html.escape(a.client.name)
            val scopes = a.scopes.map(s => s"<li><code>${Html.escape(s)}</code>: ${Html.escape(describe(s))}</li>").mkString
            page(s"${a.client.name} との連携", s"""<h1>${name} との連携</h1>
              |<p><b>${name}</b> が、あなた（${Html.escape(u.user.name)}）の権限で sruru を使います。</p>
              |<ul>$scopes</ul>
              |<ul class="muted"><li>読み取りだけです。利用者・グループ・アプリ・秘密の値の変更などの管理の操作はできません</li>
              |<li>個人設定の「API トークン」から、いつでも連携をやめられます</li></ul>
              |<form method="post" action="/oauth/authorize">$hidden<input type="hidden" name="csrf" value="$csrf">
              |<div class="actions"><button type="submit" name="decision" value="deny">拒否する</button>
              |<button type="submit" name="decision" value="allow" class="primary">許可する</button></div></form>""".stripMargin)
              .map(_.addCookie(ResponseCookie(CsrfCookie, csrf, path = Some("/oauth"), httpOnly = true, secure = cfg.cookieSecure,
                sameSite = Some(SameSite.Strict), maxAge = Some(600))))
        }

  private def authorizeDecision(req: Request[IO]): IO[Response[IO]] =
    req.as[UrlForm].attempt.flatMap {
      case Left(_) => errorPage("要求が正しくありません")
      case Right(u) =>
        val p = (k: String) => u.getFirst(k).map(_.trim).filter(_.nonEmpty)
        validate(p) match
          case Left(r) => r
          case Right(a) =>
            val csrfOk = req.cookies.find(_.name == CsrfCookie).exists(ck => p("csrf").exists(v => Crypto.constantTimeEquals(ck.content, v)))
            webUser(req).flatMap {
              case None                => errorPage("ログインが切れました。連携元の画面からやり直してください")
              case Some(_) if !csrfOk  => errorPage("画面の有効期限が切れました。連携元の画面からやり直してください")
              case Some(pr) if p("decision").contains("allow") =>
                val code = Crypto.randomToken()
                for
                  now <- Time.now
                  _   <- store.createCode(Crypto.sha256(code), OAuthCode(a.client.id, pr.id, a.redirectUri, a.challenge, a.scopes),
                           now.plusSeconds(CodeTtlSeconds))
                  _   <- audited(audit, req, pr, "oauth.authorize", audit.userTarget(pr.user),
                           Json.obj("client" -> a.client.id.asJson, "scopes" -> a.scopes.asJson))
                  r   <- back(a.redirectUri, "code" -> Some(code), "state" -> a.state)
                yield r
              case Some(_) => back(a.redirectUri, "error" -> Some("access_denied"), "error_description" -> Some("利用者が許可しませんでした"), "state" -> a.state)
            }.map(_.removeCookie(ResponseCookie(CsrfCookie, "", path = Some("/oauth"))))
    }

  // ------------------------------------------------------------------ トークン

  private def token(req: Request[IO]): IO[Response[IO]] =
    basicClient(req) match
      case None => oauthError(Status.Unauthorized, "invalid_client", "クライアントの認証（Basic）に失敗しました")
      case Some(c) =>
        form(req) { f =>
          Time.now.flatMap { now =>
            f.get("grant_type") match
              case Some("authorization_code") => byCode(req, c, f, now)
              case Some("refresh_token")      => byRefresh(req, c, f, now)
              case None    => oauthError(Status.BadRequest, "invalid_request", "grant_type がありません")
              case Some(_) => oauthError(Status.BadRequest, "unsupported_grant_type", "grant_type は authorization_code・refresh_token です")
          }
        }

  private def byCode(req: Request[IO], c: OAuthClient, f: Map[String, String], now: java.time.Instant): IO[Response[IO]] =
    (f.get("code"), f.get("redirect_uri"), f.get("code_verifier")) match
      case (Some(code), Some(uri), Some(verifier)) if verifier.length >= 43 && verifier.length <= 128 =>
        store.consumeCode(Crypto.sha256(code), now).flatMap {
          case Some(oc) if oc.clientId == c.id && oc.redirectUri == uri && Crypto.constantTimeEquals(oc.codeChallenge, Crypto.pkceS256(verifier)) =>
            dir.users.find(oc.userId).flatMap {
              case Some(u) if !u.disabled =>
                val (at, nt, rt) = newTokens(c, oc.scopes, now)
                for
                  _  <- store.replaceGrant(u.id, c.id, oc.scopes, nt, Crypto.sha256(rt), now.plusSeconds(RefreshTtlSeconds))
                  cx <- ctx(req)
                  _  <- audit.log(cx, Some(u), "oauth", "oauth.grant", audit.userTarget(u), detail = Json.obj("client" -> c.id.asJson, "scopes" -> oc.scopes.asJson))
                  r  <- tokenJson(at, rt, oc.scopes)
                yield r
              case _ => oauthError(Status.BadRequest, "invalid_grant", "利用者が無効です")
            }
          case _ => oauthError(Status.BadRequest, "invalid_grant", "認可コードが無効です（期限切れ・使用済み・不一致）")
        }
      case _ => oauthError(Status.BadRequest, "invalid_request", "code・redirect_uri・code_verifier（43〜128文字）を指定してください")

  private def byRefresh(req: Request[IO], c: OAuthClient, f: Map[String, String], now: java.time.Instant): IO[Response[IO]] =
    f.get("refresh_token") match
      case None => oauthError(Status.BadRequest, "invalid_request", "refresh_token がありません")
      // 求められたスコープは、許した範囲（read）に収まっていなければならない（広げることはできない）
      case Some(_) if f.contains("scope") && scopesFor(c, f.get("scope")).isEmpty =>
        oauthError(Status.BadRequest, "invalid_scope", "このクライアントに許していないスコープです（渡せるのは read だけです）")
      case Some(rt) =>
        val (at, nt, next) = newTokens(c, Nil, now)
        store.refresh(Crypto.sha256(rt), c.id, Crypto.sha256(next), nt, now.plusSeconds(RefreshTtlSeconds), now).flatMap {
          case RefreshResult.Ok(g, _) =>
            dir.users.find(g.userId).flatMap {
              case Some(u) if !u.disabled => tokenJson(at, next, g.scopes)
              case _ => store.revoke(g.userId, c.id) *> oauthError(Status.BadRequest, "invalid_grant", "利用者が無効です")
            }
          case RefreshResult.Reused =>
            ctx(req).flatMap(cx => audit.log(cx, None, "oauth", "oauth.refresh_reused", success = false, detail = Json.obj("client" -> c.id.asJson))) *>
              oauthError(Status.BadRequest, "invalid_grant", "リフレッシュトークンはすでに使われています（連携を取り消しました）")
          case RefreshResult.Invalid => oauthError(Status.BadRequest, "invalid_grant", "リフレッシュトークンが無効か期限切れです")
        }

  private def revoke(req: Request[IO]): IO[Response[IO]] =
    basicClient(req) match
      case None    => oauthError(Status.Unauthorized, "invalid_client", "クライアントの認証（Basic）に失敗しました")
      case Some(c) => form(req)(f => f.get("token").traverse_(t => store.revokeByToken(Crypto.sha256(t), c.id)) *> Ok())

  // ------------------------------------------------------------------ 個人設定（連携しているサービス）

  private def grants(p: Principal): IO[List[OAuthGrantDto]] =
    store.grantsOf(p.id).map(_.map(g => OAuthGrantDto(g.clientId, client(g.clientId).fold(g.clientId)(_.name), g.scopes, g.createdAt, g.lastUsedAt)))

  val routes: HttpRoutes[IO] = HttpRoutes.of[IO] {
    case req @ GET -> Root / "oauth" / "authorize"  => authorizePage(req)
    case req @ POST -> Root / "oauth" / "authorize" => authorizeDecision(req)
    case req @ POST -> Root / "oauth" / "token"     => token(req)
    case req @ POST -> Root / "oauth" / "revoke"    => revoke(req)

    case req @ GET -> Root / "api" / "me" / "oauth" => authed(req)(p => grants(p).flatMap(Ok(_)))
    case req @ DELETE -> Root / "api" / "me" / "oauth" / clientId =>
      authed(req)(p => store.revoke(p.id, clientId).flatMap {
        case true  => audited(audit, req, p, "oauth.revoke", audit.userTarget(p.user), Json.obj("client" -> clientId.asJson)) *> NoContent()
        case false => err(Status.NotFound, "見つかりません")
      })
  }
