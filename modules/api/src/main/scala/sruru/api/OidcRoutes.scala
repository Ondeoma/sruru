package sruru.api

import cats.effect.*
import cats.syntax.all.*
import io.circe.Json
import io.circe.syntax.*
import org.http4s.*
import org.http4s.circe.CirceEntityCodec.*
import org.http4s.client.Client
import org.http4s.headers.{Authorization, Location}
import sruru.core.*
import sruru.db.*
import sruru.security.*

import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.time.Instant
import java.util.UUID

/** OAuth 2.0 のエラー. */
final case class OAuthError(
  error: String,
  description: String,
  status: Status = Status.BadRequest)

/**
 * OpenID Connect プロバイダ・OAuth 2.0 認可サーバー.
 * 認可コード（PKCE）・リフレッシュトークン（ローテーションと再利用の検出）・クライアントクレデンシャル・
 * UserInfo・イントロスペクション（RFC 7662）・失効（RFC 7009）・RP からのログアウト・バックチャネルのログアウト.
 */
final class OidcRoutes(
  apps: AppStore,
  tokens: TokenStore,
  sessions: SessionStore,
  dir: Directory,
  keys: KeyService,
  claims: Claims,
  gate: AuthGate,
  val auth: SessionAuth,
  audit: AuditService,
  http: Client[IO],
  cfg: ApiConfig) extends RouteSupport {

  val routes: HttpRoutes[IO] = HttpRoutes.of[IO] {
    case GET -> Root / ".well-known" / "openid-configuration" => getWellKnownOpenidConfiguration()
    case GET -> Root / ".well-known" / "oauth-authorization-server" => getWellKnownOauthAuthorizationServer()
    case GET -> Root / "oauth2" / "jwks" => getOauth2Jwks()
    case req @ (GET | POST) -> Root / "oauth2" / "authorize" => getOauth2Authorize(req)
    case req @ POST -> Root / "oauth2" / "token" => postOauth2Token(req)
    case req @ (GET | POST) -> Root / "oauth2" / "userinfo" => getOauth2Userinfo(req)
    case req @ POST -> Root / "oauth2" / "introspect" => postOauth2Introspect(req)
    case req @ POST -> Root / "oauth2" / "revoke" => postOauth2Revoke(req)
    case req @ (GET | POST) -> Root / "oauth2" / "logout" => getOauth2Logout(req)
    case OPTIONS -> Root / "oauth2" / _ => optionsOauth2()
  }

  private def getWellKnownOpenidConfiguration(): IO[Response[IO]] =
    cors(Ok(discovery))

  private def getWellKnownOauthAuthorizationServer(): IO[Response[IO]] =
    cors(Ok(discovery))

  private def getOauth2Jwks(): IO[Response[IO]] =
    cors(keys.jwks.flatMap(j => Ok(j).map(_.putHeaders("Cache-Control" -> "public, max-age=300"))))

  private def getOauth2Authorize(
    req: Request[IO]
  ): IO[Response[IO]] =
    authorize(req)

  private def postOauth2Token(
    req: Request[IO]
  ): IO[Response[IO]] =
    cors(token(req))

  private def getOauth2Userinfo(
    req: Request[IO]
  ): IO[Response[IO]] =
    cors(userinfo(req))

  private def postOauth2Introspect(
    req: Request[IO]
  ): IO[Response[IO]] =
    introspect(req)

  private def postOauth2Revoke(
    req: Request[IO]
  ): IO[Response[IO]] =
    revoke(req)

  private def getOauth2Logout(
    req: Request[IO]
  ): IO[Response[IO]] =
    endSession(req)

  private def optionsOauth2(): IO[Response[IO]] =
    cors(IO.pure(Response[IO](Status.NoContent).putHeaders("Access-Control-Allow-Methods" -> "GET, POST")))

  private val iss = cfg.issuer
  private val SupportedScopes = List("openid", "profile", "email", "phone", "groups", "offline_access")

  // ------------------------------------------------------------------ 補助

  private def oauthErr(
    e: OAuthError
  ): IO[Response[IO]] =
    IO.pure(Response[IO](e.status).withEntity(Json.obj(
      "error" -> e.error.asJson,
      "error_description" -> e.description.asJson
    ))
      .putHeaders("Cache-Control" -> "no-store", "Pragma" -> "no-cache"))

  private def json(
    j: Json
  ): IO[Response[IO]] = Ok(j).map(_.putHeaders("Cache-Control" -> "no-store", "Pragma" -> "no-cache"))

  /** クライアントへ結果を返す（query か form_post）. */
  private def toClient(
    redirectUri: String,
    mode: String,
    params: List[(String, String)]
  ): IO[Response[IO]] =
    if mode == "form_post" then formPage(redirectUri, params, None)
    else {
      val base = Uri.unsafeFromString(redirectUri)
      IO.pure(Response[IO](Status.SeeOther).putHeaders(
        Location(params.foldLeft(base)(
          (
            u,
            kv
          ) => u.withQueryParam(kv._1, kv._2)
        )),
        "Cache-Control" -> "no-store"
      ))
    }

  /** POST するフォームの画面. question がなければすぐに送信し、あれば問いとボタンを見せる. */
  private def formPage(
    action: String,
    params: List[(String, String)],
    question: Option[String]
  ): IO[Response[IO]] = {
    val nonce = Crypto.randomToken(12)
    def esc(
      s: String
    ) = Html.escape(s)
    val inputs = params.map(
      (
        k,
        v
      ) => s"""<input type="hidden" name="${esc(k)}" value="${esc(v)}">"""
    ).mkString
    val body = question match {
      case None => s"""<form method="post" action="${esc(
                       action
                     )}">$inputs<noscript><button type="submit">続ける</button></noscript></form>
                      |<script nonce="$nonce">document.forms[0].submit()</script>""".stripMargin
      case Some(q) => s"""<form method="post" action="${esc(action)}">$inputs<p>${esc(
            q
          )}</p><button type="submit">はい</button></form>"""
    }
    val html =
      s"""<!DOCTYPE html><html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
         |<title>sruru</title></head><body>$body</body></html>""".stripMargin
    IO.pure(Html.response(html, s"default-src 'none'; script-src 'nonce-$nonce'; form-action *"))
  }

  private def params(
    req: Request[IO]
  ): IO[Map[String, String]] =
    // POST は本文だけを使う（クライアントのシークレットやトークンを URL に載せさせない）
    if req.method == Method.POST then
      req.as[UrlForm].map(f => f.values.collect { case (k, v) if v.nonEmpty => k -> v.toList.head })
    else IO.pure(req.params)

  /** クライアントの認証（client_secret_basic・client_secret_post・公開クライアント）. */
  private def clientAuth(
    req: Request[IO],
    form: Map[String, String]
  ): IO[Either[OAuthError, (Application, OidcClientConfig)]] = {
    val basic = req.headers.get[Authorization].collect { case Authorization(BasicCredentials(u, p)) =>
      (URLDecoder.decode(u, StandardCharsets.UTF_8), URLDecoder.decode(p, StandardCharsets.UTF_8))
    }
    val (id, secret) = basic.map(
      (
        u,
        p
      ) => (Some(u), Some(p))
    ).getOrElse((form.get("client_id"), form.get("client_secret")))
    id match {
      case None => IO.pure(Left(OAuthError("invalid_client", "client_id がありません", Status.Unauthorized)))
      case Some(cid) =>
        apps.byClientId(cid).map {
          case Some((a, c)) if a.enabled =>
            c.secretHash match {
              case None => Either.cond(
                  secret.isEmpty,
                  (a, c),
                  OAuthError("invalid_client", "公開クライアントにシークレットは不要です", Status.Unauthorized)
                )
              case Some(h) =>
                Either.cond(
                  secret.exists(s => Crypto.constantTimeEquals(Crypto.sha256(s), h)),
                  (a, c),
                  OAuthError("invalid_client", "クライアントの認証に失敗しました", Status.Unauthorized)
                )
            }
          case _ => Left(OAuthError("invalid_client", "クライアントが見つかりません", Status.Unauthorized))
        }
    }
  }

  // ------------------------------------------------------------------ メタデータ

  def discovery: Json = Json.obj(
    "issuer" -> iss.asJson,
    "authorization_endpoint" -> s"$iss/oauth2/authorize".asJson,
    "token_endpoint" -> s"$iss/oauth2/token".asJson,
    "userinfo_endpoint" -> s"$iss/oauth2/userinfo".asJson,
    "jwks_uri" -> s"$iss/oauth2/jwks".asJson,
    "end_session_endpoint" -> s"$iss/oauth2/logout".asJson,
    "introspection_endpoint" -> s"$iss/oauth2/introspect".asJson,
    "revocation_endpoint" -> s"$iss/oauth2/revoke".asJson,
    "response_types_supported" -> List("code").asJson,
    "response_modes_supported" -> List("query", "form_post").asJson,
    "grant_types_supported" -> List("authorization_code", "refresh_token", "client_credentials").asJson,
    "subject_types_supported" -> List("public").asJson,
    "id_token_signing_alg_values_supported" -> List("RS256", "ES256").asJson,
    "scopes_supported" -> SupportedScopes.asJson,
    "token_endpoint_auth_methods_supported" -> List("client_secret_basic", "client_secret_post", "none").asJson,
    "code_challenge_methods_supported" -> List("S256").asJson,
    "claims_supported" -> List(
      "sub",
      "iss",
      "aud",
      "exp",
      "iat",
      "auth_time",
      "nonce",
      "amr",
      "sid",
      "name",
      "given_name",
      "family_name",
      "preferred_username",
      "picture",
      "email",
      "email_verified",
      "phone_number",
      "groups",
      "locale",
      "zoneinfo",
      "updated_at"
    ).asJson,
    "prompt_values_supported" -> List("none", "login", "consent", "select_account").asJson,
    "authorization_response_iss_parameter_supported" -> true.asJson,
    "backchannel_logout_supported" -> true.asJson,
    "backchannel_logout_session_supported" -> true.asJson,
    "claims_parameter_supported" -> false.asJson,
    "request_parameter_supported" -> false.asJson
  )

  // ------------------------------------------------------------------ 認可

  private def authorize(
    req: Request[IO]
  ): IO[Response[IO]] =
    params(req).flatMap { p =>
      p.get("client_id").fold(gate.errorPage("client_id がありません"))(cid =>
        apps.byClientId(cid).flatMap {
          case None => gate.errorPage("アプリケーションが登録されていません（client_id が違います）")
          case Some((app, c)) =>
            val redirect = p.get("redirect_uri").orElse(c.redirectUris match {
              case List(one) => Some(one); case _ => None
            })
            redirect.filter(c.redirectUris.contains) match {
              case None => gate.errorPage("リダイレクト URI が登録されていません。アプリケーションの設定を確かめてください")
              case Some(ru) =>
                val mode = p.get("response_mode").filter(_ == "form_post").getOrElse("query")
                val state = p.get("state").toList.map("state" -> _)
                def back(
                  e: String,
                  d: String
                ) = toClient(ru, mode, List("error" -> e, "error_description" -> d, "iss" -> iss) ++ state)
                val requested = p.getOrElse("scope", "").split(' ').filter(_.nonEmpty).toList.distinct
                val scopes = requested.filter(c.scopes.contains)
                if !app.enabled then back("access_denied", "このアプリケーションは無効です")
                else if !p.get("response_type").contains("code") then
                  back("unsupported_response_type", "response_type は code だけです")
                else if !c.grantTypes.contains("authorization_code") then back("unauthorized_client", "認可コードは使えません")
                else if p.contains("request") || p.contains("request_uri") then
                  back("request_not_supported", "request は使えません")
                else if c.isPublic && !p.contains("code_challenge") then
                  back("invalid_request", "公開クライアントには PKCE（code_challenge）が必要です")
                else if p.get("code_challenge_method").exists(_ != "S256") then
                  back("invalid_request", "code_challenge_method は S256 だけです")
                else if requested.nonEmpty && scopes.isEmpty then back("invalid_scope", "使えるスコープがありません")
                else {
                  val stored = Json.fromFields(p.view.filterKeys(Set(
                    "client_id",
                    "state",
                    "nonce",
                    "code_challenge",
                    "prompt",
                    "max_age",
                    "login_hint",
                    "acr_values",
                    "ui_locales"
                  ).contains).toList.map(
                    (
                      k,
                      v
                    ) => k -> v.asJson
                  ) ++
                    List(
                      "redirect_uri" -> ru.asJson,
                      "response_mode" -> mode.asJson,
                      "scope" -> scopes.mkString(" ").asJson
                    ))
                  Time.now.flatMap(now =>
                    tokens.createRequest(app.id, "oidc", stored, AuthRequests.expires(now))
                  ).flatMap(r => resume(req, r))
                }
            }
        }
      )
    }

  /** ログイン・同意の後に、認可コードを発行してクライアントへ戻す. */
  def resume(
    req: Request[IO],
    r: AuthRequest
  ): IO[Response[IO]] = {
    val pc = r.params.hcursor
    def str(
      k: String
    ) = pc.get[String](k).toOption
    (apps.find(r.appId), apps.oidc(r.appId)).tupled.flatMap {
      case (Some(app), Some(c)) =>
        val ru = str("redirect_uri").get
        val mode = str("response_mode").getOrElse("query")
        val state = str("state").toList.map("state" -> _)
        val prompt = str("prompt").toList.flatMap(_.split(' ')).toSet
        val scopes = str("scope").toList.flatMap(_.split(' ').filter(_.nonEmpty))
        def back(
          e: String,
          d: String
        ) = tokens.deleteRequest(r.id) *>
          toClient(ru, mode, List("error" -> e, "error_description" -> d, "iss" -> iss) ++ state)
        // prompt=login は、要求を受けた後にログインしていれば満たす（AuthGate が認証の時刻で判定する）
        val opts =
          GateOpts(prompt("login"), prompt("none"), str("max_age").flatMap(_.toLongOption), prompt("select_account"))
        gate.check(req, r, app, opts).flatMap {
          case Gate.Interact(_, e) if prompt("none") => back(e, "画面での操作が必要です")
          case Gate.Interact(path, _) => gate.redirect(path)
          case Gate.Deny(e, msg) =>
            if prompt("none") then back(e, msg) else tokens.deleteRequest(r.id) *> gate.errorPage(msg)
          case Gate.Proceed(bs, _, user, _) if AuthRequests.markedBy(r, "deniedBy", bs, user.id) =>
            back("access_denied", "利用者が許可しませんでした")
          case Gate.Proceed(bs, login, user, m) =>
            val consented = AuthRequests.markedBy(r, "consentedBy", bs, user.id)
            apps.consent(user.id, app.id).flatMap { prev =>
              val needConsent = !consented &&
                (prompt("consent") || (c.consent == "explicit" && !scopes.forall(s => prev.exists(_.contains(s)))))
              if needConsent && prompt("none") then back("consent_required", "同意が必要です")
              else if needConsent then gate.redirect(s"/consent?req=${r.id}")
              else
                for {
                  now <- Time.now
                  code = Crypto.randomToken()
                  _ <- tokens.createCode(
                    Crypto.sha256(code),
                    AuthCode(
                      app.id,
                      user.id,
                      Some(login.id),
                      ru,
                      scopes,
                      str("nonce"),
                      str("code_challenge"),
                      str("code_challenge").map(_ => "S256"),
                      login.authTime,
                      login.amr,
                      now.plusSeconds(60),
                      None
                    )
                  )
                  _ <- tokens.deleteRequest(r.id)
                  c0 <- auth.reqCtx(req)
                  _ <- audit.log(
                    c0,
                    Some(user),
                    "oidc",
                    "app.authorize",
                    audit.appTarget(app),
                    detail = Json.obj("scopes" -> scopes.asJson)
                  )
                  res <- toClient(ru, mode, List("code" -> code, "iss" -> iss) ++ state)
                } yield res
            }
        }
      case _ => gate.errorPage("アプリケーションが見つかりません")
    }
  }

  // ------------------------------------------------------------------ トークン

  private def accessToken(
    app: Option[Application],
    c: OidcClientConfig,
    sub: String,
    userId: Option[UUID],
    loginId: Option[UUID],
    scopes: List[String],
    now: Instant
  ): IO[(String, Int)] = {
    val jti = UUID.randomUUID()
    val exp = now.plusSeconds(c.accessTokenTtl.toLong)
    keys.active(c.signingAlg).flatMap { k =>
      val jwt = Jose.sign(
        k,
        Json.obj(
          "iss" -> iss.asJson,
          "sub" -> sub.asJson,
          "aud" -> c.clientId.asJson,
          "client_id" -> c.clientId.asJson,
          "scope" -> scopes.mkString(" ").asJson,
          "iat" -> now.getEpochSecond.asJson,
          "exp" -> exp.getEpochSecond.asJson,
          "jti" -> jti.toString.asJson,
          "sid" -> loginId.map(_.toString).asJson
        ),
        "at+jwt"
      )
      tokens.recordAccess(AccessTokenRow(jti, app.map(_.id), userId, loginId, scopes, exp, None)).as((
        jwt,
        c.accessTokenTtl
      ))
    }
  }

  private def atHash(
    at: String,
    alg: String
  ): String = {
    val d = java.security.MessageDigest.getInstance("SHA-256").digest(at.getBytes(StandardCharsets.US_ASCII))
    Crypto.b64url.encodeToString(d.take(d.length / 2))
  }

  /** 発行したトークンを数える（protocol = oidc（ID トークンあり）・oauth2）. */
  private def issued(
    grant: String,
    protocol: String
  ): IO[Unit] =
    sbirds.observe.Metrics.count("sruru.tokens.issued", "grant_type" -> grant, "protocol" -> protocol)

  /** ユーザーに対するトークン一式（アクセストークン・ID トークン・リフレッシュトークン）. */
  private def issue(
    grant: String,
    app: Application,
    c: OidcClientConfig,
    u: User,
    loginId: Option[UUID],
    scopes: List[String],
    authTime: Instant,
    amr: List[String],
    nonce: Option[String],
    family: Option[UUID],
    now: Instant
  ): IO[Json] =
    for {
      m <- dir.membership(u)
      sub = claims.sub(u, c)
      att <- accessToken(Some(app), c, sub, Some(u.id), loginId, scopes, now)
      (at, ttl) = att
      idToken <- if !scopes.contains("openid") then IO.pure(None)
      else
        (claims.build(u, m, app, c, scopes.toSet), keys.active(c.signingAlg)).mapN {
          (
            cl,
            k
          ) =>
            Some(Jose.sign(
              k,
              cl.deepMerge(Json.obj(
                "iss" -> iss.asJson,
                "aud" -> c.clientId.asJson,
                "azp" -> c.clientId.asJson,
                "iat" -> now.getEpochSecond.asJson,
                "exp" -> now.plusSeconds(c.idTokenTtl.toLong).getEpochSecond.asJson,
                "auth_time" -> authTime.getEpochSecond.asJson,
                "nonce" -> nonce.asJson,
                "amr" -> amr.asJson,
                "sid" -> loginId.map(_.toString).asJson,
                "at_hash" -> atHash(at, k.alg).asJson
              ))
            ))
        }
      refresh <- if !c.grantTypes.contains("refresh_token") then IO.pure(None)
      else {
        val t = Crypto.randomToken()
        tokens.createRefresh(
          Crypto.sha256(t),
          family.getOrElse(UUID.randomUUID()),
          app.id,
          u.id,
          if scopes.contains("offline_access") then None else loginId,
          scopes,
          authTime,
          amr,
          now.plusSeconds(c.refreshTokenTtl.toLong)
        ).as(Some(t))
      }
      _ <- issued(grant, if idToken.isDefined then "oidc" else "oauth2")
    } yield Json.obj(
      "access_token" -> at.asJson,
      "token_type" -> "Bearer".asJson,
      "expires_in" -> ttl.asJson,
      "scope" -> scopes.mkString(" ").asJson,
      "id_token" -> idToken.asJson,
      "refresh_token" -> refresh.asJson
    ).dropNullValues

  /** アプリを使い続けてよいか（無効化・グループからの除外を反映する）. */
  private def stillAllowed(
    app: Application,
    u: User
  ): IO[Boolean] =
    if u.disabled || !app.enabled then IO.pure(false)
    else if !app.restrictAccess then IO.pure(true)
    else
      (apps.accessGroups(app.id), dir.membership(u)).mapN(
        (
          gs,
          m
        ) => gs.exists(m.ids.contains)
      )

  /** ログインに結び付いたトークンなら、そのログインが続いているか（期限切れ・無操作で終わったログインのトークンは使わせない）. */
  private def loginAlive(
    loginId: Option[UUID],
    now: Instant
  ): IO[Boolean] =
    loginId.fold(IO.pure(true))(id => sessions.login(id).map(_.exists(_.expiresAt.isAfter(now))))

  /** 認可コードから発行するリフレッシュトークンの系列（コードの再利用のとき、その系列をまとめて失効させる）. */
  private def codeFamily(
    code: String
  ): UUID = UUID.nameUUIDFromBytes(Crypto.sha256("sruru-code-family:" + code))

  private val Grants = Set("authorization_code", "refresh_token", "client_credentials")

  /** トークンのエンドポイント. スパン・メトリクスには grant_type と結果だけを載せる（コード・トークン・クライアントシークレットは載せない）. */
  private def token(
    req: Request[IO]
  ): IO[Response[IO]] =
    params(req).flatMap { f =>
      val grant = f.getOrElse("grant_type", "")
      val label = if Grants(grant) then grant else "other"
      sbirds.observe.Telemetry.span("oauth.token", "grant_type" -> label)(tokenFor(req, f, grant)).flatTap(r =>
        IO.whenA(!r.status.isSuccess)(sbirds.observe.Metrics.count(
          "sruru.tokens.rejected",
          "grant_type" -> label,
          "status" -> r.status.code.toString
        ))
      )
    }

  private def tokenFor(
    req: Request[IO],
    f: Map[String, String],
    grant: String
  ): IO[Response[IO]] =
    clientAuth(req, f).flatMap {
      case Left(e) => oauthErr(e)
      case Right((app, c)) =>
        if !c.grantTypes.contains(grant) then oauthErr(OAuthError("unauthorized_client", s"$grant は使えません"))
        else
          Time.now.flatMap { now =>
            grant match {
              case "authorization_code" =>
                f.get("code").fold(oauthErr(OAuthError("invalid_request", "code がありません"))) { code =>
                  tokens.useCode(Crypto.sha256(code), app.id, now).flatMap {
                    case None => oauthErr(OAuthError("invalid_grant", "認可コードが無効か期限切れです"))
                    case Some(Left(used)) =>
                      // 認可コードの再利用: そのコードで発行したトークン（系列ごと. offline_access も）を失効させる
                      tokens.revokeCodeFamily(used, codeFamily(code)) *>
                        oauthErr(OAuthError("invalid_grant", "認可コードはすでに使われています"))
                    case Some(Right(ac)) =>
                      // PKCE なしで出したコードに code_verifier が付いてきたら拒否する（PKCE のダウングレード）
                      val pkceOk = ac.codeChallenge match {
                        case Some(ch) =>
                          f.get("code_verifier").exists(v => Crypto.constantTimeEquals(Crypto.pkceS256(v), ch))
                        case None => !f.contains("code_verifier")
                      }
                      if ac.appId != app.id then oauthErr(OAuthError("invalid_grant", "別のクライアントの認可コードです"))
                      else if !f.get("redirect_uri").forall(_ == ac.redirectUri) then
                        oauthErr(OAuthError("invalid_grant", "redirect_uri が一致しません"))
                      else if !pkceOk then oauthErr(OAuthError("invalid_grant", "code_verifier が一致しません"))
                      else
                        dir.users.find(ac.userId).flatMap {
                          case Some(u) if !u.disabled =>
                            issue(
                              grant,
                              app,
                              c,
                              u,
                              ac.loginId,
                              ac.scopes,
                              ac.authTime,
                              ac.amr,
                              ac.nonce,
                              Some(codeFamily(code)),
                              now
                            ).flatMap(json)
                          case _ => oauthErr(OAuthError("invalid_grant", "ユーザーが無効です"))
                        }
                  }
                }
              case "refresh_token" =>
                f.get("refresh_token").fold(oauthErr(OAuthError("invalid_request", "refresh_token がありません"))) { rt =>
                  tokens.refresh(Crypto.sha256(rt)).flatMap {
                    case Some(t) if t.appId == app.id && t.revokedAt.isEmpty && t.expiresAt.isAfter(now) =>
                      if t.usedAt.isDefined then
                        // 再利用（盗まれた可能性）: 系列ごと失効させる
                        tokens.revokeFamilyWithAccess(t) *>
                          oauthErr(OAuthError("invalid_grant", "リフレッシュトークンはすでに使われています"))
                      else
                        dir.users.find(t.userId).flatMap {
                          case Some(u) =>
                            (stillAllowed(app, u), loginAlive(t.loginId, now)).tupled.flatMap {
                              case (_, false) =>
                                tokens.revokeFamily(t.family) *> oauthErr(OAuthError("invalid_grant", "ログインが終わっています"))
                              case (false, _) => tokens.revokeFamily(t.family) *>
                                  oauthErr(OAuthError("invalid_grant", "このアプリケーションは使えなくなりました"))
                              case (true, true) =>
                                val narrowed = f.get("scope").map(_.split(' ').filter(_.nonEmpty).toList)
                                val scopes = narrowed.fold(t.scopes)(_.filter(t.scopes.contains))
                                tokens.markRefreshUsed(t.id, now).flatMap {
                                  case false => oauthErr(OAuthError("invalid_grant", "リフレッシュトークンはすでに使われています"))
                                  case true => issue(
                                      grant,
                                      app,
                                      c,
                                      u,
                                      t.loginId,
                                      scopes,
                                      t.authTime,
                                      t.amr,
                                      None,
                                      Some(t.family),
                                      now
                                    ).flatMap(json)
                                }
                            }
                          case None => oauthErr(OAuthError("invalid_grant", "ユーザーが見つかりません"))
                        }
                    case _ => oauthErr(OAuthError("invalid_grant", "リフレッシュトークンが無効か期限切れです"))
                  }
                }
              case "client_credentials" =>
                if c.isPublic then oauthErr(OAuthError("unauthorized_client", "公開クライアントでは使えません"))
                else {
                  val requested = f.get("scope").map(_.split(' ').filter(_.nonEmpty).toList).getOrElse(c.scopes)
                  val scopes = requested.filter(s => c.scopes.contains(s) && !Set("openid", "offline_access")(s))
                  accessToken(Some(app), c, c.clientId, None, None, scopes, now).flatTap(_ =>
                    issued("client_credentials", "oauth2")
                  ).flatMap(
                    (
                      at,
                      ttl
                    ) =>
                      json(Json.obj(
                        "access_token" -> at.asJson,
                        "token_type" -> "Bearer".asJson,
                        "expires_in" -> ttl.asJson,
                        "scope" -> scopes.mkString(" ").asJson
                      ))
                  )
                }
              case _ => oauthErr(OAuthError("unsupported_grant_type", s"$grant は使えません"))
            }
          }
    }

  // ------------------------------------------------------------------ アクセストークンの検証

  /** 自分が発行したアクセストークン（署名・期限・失効を確かめる）. */
  def verifyAccess(
    at: String
  ): IO[Option[(Json, AccessTokenRow)]] =
    keys.publicJwks.flatMap { ks =>
      val ok = for {
        h <- Jose.header(at).toOption
        _ <- Option.when(h.hcursor.get[String]("typ").toOption.contains("at+jwt"))(())
        cl <- Jose.verify(at, ks).toOption
        _ <- Option.when(cl.hcursor.get[String]("iss").toOption.contains(iss))(())
        jti <- cl.hcursor.get[String]("jti").toOption.flatMap(s => scala.util.Try(UUID.fromString(s)).toOption)
      } yield (cl, jti)
      ok.fold(IO.pure(None)) {
        (
          cl,
          jti
        ) =>
          (tokens.access(jti), Time.now).mapN(
            (
              row,
              now
            ) => row.filter(r => r.revokedAt.isEmpty && r.expiresAt.isAfter(now)).map(cl -> _)
          )
      }
    }

  private def bearer(
    req: Request[IO],
    form: Map[String, String]
  ): Option[String] =
    req.headers.get[Authorization].collect { case Authorization(Credentials.Token(AuthScheme.Bearer, t)) => t }.orElse(
      form.get("access_token").filter(_ => req.method == Method.POST)
    )

  private def userinfo(
    req: Request[IO]
  ): IO[Response[IO]] =
    params(req).flatMap { f =>
      def unauthorized(
        e: String
      ) =
        IO.pure(Response[IO](Status.Unauthorized).putHeaders(
          "WWW-Authenticate" -> s"""Bearer error="$e"""",
          "Cache-Control" -> "no-store"
        ))
      bearer(req, f).fold(unauthorized("invalid_token"))(at =>
        verifyAccess(at).flatMap {
          case None => unauthorized("invalid_token")
          case Some((_, row)) if !row.scopes.contains("openid") =>
            IO.pure(Response[IO](Status.Forbidden).putHeaders("WWW-Authenticate" ->
              """Bearer error="insufficient_scope""""))
          case Some((_, row)) =>
            (
              row.userId.flatTraverse(dir.users.find),
              row.appId.flatTraverse(apps.find),
              row.appId.flatTraverse(apps.oidc)
            ).tupled.flatMap {
              case (Some(u), Some(app), Some(c)) =>
                stillAllowed(app, u).flatMap {
                  case true =>
                    dir.membership(u).flatMap(m => claims.build(u, m, app, c, row.scopes.toSet)).flatMap(json)
                  case false => unauthorized("invalid_token")
                }
              case _ => unauthorized("invalid_token")
            }
        }
      )
    }

  private def introspect(
    req: Request[IO]
  ): IO[Response[IO]] =
    params(req).flatMap { f =>
      clientAuth(req, f).flatMap {
        case Left(e) => oauthErr(e)
        case Right((app, c)) =>
          val inactive = json(Json.obj("active" -> false.asJson))
          f.get("token").fold(oauthErr(OAuthError("invalid_request", "token がありません"))) { t =>
            verifyAccess(t).flatMap {
              case Some((cl, row)) if row.appId.contains(app.id) =>
                row.userId.flatTraverse(dir.users.find).flatMap { u =>
                  // ユーザーのトークンは、ユーザー・アプリ・グループの今の状態で判定する（クライアントクレデンシャルはアプリの有効だけ）
                  u.fold(IO.pure(row.userId.isEmpty && app.enabled))(stillAllowed(app, _)).map(ok => (u, ok))
                }.flatMap {
                  (
                    u,
                    ok
                  ) =>
                    if !ok then inactive
                    else
                      json(Json.obj(
                        "active" -> true.asJson,
                        "scope" -> row.scopes.mkString(" ").asJson,
                        "client_id" -> c.clientId.asJson,
                        "username" -> u.map(_.username).asJson,
                        "token_type" -> "Bearer".asJson,
                        "exp" -> cl.hcursor.get[Long]("exp").toOption.asJson,
                        "iat" -> cl.hcursor.get[Long]("iat").toOption.asJson,
                        "sub" -> cl.hcursor.get[String]("sub").toOption.asJson,
                        "aud" -> c.clientId.asJson,
                        "iss" -> iss.asJson,
                        "jti" -> row.jti.toString.asJson
                      ).dropNullValues)
                }
              case Some(_) => inactive
              case None =>
                (tokens.refresh(Crypto.sha256(t)), Time.now).tupled.flatMap {
                  case (Some(rt), now)
                      if rt.appId == app.id && rt.revokedAt.isEmpty && rt.usedAt.isEmpty && rt.expiresAt.isAfter(now) =>
                    dir.users.find(rt.userId).flatMap {
                      case Some(u) => (stillAllowed(app, u), loginAlive(rt.loginId, now)).tupled.flatMap {
                          case (true, true) => json(Json.obj(
                              "active" -> true.asJson,
                              "scope" -> rt.scopes.mkString(" ").asJson,
                              "client_id" -> c.clientId.asJson,
                              "username" -> u.username.asJson,
                              "sub" -> claims.sub(u, c).asJson,
                              "exp" -> rt.expiresAt.getEpochSecond.asJson,
                              "token_type" -> "refresh_token".asJson
                            ))
                          case _ => inactive
                        }
                      case _ => inactive
                    }
                  case _ => inactive
                }
            }
          }
      }
    }

  private def revoke(
    req: Request[IO]
  ): IO[Response[IO]] =
    params(req).flatMap { f =>
      clientAuth(req, f).flatMap {
        case Left(e) => oauthErr(e)
        case Right((app, _)) =>
          f.get("token").fold(oauthErr(OAuthError("invalid_request", "token がありません"))) { t =>
            tokens.refresh(Crypto.sha256(t)).flatMap {
              // RFC 7009 2.1: 同じ許可で出したアクセストークンも失効させる
              case Some(rt) if rt.appId == app.id => tokens.revokeFamilyWithAccess(rt)
              case Some(_) => IO.unit
              case None => verifyAccess(t).flatMap(_.filter(_._2.appId.contains(app.id)).traverse_(x =>
                  tokens.revokeAccess(x._2.jti)
                ))
            } *> Ok()
          }
      }
    }

  // ------------------------------------------------------------------ ログアウト

  private def endSession(
    req: Request[IO]
  ): IO[Response[IO]] =
    params(req).flatMap { f =>
      for {
        ks <- keys.publicJwks
        hint = f.get(
          "id_token_hint"
        ).flatMap(t => Jose.verify(t, ks).toOption).filter(_.hcursor.get[String]("iss").toOption.contains(iss))
        cid = hint.flatMap(_.hcursor.get[String]("aud").toOption).orElse(f.get("client_id"))
        client <- cid.flatTraverse(apps.byClientId)
        sid =
          hint.flatMap(_.hcursor.get[String]("sid").toOption).flatMap(s => scala.util.Try(UUID.fromString(s)).toOption)
        active <- auth.activeFor(req)
        c <- auth.reqCtx(req)
        // id_token_hint の sid がこのブラウザのログインなら、そのログインをログアウトする
        byHint <- sid.flatTraverse(sessions.login).map(_.flatMap(l =>
          active.filter(_._1.id == l.browserSessionId).map(a => (a._1, l.userId))
        ))
        post = f.get("post_logout_redirect_uri").filter(u => client.exists(c => OidcRoutes.allowedPostLogout(c._2, u)))
        res <-
          if byHint.isEmpty && active.isDefined && req.method == Method.GET then
            // ヒントで特定できない GET は確認してから（他のサイトに埋め込まれたリンクだけでログアウトさせない）.
            // 確認のフォームは同じサイトからの POST なので、SameSite=Lax の Cookie が付く
            formPage("/oauth2/logout", (f - "id_token_hint" ++ cid.map("client_id" -> _)).toList, Some("ログアウトしますか？"))
          else {
            val target = byHint.orElse(active.map(a => (a._1, a._3.id)))
            target.traverse_ {
              (
                bs,
                uid
              ) =>
                sessions.removeLogin(bs.id, uid).flatMap(_.traverse_ { lid =>
                  dir.endLogin(uid, lid) *> dir.users.find(uid).flatMap(_.traverse_ { u =>
                    audit.log(
                      c,
                      Some(u),
                      "oidc",
                      "logout",
                      audit.userTarget(u),
                      detail = Json.obj("client" -> cid.asJson)
                    )
                  })
                })
            } *>
              (post match {
                case Some(u) => toClient(u, "query", f.get("state").toList.map("state" -> _))
                case None => gate.redirect("/logged-out")
              })
          }
      } yield res
    }

  // ------------------------------------------------------------------ ルート

  private def cors(
    r: IO[Response[IO]]
  ): IO[Response[IO]] =
    r.map(_.putHeaders(
      "Access-Control-Allow-Origin" -> "*",
      "Access-Control-Allow-Headers" -> "Authorization, Content-Type"
    ))

}

object OidcRoutes {
  private def origin(
    u: String
  ): Option[String] =
    scala.util.Try(java.net.URI.create(u)).toOption.filter(x =>
      x.getScheme != null && x.getHost != null && x.getUserInfo == null
    )
      .map(x =>
        s"${x.getScheme.toLowerCase}://${x.getHost.toLowerCase}${if x.getPort == -1 then "" else s":${x.getPort}"}"
      )

  /** ログアウト後に戻してよい URI: 登録したもの、または登録したリダイレクト URI と同じオリジンの URL（各サービスの「/」を個別に登録しなくてよいように）. */
  def allowedPostLogout(
    c: OidcClientConfig,
    u: String
  ): Boolean =
    c.postLogoutRedirectUris.contains(u) || origin(u).exists(o => c.redirectUris.flatMap(origin).contains(o))
}
