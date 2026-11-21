package sruru.api

import cats.effect.*
import cats.syntax.all.*
import io.circe.Json
import io.circe.syntax.*
import sruru.core.*
import sruru.db.*
import sruru.security.*
import sruru.shared.*

import java.util.UUID

/**
 * マジックリンク（一時トークンによるログイン. docs/design.md の「マジックリンク」）.
 * 発行は管理者（メールで送るだけ）か、許可した OAuth クライアント（URL を返すか、メールで送る）. トークンは email_tokens（purpose = magic）に
 * SHA-256 だけを保存し、1回限り・既定 15 分. 使うのは確認の画面のボタン（POST + X-Sruru）からで、通常のログインの流れ（多要素認証を含む）に乗せる.
 */
final class MagicLinkService(dir: Directory,
                             login: LoginService,
                             sessions: SessionStore,
                             factors: FactorStore,
                             tokens: TokenStore,
                             apps: AppStore,
                             audit: AuditService,
                             mail: MailService,
                             cfg: ApiConfig) {

  private val Purpose = "magic"
  // 回数の制限の窓（15 分）と上限
  private val Window = 15L * 60
  private val PerUser = 5
  private val PerClient = 500
  private val PerAdmin = 50

  private def ttl: Long = cfg.magicLinkMinutes.toLong * 60

  /** 回数を1つ数え、窓の中の回数が max 以下なら true. */
  private def within(key: String, max: Int): IO[Boolean] =
    Time.now.flatMap(now => factors.throttleFail(key, now.minusSeconds(Window))).map(_ <= max)

  /** 発行の回数の制限（利用者ごとと、発行した人ごと）. */
  private def limited(u: User, actorKey: String, actorMax: Int): IO[Boolean] =
    (within(s"magic:user:${u.id}", PerUser), within(actorKey, actorMax)).mapN(_ && _).map(!_)

  /** トークンを作って保存し、リンクの URL を返す（ドメインはこの要求のホスト名）. */
  private def create(u: User, data: Json): IO[String] =
    for {
      now <- Time.now
      host <- Site.host
      t = Crypto.randomToken()
      _ <- factors.createEmailToken(
        u.id,
        Purpose,
        Crypto.sha256(t),
        now.plusSeconds(ttl),
        data.deepMerge(Json.obj("domain" -> host.asJson))
      )
    } yield s"${cfg.urlOf(host)}/magic?token=$t"

  private def sendMail(to: String, u: User, url: String, intro: String, c: ReqCtx): IO[Unit] =
    dir.policyFor(u).flatMap(p =>
      mail.send(
        to,
        s"${p.branding.title} のログインのリンク",
        s"${u.name} さん\n\n$intro\n次のリンクを開き、画面の「ログインする」を押してください（${cfg.magicLinkMinutes}分間有効・1回だけ使えます）。\n$url\n\n" +
          s"心当たりがない場合は、このメールを破棄してください。リンクを他の人に渡さないでください。\n\nIP アドレス: ${c.ip}\n"
      )
    )

  // ------------------------------------------------------------------ 発行（管理者）

  /**
   * 管理者が発行する. 登録されているアドレスへメールで送るだけで、URL は返さない（管理者が利用者になりすませる道具にしない）.
   * 戻り先はポータル.
   */
  def issueByAdmin(c: ReqCtx, p: Principal, u: User): Res[MagicLinkDto] =
    Time.now.flatMap { now =>
      if u.disabled || u.isService || u.locked(now) then Res.fail(ErrorCode.MagicLinkUserNotAllowed)
      else
        u.email match {
          case None => Res.fail(ErrorCode.MagicLinkNoEmail)
          case Some(to) =>
            limited(u, s"magic:admin:${p.id}", PerAdmin).flatMap {
              case true => Res.fail(ErrorCode.MagicLinkTooMany)
              case false =>
                for {
                  url <- create(u, Json.obj("by" -> "admin".asJson, "actor" -> p.id.asJson))
                  _ <- sendMail(to, u, url, "管理者がログインのリンクを送りました。", c)
                  _ <- audit.byPrincipal(
                    c,
                    p,
                    "magic_link.issue",
                    audit.userTarget(u),
                    detail = Json.obj("delivery" -> "email".asJson)
                  )
                } yield Right(MagicLinkDto("email", ttl))
            }
        }
    }

  // ------------------------------------------------------------------ 発行（サービス）

  /**
   * 許可した OAuth クライアント（機密クライアント）が発行する. リンクを使ったときに、このクライアントへの認可の要求を作り、
   * ログインの後は登録済みのリダイレクト URI へ認可コードを返す.
   */
  def issueByClient(c: ReqCtx, app: Application, oc: OidcClientConfig, r: MagicLinkReq): Res[MagicLinkDto] = {
    val redirect = r.redirectUri.map(_.trim).filter(_.nonEmpty).orElse(oc.redirectUris match {
      case List(one) => Some(one); case _ => None
    })
    val requested = r.scope.getOrElse("openid").split(' ').filter(_.nonEmpty).toList.distinct
    val scopes = requested.filter(oc.scopes.contains)
    if !oc.magicLinks || oc.isPublic || !app.enabled || !oc.grantTypes.contains("authorization_code") then
      Res.fail(ErrorCode.MagicLinkNotAllowed)
    // 登録済みのリダイレクト URI と完全一致だけ（ループバックのポートの違いも許さない. 機密クライアントなので戻り先は決まっている）
    else if !redirect.exists(oc.redirectUris.contains) then Res.fail(ErrorCode.MagicLinkRedirectInvalid)
    else if !Set("url", "email")(r.delivery) then
      Res.fail(ErrorCode.MagicLinkRequestInvalid, "delivery は url か email です")
    else if r.codeChallengeMethod.exists(_ != "S256") || (r.codeChallengeMethod.isDefined && r.codeChallenge.isEmpty)
    then
      Res.fail(ErrorCode.MagicLinkRequestInvalid, "codeChallengeMethod は S256 だけです")
    else if r.responseMode.exists(m => m != "query" && m != "form_post") then
      Res.fail(ErrorCode.MagicLinkRequestInvalid, "responseMode は query か form_post です")
    else if scopes.isEmpty then Res.fail(ErrorCode.MagicLinkRequestInvalid, "使えるスコープがありません")
    else
      dir.users.byLoginName(r.user.trim).flatMap {
        case None => Res.fail(ErrorCode.MagicLinkUserNotFound)
        case Some(u) =>
          (dir.membership(u), apps.accessGroups(app.id), Time.now).flatMapN {
            (m, groups, now) =>
              // sruru の管理者のログインは、サービスからは作らせない
              if u.disabled || u.isService || u.locked(now) || dir.isAdmin(u, m) ||
                (app.restrictAccess && !groups.exists(m.ids.contains))
              then Res.fail(ErrorCode.MagicLinkUserNotAllowed)
              // メールは確認済みのアドレスだけ（未確認のアドレスは他人のものかもしれない）
              else if r.delivery == "email" && u.verifiedEmail.isEmpty then Res.fail(ErrorCode.MagicLinkNoEmail)
              else
                limited(u, s"magic:client:${oc.clientId}", PerClient).flatMap {
                  case true => Res.fail(ErrorCode.MagicLinkTooMany)
                  case false =>
                    // 認可の要求の値（OidcRoutes.authorize が auth_requests に保存するものと同じ形）
                    val authorize = Json.fromFields(
                      List(
                        "client_id" -> oc.clientId.asJson,
                        "redirect_uri" -> redirect.get.asJson,
                        "response_mode" -> r.responseMode.getOrElse("query").asJson,
                        "scope" -> scopes.mkString(" ").asJson
                      ) ++ List(
                        "state" -> r.state,
                        "nonce" -> r.nonce,
                        "code_challenge" -> r.codeChallenge
                      ).collect { case (k, Some(v)) => k -> v.asJson }
                    )
                    for {
                      url <- create(
                        u,
                        Json.obj(
                          "by" -> "client".asJson,
                          "actor" -> oc.clientId.asJson,
                          "appId" -> app.id.asJson,
                          "authorize" -> authorize
                        )
                      )
                      _ <- IO.whenA(r.delivery == "email")(
                        sendMail(u.verifiedEmail.get, u, url, s"「${app.name}」へのログインのリンクです。", c)
                      )
                      _ <- audit.log(
                        c,
                        None,
                        "oauth2",
                        "magic_link.issue",
                        audit.userTarget(u),
                        detail = Json.obj(
                          "client" -> oc.clientId.asJson,
                          "app" -> app.slug.asJson,
                          "delivery" -> r.delivery.asJson
                        )
                      )
                    } yield Right(MagicLinkDto(r.delivery, ttl, Option.when(r.delivery == "url")(url)))
                }
          }
      }
  }

  // ------------------------------------------------------------------ 使う

  /**
   * 確認の画面のボタンから使う. 1回限りで消費し、ログインの流れ（多要素認証を含む）に乗せる.
   * サービスが発行したものは、そのクライアントへの認可の要求を作ってから流れに結び付ける（完了したら /auth/resume でアプリへ戻る）.
   */
  def consume(c: ReqCtx, bs: BrowserSession, token: String): Res[FlowDto] =
    login.precheck(c).flatMap {
      case Some(e) => Res.fail(e)
      case None =>
        for {
          now <- Time.now
          host <- Site.host
          t <- factors.emailTokenByHash(Purpose, Crypto.sha256(token.trim), now)
          // ほかのドメインで出したリンクは「ない」ものとして扱う
          res <- t.filter(_.data.hcursor.get[String]("domain").toOption.getOrElse("") == host) match {
            case None => invalid(c, None, "invalid or expired token")
            case Some(t) =>
              dir.users.find(t.userId).flatMap {
                case None => invalid(c, None, "user not found")
                case Some(u) if u.disabled || u.isService || u.locked(now) =>
                  // 使えない利用者のリンクは消費しない（応答はほかの無効なリンクと同じ）
                  invalid(c, Some(u), if u.disabled then "disabled" else "unusable")
                case Some(u) =>
                  // 同時に2回使われても1回だけ通す
                  factors.consumeEmailToken(t.id).flatMap {
                    case false => invalid(c, Some(u), "already used")
                    case true => start(c, bs, u, t, now)
                  }
              }
          }
        } yield res
    }

  private def invalid(c: ReqCtx, u: Option[User], reason: String): Res[FlowDto] =
    // 失敗はログインの失敗と同じく IP ごとに数える（総当たり・使い回しの試行を止める）. 利用者のロックには数えない
    login.externalFailed(c, None, "login.magic", reason + u.fold("")(x => s": ${x.username}")) *>
      Res.fail(ErrorCode.MagicLinkInvalid)

  private def start(c: ReqCtx, bs: BrowserSession, u: User, t: EmailToken, now: java.time.Instant): Res[FlowDto] = {
    val d = t.data.hcursor
    val request: IO[Option[UUID]] =
      (d.get[UUID]("appId").toOption, d.downField("authorize").focus).tupled.flatTraverse((appId, params) =>
        apps.find(appId).flatMap {
          case Some(a) if a.enabled =>
            Site.host.flatMap(h => tokens.createRequest(appId, "oidc", params, AuthRequests.expires(now), h))
              .map(r => Some(r.id))
          case _ => IO.pure(None)
        }
      )
    request.flatMap { reqId =>
      if d.get[UUID]("appId").isRight && reqId.isEmpty then
        invalid(c, Some(u), "application unavailable")
      else
        for {
          f <- sessions.createFlow(bs.id, reqId, None, now.plusSeconds(15L * 60))
          f2 = f.copy(userId = Some(u.id), amr = List(Amr.Magic))
          _ <- sessions.saveFlow(f2)
          _ <- audit.log(
            c,
            Some(u),
            "web",
            "login.magic",
            audit.userTarget(u),
            detail = Json.obj(
              "by" -> d.get[String]("by").toOption.asJson,
              "actor" -> d.downField("actor").focus.asJson
            )
          )
          dto <- login.advance(c, bs, f2, u)
        } yield Right(dto)
    }
  }
}
