package sruru.api

import cats.effect.*
import io.circe.Json
import io.circe.syntax.*
import org.http4s.*
import org.http4s.headers.Location
import sruru.core.*
import sruru.db.*

/** アプリケーションへのログインを許すかの判定の結果. */
enum Gate {
  case Proceed(
    bs: BrowserSession,
    login: Login,
    user: User,
    membership: Membership)

  /** 画面での操作が要る（ログイン・アカウントの選択・多要素認証の追加）. error は prompt=none のときに返す OAuth のエラー. */
  case Interact(
    path: String,
    error: String)

  /** 許可しない（error は OAuth のエラー、message は利用者に見せる文）. */
  case Deny(
    error: String,
    message: String)
}

/** 判定の条件. */
final case class GateOpts(forceLogin: Boolean, passive: Boolean, maxAge: Option[Long], selectAccount: Boolean)

/**
 * OIDC・SAML で共通の判定: アプリの有効・IP 制限・ログイン（再認証・max_age）・アカウントの選択・利用できるグループ・多要素認証.
 */
final class AuthGate(auth: SessionAuth,
                     apps: AppStore,
                     tokens: TokenStore,
                     dir: Directory,
                     policies: PolicyService,
                     audit: AuditService) {

  def check(req: Request[IO], r: AuthRequest, app: Application, o: GateOpts): IO[Gate] =
    for {
      c <- auth.reqCtx(req)
      now <- Time.now
      active <- auth.activeFor(req)
      p <- active.fold(policies.get)(a => dir.policyFor(a._3))
      groups <- apps.accessGroups(app.id)
      g <-
        if !app.enabled then IO.pure(Gate.Deny("access_denied", "このアプリケーションは現在使えません"))
        else if !IpRules.allowedBy(c.ip, p.ip) || (app.ipAllow.nonEmpty && !IpRules.matches(c.ip, app.ipAllow)) then
          audit.log(
            c,
            active.map(_._3),
            "web",
            "app.access",
            audit.appTarget(app),
            success = false,
            detail = Json.obj("reason" -> "ip".asJson)
          )
            .as(Gate.Deny("access_denied", "この IP アドレスからはこのアプリケーションを使えません"))
        else
          active match {
            case None => IO.pure(Gate.Interact(s"/login?req=${r.id}", "login_required"))
            // 再認証: 要求を受けた後にログインしたのでなければ、ログインし直してもらう
            case Some((_, l, _)) if o.forceLogin && l.authTime.isBefore(r.createdAt.minusSeconds(1)) =>
              IO.pure(Gate.Interact(s"/login?req=${r.id}&add=1", "login_required"))
            case Some((_, l, _)) if o.maxAge.exists(m => l.authTime.plusSeconds(m).isBefore(now)) =>
              IO.pure(Gate.Interact(s"/login?req=${r.id}&add=1", "login_required"))
            case Some((bs, _, u)) if o.selectAccount && !AuthRequests.markedBy(r, "selectedBy", bs, u.id) =>
              IO.pure(Gate.Interact(s"/choose?req=${r.id}", "account_selection_required"))
            case Some((bs, l, u)) =>
              dir.membership(u).flatMap { m =>
                if app.restrictAccess && !groups.exists(m.ids.contains) then
                  audit.log(
                    c,
                    Some(u),
                    "web",
                    "app.access",
                    audit.appTarget(app),
                    success = false,
                    detail = Json.obj("reason" -> "group".asJson)
                  )
                    .as(Gate.Deny("access_denied", s"「${app.name}」を使う権限がありません。管理者に連絡してください"))
                else if app.requireMfa && !Amr.isMulti(l.amr) then
                  IO.pure(Gate.Interact(s"/login?req=${r.id}&stepup=1", "interaction_required"))
                else IO.pure(Gate.Proceed(bs, l, u, m))
              }
          }
    } yield g

  /** 画面のエラー表示へ. */
  def errorPage(message: String): IO[Response[IO]] =
    IO.pure(Response[IO](Status.SeeOther).putHeaders(Location(Uri.unsafeFromString("/error").withQueryParam(
      "message",
      message
    ))))

  def redirect(path: String): IO[Response[IO]] =
    IO.pure(Response[IO](Status.SeeOther).putHeaders(
      Location(Uri.unsafeFromString(path)),
      "Cache-Control" -> "no-store"
    ))
}
