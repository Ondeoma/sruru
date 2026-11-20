package sruru.api

import cats.effect.*
import cats.syntax.all.*
import org.http4s.*
import org.http4s.headers.Authorization
import org.http4s.server.ServerRequestKeys
import org.typelevel.ci.CIString
import sruru.core.*
import sruru.db.*
import sruru.security.*

import java.time.Instant

/**
 * 認証: ブラウザの Cookie（1つのブラウザで複数のアカウントにログインでき、そのうち1つが使用中）、
 * または `Authorization: Bearer sruru_…`（API トークン. REST・MCP・SCIM）.
 */
object SessionAuth {

  /** MCP の内部呼び出しの印（ヘッダーではなく要求の属性. 外からの要求では付けられない）. */
  val McpCall: org.typelevel.vault.Key[Unit] = org.typelevel.vault.Key.newKey[SyncIO, Unit].unsafeRunSync()
}

final class SessionAuth(sessions: SessionStore,
                        factors: FactorStore,
                        dir: Directory,
                        policies: PolicyService,
                        cfg: ApiConfig) {

  // ------------------------------------------------------------------ 要求元

  /** この要求で提示されたクライアント証明書のチェーン（TLS か、信頼するプロキシからのヘッダー）. */
  def presentedChain(req: Request[IO]): IO[Option[List[java.security.cert.X509Certificate]]] =
    policies.global.map { p =>
      val remote = req.remote.map(_.host.toString).getOrElse("-")
      val fromTls =
        req.attributes.lookup(ServerRequestKeys.SecureSession).flatten.map(_.X509Certificate).filter(_.nonEmpty)
      // ヘッダーは信頼するプロキシからのときだけ使う
      val fromHdr = Option.when(IpRules.matches(
        remote,
        p.ip.trustedProxies
      ))(req.headers.get(CIString(p.cert.header)).map(_.head.value))
        .flatten.filter(_.nonEmpty).flatMap(v => ClientCerts.fromHeader(v).toOption).map(List(_))
      fromTls.orElse(fromHdr)
    }

  def reqCtx(req: Request[IO]): IO[ReqCtx] =
    policies.global.map { p =>
      val remote = req.remote.map(_.host.toString).getOrElse("-")
      val ip = IpRules.clientIp(
        remote,
        req.headers.get(CIString("X-Forwarded-For")).map(_.toList.map(_.value).mkString(",")),
        p.ip.trustedProxies,
        Option(p.ip.clientIpHeader.trim).filter(_.nonEmpty).flatMap(h => req.headers.get(CIString(h))).map(_.head.value)
      )
      ReqCtx(ip, req.headers.get(CIString("User-Agent")).map(_.head.value.take(400)))
    }

  /** ユーザーに効く IP の許可・拒否（全体とグループの上書き）. */
  def ipAllowed(req: Request[IO], u: User, m: Membership): IO[Boolean] =
    (reqCtx(req), dir.policyFor(u, m)).mapN((c, p) => IpRules.allowedBy(c.ip, p.ip))

  /** このホスト名（ドメイン）で管理画面・管理 API を使えるか. */
  def adminEnabled: IO[Boolean] = Site.current.map(_.forall(_.policy.admin))

  /** 管理機能の IP 制限. */
  def adminIpAllowed(req: Request[IO]): IO[Boolean] =
    (reqCtx(req), policies.global).mapN((c, p) => p.ip.adminAllow.isEmpty || IpRules.matches(c.ip, p.ip.adminAllow))

  // ------------------------------------------------------------------ ブラウザのセッション

  private def token(req: Request[IO]): Option[String] =
    req.cookies.find(_.name == cfg.cookieName).map(_.content).filter(_.nonEmpty)

  def browser(req: Request[IO]): IO[Option[BrowserSession]] =
    // 作ったときと同じドメイン（ホスト名）のセッションだけ（ほかのホスト名の Cookie を持ち込んでも使えない）
    token(req).fold(IO.pure(None))(t =>
      (Time.now, Site.host).flatMapN((now, d) => sessions.findBrowser(Crypto.sha256(t), now, d))
    )

  /** ブラウザのセッション（なければ作り、Cookie を返す）. */
  def ensureBrowser(req: Request[IO]): IO[(BrowserSession, Option[ResponseCookie])] =
    browser(req).flatMap {
      case Some(b) => IO.pure((b, None))
      case None =>
        for {
          c <- reqCtx(req)
          p <- policies.get
          now <- Time.now
          t = Crypto.randomToken()
          ttl = p.session.lifetimeHours.toLong * 3600
          b <- sessions.createBrowser(Crypto.sha256(t), c.ip, c.userAgent, now.plusSeconds(ttl), p.domain)
        } yield (b, Some(cookie(t, ttl)))
    }

  /** ブラウザのセッションの Cookie の値を新しくする. */
  def rotate(b: BrowserSession): IO[ResponseCookie] =
    (policies.get, Time.now).flatMapN {
      (p, now) =>
        val t = Crypto.randomToken()
        sessions.rotate(b.id, Crypto.sha256(t)).as(cookie(
          t,
          math.max(60L, b.expiresAt.getEpochSecond - now.getEpochSecond)
            .max(p.session.lifetimeHours.toLong * 3600)
        ))
    }

  def cookie(value: String, maxAge: Long): ResponseCookie =
    ResponseCookie(
      cfg.cookieName,
      value,
      maxAge = Some(maxAge),
      path = Some("/"),
      httpOnly = true,
      secure = cfg.cookieSecure,
      sameSite = Some(SameSite.Lax)
    )

  def clearCookie: ResponseCookie = cookie("", 0)

  /** 使用中のログイン（期限・無操作の時間・ユーザーの状態を確かめる）. */
  def active(b: BrowserSession): IO[Option[(Login, User)]] =
    b.activeUser.fold(IO.pure(None)) { uid =>
      for {
        now <- Time.now
        ls <- sessions.logins(b.id, now)
        res <- ls.find(_.userId == uid) match {
          case None => IO.pure(None)
          case Some(l) =>
            dir.users.find(uid).flatMap {
              case Some(u) if !u.disabled && !u.isService =>
                // 無操作の時間はユーザーに効くポリシー（グループの上書き）で判定する
                dir.policyFor(u).flatMap { p =>
                  if p.session.idleMinutes > 0 &&
                    l.lastSeenAt.plusSeconds(p.session.idleMinutes.toLong * 60).isBefore(now)
                  then
                    sessions.removeLogin(b.id, uid).flatMap(_.traverse_(dir.endLogin(uid, _))).as(None)
                  else IO.whenA(l.lastSeenAt.plusSeconds(60).isBefore(now))(sessions.touch(l.id)).as(Some((l, u)))
                }
              case _ => IO.pure(None)
            }
        }
      } yield res
    }

  def activeFor(req: Request[IO]): IO[Option[(BrowserSession, Login, User)]] =
    browser(req).flatMap(_.fold(IO.pure(None))(b =>
      active(b).map(_.map((l, u) => (b, l, u)))
    ))

  // ------------------------------------------------------------------ 利用者

  private def bearer(req: Request[IO]): Option[String] =
    req.headers.get[Authorization].collect { case Authorization(Credentials.Token(AuthScheme.Bearer, t)) => t }.filter(
      ApiTokens.looksLike
    )

  def principal(req: Request[IO]): IO[Option[Principal]] =
    bearer(req) match {
      case Some(t) =>
        Time.now.flatMap(now => factors.findToken(Crypto.sha256(t), now)).flatMap {
          case None => IO.pure(None)
          case Some(tk) =>
            dir.users.find(tk.userId).flatMap {
              case Some(u) if !u.disabled =>
                // IP の許可・拒否（全体とグループの上書き）はトークンにも効かせる
                dir.membership(u).flatMap { m =>
                  ipAllowed(req, u, m).map(ok =>
                    Option.when(ok) {
                      val mcp = req.pathInfo.renderString.startsWith("/mcp") ||
                        req.attributes.contains(SessionAuth.McpCall)
                      Principal(u, m, dir.isAdmin(u, m), Via.Token(tk.id, tk.scopes.toSet, mcp))
                    }
                  )
                }
              case _ => IO.pure(None)
            }
        }
      case None =>
        activeFor(req).flatMap {
          case None => IO.pure(None)
          case Some((b, l, u)) =>
            dir.membership(u).flatMap(m =>
              ipAllowed(req, u, m).map(ok => Option.when(ok)(Principal(u, m, dir.isAdmin(u, m), Via.Web(b, l))))
            )
        }
    }

  def now: IO[Instant] = Time.now
}
