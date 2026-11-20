package sruru.api

import sbirds.db.*
import cats.effect.*
import cats.syntax.all.*
import io.circe.Json
import io.circe.syntax.*
import munit.CatsEffectSuite
import org.http4s.*
import org.http4s.circe.CirceEntityCodec.*
import org.http4s.client.Client
import org.http4s.headers.Cookie
import org.http4s.implicits.*
import sruru.core.{ErrorCode, User}
import sruru.db.*
import sruru.security.*
import sruru.shared.*

import java.util.UUID

/**
 * ログインの守り: 多要素認証の追加（step-up）の途中では要素を新しく登録できないこと、
 * ログイン後のパスワードの確認にもログインと同じ試行の制限がかかること.
 * DB を使う（TEST_DATABASE_URL がなければ飛ばす）.
 */
class LoginGuardSpec extends CatsEffectSuite {

  private val dbCfg: Option[DbConfig] = sys.env.get("TEST_DATABASE_URL").map(url =>
    DbConfig(
      url,
      sys.env.getOrElse("TEST_DATABASE_USER", "sruru"),
      sys.env.getOrElse("TEST_DATABASE_PASSWORD", "sruru")
    )
  )

  private val xaFixture = ResourceSuiteLocalFixture(
    "xa",
    dbCfg.fold(Resource.eval(IO.raiseError[doobie.Transactor[IO]](new RuntimeException("no db"))))(c =>
      Resource.eval(Database.migrate(c)) *> Database.transactor(c)
    )
  )

  override def munitFixtures = if dbCfg.isDefined then List(xaFixture) else Nil

  private val cfg = ApiConfig(publicUrl = "http://localhost:9100", cookieSecure = false)
  private val Password = "correct horse battery staple 42"

  /** Main と同じ組み立て（外部への HTTP は使わない）. */
  private final class Env(xa: doobie.Transactor[IO]) {
    private val http = Client.fromHttpApp[IO](HttpApp.notFound)
    val box = new SecretBox("sruru-test-secret-0123456789")
    val users = new UserStore(xa)
    val sessions = new SessionStore(xa)
    val factors = new FactorStore(xa)
    private val apps = new AppStore(xa)
    private val tokens = new TokenStore(xa)
    private val settings = new SettingsStore(xa)
    private val fedStore = new FederationStore(xa)

    def services: IO[(LoginService, HttpApp[IO])] =
      for {
        policies <- PolicyService.create(settings)
        keys <- KeyService.create(tokens, box, "sruru")
      } yield {
        val audit = new AuditService(new AuditStore(xa))
        val mail = new MailService(new MailStore(xa), None, cfg)
        val dir = new Directory(
          users,
          new GroupStore(xa),
          factors,
          sessions,
          tokens,
          policies,
          new LogoutNotifier(apps, tokens, keys, http, cfg),
          cfg
        )
        val auth = new SessionAuth(sessions, factors, dir, policies, cfg)
        val login = new LoginService(dir, sessions, factors, tokens, apps, fedStore, policies, audit, mail, box, cfg)
        val me =
          new MeRoutes(
            dir,
            factors,
            sessions,
            tokens,
            apps,
            fedStore,
            login,
            mail,
            policies,
            audit,
            box,
            settings,
            auth,
            cfg
          )
        (login, me.routes.orNotFound)
      }

    /** パスワードでログインした利用者（多要素認証は未登録）と、そのブラウザのセッション・Cookie. */
    def loggedIn: IO[(User, BrowserSession, RequestCookie)] =
      for {
        h <- Directory.hash(Password)
        u <- users.create(NewUser(
          "guard-" + UUID.randomUUID().toString.take(8),
          None,
          "守り 太郎",
          passwordHash = Some(h)
        )).map(_.toOption.get)
        now <- IO.realTimeInstant
        t = Crypto.randomToken()
        bs <- sessions.createBrowser(Crypto.sha256(t), "127.0.0.1", None, now.plusSeconds(3600))
        _ <- sessions.upsertLogin(bs.id, u.id, List("pwd"), "127.0.0.1", None, now.plusSeconds(3600))
      } yield (u, bs, RequestCookie(cfg.cookieName, t))

    /** IP ごとの失敗の回数を消す（テストの要求はどれも同じ IP「-」になるので、前のテスト・前回の実行の分を持ち越さない）. */
    def clearThrottle: IO[Unit] = IO.realTimeInstant.flatMap(now => factors.purgeThrottle(now.plusSeconds(60))).void
  }

  private def withDb(name: String)(body: Env => IO[Unit]): Unit =
    test(name)(if dbCfg.isEmpty then IO(assume(false, "TEST_DATABASE_URL が未設定")) else body(Env(xaFixture())))

  private val ctx = ReqCtx("-", None)

  private def stepUp(env: Env, login: LoginService, u: User, bs: BrowserSession): IO[FlowDto] =
    for {
      now <- IO.realTimeInstant
      l <- env.sessions.logins(bs.id, now).map(_.find(_.userId == u.id).get)
      f <- login.start(ctx, bs, LoginStartReq(stepUp = true), Some((l, u))).map(_.toOption.get)
    } yield f

  withDb("step-up の途中では、認証アプリを新しく登録できない（要素が未登録ならエラーで終わる）") { env =>
    for {
      sv <- env.services
      (login, _) = sv
      li <- env.loggedIn
      (u, bs, _) = li
      f <- stepUp(env, login, u, bs)
      // 登録の段階（enroll_mfa）へは進まない
      _ = assertEquals(f.stage, "error")
      _ = assertEquals(f.message, Some(ErrorCode.MfaEnrollNotInStepUp.message))
      // 流れは消してあるので、登録の API も使えない
      e <- login.enrollTotp(bs, f.id)
      _ = assert(e.isLeft, e.toString)
      n <- env.factors.totps(u.id)
      _ = assertEquals(n, Nil)
      // ログインは多要素になっていない
      now <- IO.realTimeInstant
      l <- env.sessions.logins(bs.id, now).map(_.find(_.userId == u.id).get)
      _ = assertEquals(l.amr, List("pwd"))
    } yield ()
  }

  withDb("step-up の流れのまま登録の段階にあっても、登録の開始・確認は断る") { env =>
    for {
      sv <- env.services
      (login, _) = sv
      li <- env.loggedIn
      (u, bs, _) = li
      // 登録済みの認証アプリがあれば、その確認（mfa）へ進む
      secret = Totp.newSecret()
      d <- env.factors.addTotp(u.id, "認証アプリ", env.box.encrypt(secret))
      _ <- env.factors.confirmTotp(d.id, 0)
      f <- stepUp(env, login, u, bs)
      _ = assertEquals(f.stage, "mfa")
      _ = assertEquals(f.mfaMethods, List("totp"))
      // 流れの段階だけを登録（enroll_mfa）に書き換えても、step-up の流れでは登録できない
      now <- IO.realTimeInstant
      flow <- env.sessions.flow(f.id, bs.id, now).map(_.get)
      _ <- env.sessions.saveFlow(flow.copy(stage = "enroll_mfa"))
      e1 <- login.enrollTotp(bs, f.id)
      _ = assertEquals(e1.left.map(_.code), Left(ErrorCode.MfaEnrollNotInStepUp))
      pending <- env.factors.addTotp(u.id, "攻撃者のアプリ", env.box.encrypt(Totp.newSecret()))
      e2 <- login.verifyEnroll(ctx, bs, FlowTotpVerifyReq(f.id, pending.id, "000000"))
      _ = assertEquals(e2.left.map(_.code), Left(ErrorCode.MfaEnrollNotInStepUp))
      ts <- env.factors.totps(u.id)
      _ = assertEquals(ts.filter(_.confirmed).map(_.id), List(d.id))
    } yield ()
  }

  private def changePassword(app: HttpApp[IO], ck: RequestCookie, current: String): IO[(Status, String)] =
    app.run(
      Request[IO](Method.POST, uri"/api/me/password")
        .withEntity(Json.obj("current" -> current.asJson, "next" -> "another long passphrase 2026!".asJson))
        .putHeaders(Cookie(ck), "X-Sruru" -> "1")
    ).flatMap(r =>
      r.as[Json].attempt.map(j => r.status -> j.toOption.flatMap(_.hcursor.get[String]("code").toOption).getOrElse(""))
    )

  withDb("ログイン後のパスワードの確認: 失敗を重ねるとアカウントがロックされ、正しいパスワードでも通らない") { env =>
    for {
      _ <- env.clearThrottle
      sv <- env.services
      (_, app) = sv
      li <- env.loggedIn
      (u, _, ck) = li
      // 既定のポリシー: 5回の失敗でロック
      rs <- (1 to 5).toList.traverse(_ => changePassword(app, ck, "wrong password"))
      _ = assertEquals(rs.map(_._2).distinct, List(ErrorCode.CurrentPasswordWrong.code))
      locked <- env.users.find(u.id).map(_.get)
      now <- IO.realTimeInstant
      _ = assert(locked.locked(now), "ロックされていない")
      r <- changePassword(app, ck, Password)
      _ = assertEquals(r, (Status.Forbidden, ErrorCode.AccountLocked.code))
      // パスワードは変わっていない
      after <- env.users.find(u.id).map(_.get)
      _ = assert(Passwords.verify(Password, after.passwordHash.get))
      _ <- env.clearThrottle
    } yield ()
  }

  withDb("ログイン後のパスワードの確認: 同じ IP からの失敗が上限に達すると、確かめずに 429") { env =>
    for {
      _ <- env.clearThrottle
      sv <- env.services
      (_, app) = sv
      li <- env.loggedIn
      (u, _, ck) = li
      // 失敗は IP ごとの回数にも数える
      _ <- changePassword(app, ck, "wrong password")
      now <- IO.realTimeInstant
      n <- env.factors.throttleCount("ip:-", now.minusSeconds(60))
      _ = assertEquals(n, 1)
      // 既定のポリシー: 同じ IP から15分に30回まで
      _ <- (1 to 29).toList.traverse_(_ => env.factors.throttleFail("ip:-", now.minusSeconds(60)))
      r <- changePassword(app, ck, Password)
      _ = assertEquals(r, (Status.TooManyRequests, ErrorCode.TooManyAttempts.code))
      after <- env.users.find(u.id).map(_.get)
      _ = assert(Passwords.verify(Password, after.passwordHash.get))
      _ <- env.clearThrottle
      // 制限が解ければ、正しいパスワードで変えられる
      ok <- changePassword(app, ck, Password)
      _ = assertEquals(ok._1, Status.NoContent)
    } yield ()
  }
}
