package sruru.api

import sbirds.db.*
import cats.effect.*
import cats.syntax.all.*
import doobie.implicits.*
import doobie.postgres.implicits.*
import io.circe.Json
import io.circe.syntax.*
import munit.CatsEffectSuite
import org.http4s.*
import org.http4s.circe.CirceEntityCodec.*
import org.http4s.client.Client
import org.http4s.headers.Authorization
import org.http4s.implicits.*
import sruru.core.{Amr, Application, ErrorCode, OidcClientConfig, User}
import sruru.db.*
import sruru.security.*
import sruru.shared.*

import java.util.UUID

/**
 * マジックリンク（発行・1回限りの消費・認可の要求への結び付け・多要素認証）と、移行した bcrypt のハッシュでのログイン
 * （成功したら Argon2id に置き換わる）. DB を使う（TEST_DATABASE_URL がなければ飛ばす）.
 */
class MagicLinkSpec extends CatsEffectSuite {

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
  private val ctx = ReqCtx("-", None)

  // jBCrypt（streaming の形式）で作ったハッシュ: 「streaming の古いパスワード 2026」, コスト 4
  private val OldPassword = "streaming の古いパスワード 2026"
  private val OldHash = "$2a$04$WmhGXqlWhQ3CNBohPFt8heDmUnxNV71ZtM/PndGN0Y56MkyAiMYWK"
  private val Secret = "magic-client-secret-0123456789"
  private val Redirect = "https://streaming.example.com/auth/callback"

  private final class Env(val xa: doobie.Transactor[IO]) {
    private val http = Client.fromHttpApp[IO](HttpApp.notFound)
    val box = new SecretBox("sruru-test-secret-0123456789")
    val users = new UserStore(xa)
    val sessions = new SessionStore(xa)
    val factors = new FactorStore(xa)
    val apps = new AppStore(xa)
    val tokens = new TokenStore(xa)
    private val settings = new SettingsStore(xa)
    private val fedStore = new FederationStore(xa)

    def services: IO[(LoginService, MagicLinkService, HttpApp[IO])] =
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
        val magic = new MagicLinkService(dir, login, sessions, factors, tokens, apps, audit, mail, cfg)
        (login, magic, new MagicLinkRoutes(magic, dir, apps, auth, cfg).routes.orNotFound)
      }

    def user(hash: Option[String] = None, verifiedEmail: Boolean = true, admin: Boolean = false): IO[User] = {
      val name = "magic-" + UUID.randomUUID().toString.take(8)
      users.create(NewUser(
        name,
        Some(s"$name@example.com"),
        "移行 太郎",
        passwordHash = hash,
        emailVerified = verifiedEmail,
        isAdmin = admin
      )).map(_.toOption.get)
    }

    /** サービス（機密クライアント）. magicLinks で発行の許可. */
    def client(magicLinks: Boolean = true, requireMfa: Boolean = false): IO[(Application, OidcClientConfig)] =
      IO.realTimeInstant.flatMap { now =>
        val id = UUID.randomUUID()
        val slug = "svc-" + id.toString.take(8)
        val a = Application(id, slug, "テストのサービス", "", "oidc", true, None, false, None, requireMfa, Nil, false, now, now)
        val c = OidcClientConfig(
          id,
          slug,
          Some(Crypto.sha256(Secret)),
          List(Redirect),
          Nil,
          List("authorization_code", "refresh_token"),
          List("openid", "profile", "email"),
          "implicit",
          "id",
          "RS256",
          300,
          300,
          3600,
          false,
          None,
          magicLinks = magicLinks
        )
        apps.create(a, Some(c), None).map(r => (r.toOption.get, c))
      }

    def browser: IO[BrowserSession] =
      IO.realTimeInstant.flatMap(now =>
        sessions.createBrowser(Crypto.sha256(Crypto.randomToken()), "127.0.0.1", None, now.plusSeconds(3600))
      )

    /** IP ごとの失敗の回数を消す（テストの要求はどれも同じ IP「-」）. */
    def clearThrottle: IO[Unit] = IO.realTimeInstant.flatMap(now => factors.purgeThrottle(now.plusSeconds(60))).void
  }

  private def withDb(name: String)(body: Env => IO[Unit]): Unit =
    test(name)(if dbCfg.isEmpty then IO(assume(false, "TEST_DATABASE_URL が未設定")) else body(Env(xaFixture())))

  private def tokenOf(url: String): String = url.split("token=").last

  private def req(u: User, delivery: String = "url"): MagicLinkReq =
    MagicLinkReq(
      u.username,
      Some(Redirect),
      Some("openid email"),
      Some("st-123"),
      Some("n-1"),
      Some("challenge-abc"),
      Some("S256"),
      None,
      delivery
    )

  // ------------------------------------------------------------------ bcrypt

  withDb("bcrypt のハッシュの利用者: 正しいパスワードでログインでき、Argon2id に置き換わる（履歴も）") { env =>
    for {
      _ <- env.clearThrottle
      sv <- env.services
      (login, _, _) = sv
      u <- env.user(hash = Some(OldHash))
      bs <- env.browser
      // 違うパスワードでは通らず、bcrypt のまま
      f0 <- login.start(ctx, bs, LoginStartReq(), None).map(_.toOption.get)
      bad <- login.password(ctx, bs, PasswordLoginReq(f0.id, u.username, "wrong"))
      _ = assertEquals(bad.left.map(_.code), Left(ErrorCode.LoginFailed))
      still <- env.users.find(u.id).map(_.get)
      _ = assertEquals(still.passwordHash, Some(OldHash))
      // 正しいパスワード
      ok <- login.password(ctx, bs, PasswordLoginReq(f0.id, u.username, OldPassword)).map(_.toOption.get)
      _ = assertEquals(ok.stage, "done")
      after <- env.users.find(u.id).map(_.get)
      h = after.passwordHash.get
      _ = assert(h.startsWith("$argon2id$"), h)
      _ = assert(Passwords.verify(OldPassword, h))
      _ = assertEquals(after.passwordChangedAt, still.passwordChangedAt)
      hist <- env.users.passwordHistory(u.id, 10)
      _ = assertEquals(hist, List(h))
      // 置き換えた後も同じパスワードでログインできる
      bs2 <- env.browser
      f1 <- login.start(ctx, bs2, LoginStartReq(), None).map(_.toOption.get)
      ok2 <- login.password(ctx, bs2, PasswordLoginReq(f1.id, u.username, OldPassword)).map(_.toOption.get)
      _ = assertEquals(ok2.stage, "done")
      _ <- env.clearThrottle
    } yield ()
  }

  // ------------------------------------------------------------------ マジックリンク

  withDb("サービスが発行したリンク: 1回だけ使え、認可の要求に結び付いてアプリへ戻る") { env =>
    for {
      _ <- env.clearThrottle
      sv <- env.services
      (_, magic, _) = sv
      ac <- env.client()
      (app, oc) = ac
      u <- env.user()
      r <- magic.issueByClient(ctx, app, oc, req(u)).map(_.toOption.get)
      _ = assertEquals(r.delivery, "url")
      _ = assertEquals(r.expiresIn, 15L * 60)
      url = r.url.get
      _ = assert(url.startsWith("http://localhost:9100/magic?token="), url)
      // DB にはハッシュだけ
      raw <- sql"select count(*) from email_tokens where token_hash = ${tokenOf(url).getBytes}".query[Int].unique
        .transact(env.xa)
      _ = assertEquals(raw, 0)
      bs <- env.browser
      f <- magic.consume(ctx, bs, tokenOf(url)).map(_.toOption.get)
      _ = assertEquals(f.stage, "done")
      reqId = f.redirect.get.stripPrefix("/auth/resume?req=")
      ar <- IO.realTimeInstant.flatMap(now => env.tokens.request(UUID.fromString(reqId), now)).map(_.get)
      _ = assertEquals(ar.appId, app.id)
      p = ar.params.hcursor
      _ = assertEquals(p.get[String]("redirect_uri").toOption, Some(Redirect))
      _ = assertEquals(p.get[String]("state").toOption, Some("st-123"))
      _ = assertEquals(p.get[String]("code_challenge").toOption, Some("challenge-abc"))
      _ = assertEquals(p.get[String]("scope").toOption, Some("openid email"))
      now <- IO.realTimeInstant
      l <- env.sessions.logins(bs.id, now).map(_.find(_.userId == u.id).get)
      _ = assertEquals(l.amr, List(Amr.Magic))
      // 2回目は使えない
      again <- magic.consume(ctx, bs, tokenOf(url))
      _ = assertEquals(again.left.map(_.code), Left(ErrorCode.MagicLinkInvalid))
      _ <- env.clearThrottle
    } yield ()
  }

  withDb("期限切れ・ほかのドメインのリンクは使えない") { env =>
    for {
      _ <- env.clearThrottle
      sv <- env.services
      (_, magic, _) = sv
      ac <- env.client()
      (app, oc) = ac
      u <- env.user()
      r1 <- magic.issueByClient(ctx, app, oc, req(u)).map(_.toOption.get)
      _ <- sql"update email_tokens set expires_at = now() - interval '1 minute' where user_id = ${u.id}".update.run
        .transact(env.xa)
      bs <- env.browser
      e1 <- magic.consume(ctx, bs, tokenOf(r1.url.get))
      _ = assertEquals(e1.left.map(_.code), Left(ErrorCode.MagicLinkInvalid))
      r2 <- magic.issueByClient(ctx, app, oc, req(u)).map(_.toOption.get)
      _ <-
        sql"update email_tokens set data = data || jsonb_build_object('domain', 'other.example.com') where user_id = ${u.id}"
          .update.run.transact(env.xa)
      e2 <- magic.consume(ctx, bs, tokenOf(r2.url.get))
      _ = assertEquals(e2.left.map(_.code), Left(ErrorCode.MagicLinkInvalid))
      _ <- env.clearThrottle
    } yield ()
  }

  withDb("発行の条件: 許可のないクライアント・登録外の戻り先・管理者・未確認のアドレス・回数の上限") { env =>
    for {
      _ <- env.clearThrottle
      sv <- env.services
      (_, magic, _) = sv
      denied <- env.client(magicLinks = false)
      ac <- env.client()
      (app, oc) = ac
      u <- env.user()
      e1 <- magic.issueByClient(ctx, denied._1, denied._2, req(u))
      _ = assertEquals(e1.left.map(_.code), Left(ErrorCode.MagicLinkNotAllowed))
      e2 <- magic.issueByClient(ctx, app, oc, req(u).copy(redirectUri = Some(Redirect + "/x")))
      _ = assertEquals(e2.left.map(_.code), Left(ErrorCode.MagicLinkRedirectInvalid))
      e3 <- magic.issueByClient(ctx, app, oc, req(u).copy(codeChallengeMethod = Some("plain")))
      _ = assertEquals(e3.left.map(_.code), Left(ErrorCode.MagicLinkRequestInvalid))
      adm <- env.user(admin = true)
      e4 <- magic.issueByClient(ctx, app, oc, req(adm))
      _ = assertEquals(e4.left.map(_.code), Left(ErrorCode.MagicLinkUserNotAllowed))
      unverified <- env.user(verifiedEmail = false)
      e5 <- magic.issueByClient(ctx, app, oc, req(unverified, "email"))
      _ = assertEquals(e5.left.map(_.code), Left(ErrorCode.MagicLinkNoEmail))
      e6 <- magic.issueByClient(ctx, app, oc, req(u).copy(user = "nobody-" + UUID.randomUUID()))
      _ = assertEquals(e6.left.map(_.code), Left(ErrorCode.MagicLinkUserNotFound))
      // 利用者ごとに 15 分で 5 回まで
      rs <- (1 to 6).toList.traverse[IO, Either[sbirds.shared.AppError, MagicLinkDto]](_ =>
        magic.issueByClient(ctx, app, oc, req(u))
      )
      _ = assertEquals(rs.map(_.isRight), List(true, true, true, true, true, false))
      _ = assertEquals(rs.last.left.map(_.code), Left(ErrorCode.MagicLinkTooMany))
      // 新しいリンクを出すと前のリンクは使えない
      bs <- env.browser
      first <- magic.consume(ctx, bs, tokenOf(rs.head.toOption.get.url.get))
      _ = assertEquals(first.left.map(_.code), Left(ErrorCode.MagicLinkInvalid))
      last <- magic.consume(ctx, bs, tokenOf(rs(4).toOption.get.url.get))
      _ = assert(last.isRight, last.toString)
      _ <- env.clearThrottle
    } yield ()
  }

  withDb("多要素認証: 認証アプリを登録した人は2つ目の要素を求められ、メールのコードは選べない") { env =>
    for {
      _ <- env.clearThrottle
      sv <- env.services
      (login, magic, _) = sv
      ac <- env.client()
      (app, oc) = ac
      u <- env.user()
      d <- env.factors.addTotp(u.id, "認証アプリ", env.box.encrypt(Totp.newSecret()))
      _ <- env.factors.confirmTotp(d.id, 0)
      r <- magic.issueByClient(ctx, app, oc, req(u)).map(_.toOption.get)
      bs <- env.browser
      f <- magic.consume(ctx, bs, tokenOf(r.url.get)).map(_.toOption.get)
      _ = assertEquals(f.stage, "mfa")
      _ = assertEquals(f.mfaMethods, List("totp"))
      // メールのコードは送れず、使えない
      e1 <- login.sendEmailCode(ctx, bs, f.id)
      _ = assertEquals(e1.left.map(_.code), Left(ErrorCode.EmailCodeDisabled))
      e2 <- login.mfa(ctx, bs, MfaReq(f.id, "email", "123456"))
      _ = assertEquals(e2.left.map(_.code), Left(ErrorCode.CodeInvalidOrExpired))
      now <- IO.realTimeInstant
      ls <- env.sessions.logins(bs.id, now)
      _ = assert(!ls.exists(_.userId == u.id), "2つ目の要素の前にログインできてしまった")
      _ <- env.clearThrottle
    } yield ()
  }

  withDb("多要素認証が必須で認証アプリがない人は、リンクでは登録させずに断る") { env =>
    for {
      _ <- env.clearThrottle
      sv <- env.services
      (_, magic, _) = sv
      ac <- env.client(requireMfa = true)
      (app, oc) = ac
      u <- env.user()
      r <- magic.issueByClient(ctx, app, oc, req(u)).map(_.toOption.get)
      bs <- env.browser
      // アプリで必須. 確認済みのアドレスはあるが、リンクの流れではメールのコードを使えない
      f <- magic.consume(ctx, bs, tokenOf(r.url.get)).map(_.toOption.get)
      _ = assertEquals(f.stage, "error")
      _ = assertEquals(f.message, Some(ErrorCode.MagicLinkMfaEnrollNeeded.message))
      ts <- env.factors.totps(u.id)
      _ = assertEquals(ts, Nil)
      _ <- env.clearThrottle
    } yield ()
  }

  withDb("POST /api/magic-links: Basic 認証のクライアントだけが発行できる") { env =>
    def call(app: HttpApp[IO], secret: String, body: Json): IO[(Status, Json)] =
      app.run(
        Request[IO](Method.POST, uri"/api/magic-links").withEntity(body)
          .putHeaders(Authorization(BasicCredentials(secret.takeWhile(_ != ':'), secret.dropWhile(_ != ':').drop(1))))
      ).flatMap(r => r.as[Json].map(r.status -> _))
    for {
      _ <- env.clearThrottle
      sv <- env.services
      (_, _, app) = sv
      ac <- env.client()
      (_, oc) = ac
      u <- env.user()
      body = Json.obj("user" -> u.email.get.asJson, "redirectUri" -> Redirect.asJson, "state" -> "s".asJson)
      bad <- call(app, s"${oc.clientId}:wrong", body)
      _ = assertEquals(bad._1, Status.Unauthorized)
      _ = assertEquals(bad._2.hcursor.get[String]("code").toOption, Some(ErrorCode.MagicLinkClientAuthFailed.code))
      ok <- call(app, s"${oc.clientId}:$Secret", body)
      _ = assertEquals(ok._1, Status.Ok)
      _ = assert(ok._2.hcursor.get[String]("url").toOption.exists(_.contains("/magic?token=")), ok._2.noSpaces)
      _ <- env.clearThrottle
    } yield ()
  }
}
