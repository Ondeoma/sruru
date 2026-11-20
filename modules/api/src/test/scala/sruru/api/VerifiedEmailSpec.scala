package sruru.api

import sbirds.db.*
import sbirds.mail.{Mail, Mailer}
import cats.effect.*
import cats.syntax.all.*
import doobie.implicits.*
import io.circe.Json
import io.circe.syntax.*
import munit.CatsEffectSuite
import org.http4s.*
import org.http4s.circe.CirceEntityCodec.*
import org.http4s.client.Client
import org.http4s.headers.{Authorization, Cookie}
import org.http4s.implicits.*
import sruru.core.*
import sruru.db.*
import sruru.security.*
import sruru.shared.*

import java.time.Instant
import java.util.UUID

/**
 * 各サービスに渡すメールアドレスは、確認済みの値だけ:
 * 本人がアドレスを変えた直後は以前の確認済みのアドレス、確認が済んだら新しいアドレス、確認済みのアドレスが無ければ渡さない.
 * OIDC のクレーム・式（SAML・追加のクレーム）・SCIM・トークンで読む /api/me・パスワードの再設定の宛先を確かめる.
 * DB を使う（TEST_DATABASE_URL がなければ飛ばす）.
 */
class VerifiedEmailSpec extends CatsEffectSuite {

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

  /** 再設定の依頼は IP ごとに回数の制限があるので、実行のたびに別の IP にする（ほかのテスト・前回の実行の分を持ち越さない）. */
  private val ctx = {
    val r = new scala.util.Random()
    ReqCtx(s"2001:db8:${r.nextInt(0xffff).toHexString}:${r.nextInt(0xffff).toHexString}::1", None)
  }

  private final case class Services(claims: Claims, login: LoginService, app: HttpApp[IO])

  /** Main と同じ組み立て（外部への HTTP は使わない. メールは送信待ちの表に入るだけ）. */
  private final class Env(val xa: doobie.Transactor[IO]) {
    private val http = Client.fromHttpApp[IO](HttpApp.notFound)
    private val box = new SecretBox("sruru-test-secret-0123456789")
    val users = new UserStore(xa)
    val sessions = new SessionStore(xa)
    val factors = new FactorStore(xa)
    private val apps = new AppStore(xa)
    private val tokens = new TokenStore(xa)
    private val settings = new SettingsStore(xa)
    private val fedStore = new FederationStore(xa)
    private val mailer = new Mailer { def send(m: Mail): IO[Unit] = IO.unit }

    def services: IO[Services] =
      for {
        policies <- PolicyService.create(settings)
        keys <- KeyService.create(tokens, box, "sruru")
      } yield {
        val audit = new AuditService(new AuditStore(xa))
        val mail = new MailService(new MailStore(xa), Some(mailer), cfg)
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
        val scim = new ScimRoutes(dir, sessions, tokens, policies, audit, auth, cfg)
        Services(new Claims(dir, apps, cfg.publicUrl), login, (me.routes <+> scim.routes).orNotFound)
      }

    def addr(label: String): String = s"$label-${UUID.randomUUID().toString.take(8)}@example.com"

    def newUser(email: Option[String], verified: Boolean, isAdmin: Boolean = false): IO[User] =
      users.create(NewUser(
        "mail-" + UUID.randomUUID().toString.take(8),
        email,
        "確認 花子",
        emailVerified = verified,
        isAdmin = isAdmin
      )).map(_.toOption.get)

    /** ログインしたばかりのブラウザの Cookie. */
    def cookie(u: User): IO[RequestCookie] =
      for {
        now <- IO.realTimeInstant
        t = Crypto.randomToken()
        bs <- sessions.createBrowser(Crypto.sha256(t), "127.0.0.1", None, now.plusSeconds(3600))
        _ <- sessions.upsertLogin(bs.id, u.id, List("pwd"), "127.0.0.1", None, now.plusSeconds(3600))
      } yield RequestCookie(cfg.cookieName, t)

    /** API トークン（ほかのサービスが読むときの入口）. */
    def token(u: User, scopes: List[String]): IO[String] = {
      val (t, prefix) = ApiTokens.generate()
      factors.createToken(u.id, "テスト", prefix, Crypto.sha256(t), scopes, None).as(t)
    }

    def reload(u: User): IO[User] = users.find(u.id).map(_.get)

    /** 送信待ちのメールのうち、この宛先のものの件数. */
    def mailsTo(to: String): IO[Int] =
      sql"select count(*) from mail_outbox where to_addr = $to".query[Int].unique.transact(xa)
  }

  private def withDb(name: String)(body: Env => IO[Unit]): Unit =
    test(name)(if dbCfg.isEmpty then IO(assume(false, "TEST_DATABASE_URL が未設定")) else body(Env(xaFixture())))

  private val now = Instant.now()
  private val application =
    Application(UUID.randomUUID(), "rp", "RP", "", "oidc", true, None, false, None, false, Nil, false, now, now)
  private def client(subMode: String = "id") = OidcClientConfig(
    application.id,
    "rp",
    None,
    Nil,
    Nil,
    List("authorization_code"),
    List("openid", "profile", "email"),
    "implicit",
    subMode,
    "RS256",
    300,
    300,
    3600,
    false,
    None
  )

  private def emailClaims(s: Services, u: User): IO[(Option[String], Option[Boolean])] =
    s.claims.build(u, Membership(Nil), application, client(), Set("openid", "email")).map(j =>
      (j.hcursor.get[String]("email").toOption, j.hcursor.get[Boolean]("email_verified").toOption)
    )

  private def putMe(s: Services, ck: RequestCookie, email: Option[String]): IO[(Status, Json)] =
    s.app.run(
      Request[IO](Method.PUT, uri"/api/me")
        .withEntity(Json.obj("name" -> "確認 花子".asJson, "email" -> email.asJson))
        .putHeaders(Cookie(ck), "X-Sruru" -> "1")
    ).flatMap(r => r.as[Json].attempt.map(j => r.status -> j.getOrElse(Json.Null)))

  private def confirm(env: Env, s: Services, u: User, ck: RequestCookie, email: String): IO[Status] = {
    val t = Crypto.randomToken()
    IO.realTimeInstant.flatMap(n =>
      env.factors.createEmailToken(u.id, "verify", EmailBinding.hash(t, email), n.plusSeconds(600))
    ) *>
      s.app.run(
        Request[IO](Method.POST, uri"/api/me/email/confirm")
          .withEntity(Json.obj("token" -> t.asJson))
          .putHeaders(Cookie(ck), "X-Sruru" -> "1")
      ).map(_.status)
  }

  private def bearer(t: String) = Authorization(Credentials.Token(AuthScheme.Bearer, t))

  private def scimEmails(j: Json): List[String] =
    j.hcursor.downField("emails").as[List[Json]].getOrElse(Nil).flatMap(_.hcursor.get[String]("value").toOption)

  withDb("メールを変えた直後のクレームは以前の確認済みのアドレス、確認が済んだら新しいアドレス") { env =>
    val (old, next) = (env.addr("old"), env.addr("new"))
    for {
      s <- env.services
      u0 <- env.newUser(Some(old), verified = true)
      _ = assertEquals(u0.verifiedEmail, Some(old))
      c0 <- emailClaims(s, u0)
      _ = assertEquals(c0, (Some(old), Some(true)))
      ck <- env.cookie(u0)

      // 本人が画面からアドレスを変える: 画面には今の値（未確認）と確認済みの値の両方が返る
      r <- putMe(s, ck, Some(next))
      _ = assertEquals(r._1, Status.Ok, r._2.noSpaces)
      _ = assertEquals(r._2.hcursor.get[String]("email").toOption, Some(next))
      _ = assertEquals(r._2.hcursor.get[Boolean]("emailVerified").toOption, Some(false))
      _ = assertEquals(r._2.hcursor.get[String]("verifiedEmail").toOption, Some(old))
      u1 <- env.reload(u0)
      _ = assertEquals((u1.email, u1.emailVerified, u1.verifiedEmail), (Some(next), false, Some(old)))

      // 各サービスに渡るのは以前の確認済みのアドレス（ID トークン・userinfo・sub（email モード）・式）
      c1 <- emailClaims(s, u1)
      _ = assertEquals(c1, (Some(old), Some(true)))
      _ = assertEquals(Claims.sub(u1, client("email")), old)
      user = Context.user(u1, Membership(Nil), None).hcursor
      _ = assertEquals(user.get[String]("email").toOption, Some(old))
      _ = assertEquals(
        SamlMapping.attributes(Nil, Context.of(user.value, None)).find(_.name == "email").map(_.values),
        Some(List(old))
      )

      // パスワードの再設定のメールは、未確認のアドレスには送らない（確認済みのアドレスへ）
      _ <- s.login.forgot(ctx, ForgotReq(u1.username))
      sent <- (env.mailsTo(old), env.mailsTo(next)).tupled
      _ = assertEquals(sent, (1, 0))

      // 確認が済んだら、新しいアドレスに入れ替わる
      st <- confirm(env, s, u1, ck, next)
      _ = assertEquals(st, Status.NoContent)
      u2 <- env.reload(u0)
      _ = assertEquals((u2.email, u2.emailVerified, u2.verifiedEmail), (Some(next), true, Some(next)))
      c2 <- emailClaims(s, u2)
      _ = assertEquals(c2, (Some(next), Some(true)))
      _ = assertEquals(Claims.sub(u2, client("email")), next)
    } yield ()
  }

  withDb("確認済みのアドレスが無い人は、email も email_verified もクレームに載せない") { env =>
    val a = env.addr("unverified")
    for {
      s <- env.services
      u <- env.newUser(Some(a), verified = false)
      _ = assertEquals(u.verifiedEmail, None)
      j <- s.claims.build(u, Membership(Nil), application, client(), Set("openid", "profile", "email"))
      _ = assertEquals(j.hcursor.keys.map(_.toSet.intersect(Set("email", "email_verified"))), Some(Set.empty[String]))
      _ = assertEquals(Claims.sub(u, client("email")), u.id.toString)
      user = Context.user(u, Membership(Nil), None).hcursor
      _ = assertEquals(user.get[Option[String]]("email").toOption.flatten, None)
      _ = assertEquals(user.get[Boolean]("email_verified").toOption, Some(false))
      // 本人からの再設定の依頼では送らない. 管理者が画面から送るときは、登録されているアドレスへ送る
      _ <- s.login.forgot(ctx, ForgotReq(u.username))
      n0 <- env.mailsTo(a)
      _ = assertEquals(n0, 0)
      _ <- s.login.forgot(ctx, ForgotReq(u.username), byAdmin = true)
      n1 <- env.mailsTo(a)
      _ = assertEquals(n1, 1)
      // 確認すると載る
      ck <- env.cookie(u)
      st <- confirm(env, s, u, ck, a)
      _ = assertEquals(st, Status.NoContent)
      c <- env.reload(u).flatMap(emailClaims(s, _))
      _ = assertEquals(c, (Some(a), Some(true)))
    } yield ()
  }

  withDb("SCIM と、トークンで読む /api/me も確認済みのアドレスを返す（返ってきた値を書き戻しても確認待ちは消えない）") { env =>
    val (old, next) = (env.addr("old"), env.addr("new"))
    for {
      s <- env.services
      u0 <- env.newUser(Some(old), verified = true)
      admin <- env.newUser(None, verified = false, isAdmin = true)
      ck <- env.cookie(u0)
      r <- putMe(s, ck, Some(next))
      _ = assertEquals(r._1, Status.Ok, r._2.noSpaces)

      read <- env.token(u0, List(TokenScopes.Read))
      me <- s.app.run(Request[IO](Method.GET, uri"/api/me").putHeaders(bearer(read))).flatMap(_.as[Json])
      _ = assertEquals(me.hcursor.get[String]("email").toOption, Some(old))
      _ = assertEquals(me.hcursor.get[Boolean]("emailVerified").toOption, Some(true))

      scim <- env.token(admin, List(TokenScopes.Scim))
      path = Uri.unsafeFromString(s"/scim/v2/Users/${u0.id}")
      got <- s.app.run(Request[IO](Method.GET, path).putHeaders(bearer(scim))).flatMap(_.as[Json])
      _ = assertEquals(scimEmails(got), List(old))
      // 読んだ内容をそのまま PUT しても、本人が変えて確認待ちのアドレスは残る
      put <- s.app.run(Request[IO](Method.PUT, path).withEntity(got).putHeaders(bearer(scim)))
      _ = assertEquals(put.status, Status.Ok)
      u1 <- env.reload(u0)
      _ = assertEquals((u1.email, u1.emailVerified, u1.verifiedEmail), (Some(next), false, Some(old)))
      // SCIM で別のアドレスが入ってきたら、確認済みとして入れ替える
      third = env.addr("scim")
      body = got.mapObject(_.add("emails", Json.arr(Json.obj("value" -> third.asJson, "primary" -> true.asJson))))
      put2 <- s.app.run(Request[IO](Method.PUT, path).withEntity(body).putHeaders(bearer(scim)))
      _ = assertEquals(put2.status, Status.Ok)
      u2 <- env.reload(u0)
      _ = assertEquals((u2.email, u2.emailVerified, u2.verifiedEmail), (Some(third), true, Some(third)))
    } yield ()
  }

  withDb("確認済みの値の決まり: 元のアドレスに戻す・確認済みの取り消し・アドレスの削除・ほかの人による確認") { env =>
    val (old, next) = (env.addr("old"), env.addr("new"))
    for {
      s <- env.services
      u0 <- env.newUser(Some(old), verified = true)
      ck <- env.cookie(u0)
      // 変えてから、確認済みだった元のアドレスに戻すと、確認済みのまま
      _ <- putMe(s, ck, Some(next))
      back <- putMe(s, ck, Some(old))
      _ = assertEquals(back._1, Status.Ok, back._2.noSpaces)
      u1 <- env.reload(u0)
      _ = assertEquals((u1.email, u1.emailVerified, u1.verifiedEmail), (Some(old), true, Some(old)))

      // 管理者が同じアドレスの「確認済み」を外すと、確認済みの値も消える（渡さなくなる）
      u2 <- env.users.save(u1.copy(emailVerified = false)).map(_.toOption.get)
      _ = assertEquals((u2.email, u2.verifiedEmail), (Some(old), None))
      // 確認済みにすると入る. 未確認で別のアドレスにすると以前の値が残り、アドレスを消すと確認済みの値も消える
      u3 <- env.users.save(u2.copy(emailVerified = true)).map(_.toOption.get)
      _ = assertEquals(u3.verifiedEmail, Some(old))
      u4 <- env.users.save(u3.copy(email = Some(next), emailVerified = false)).map(_.toOption.get)
      _ = assertEquals(u4.verifiedEmail, Some(old))

      // 別の人が old を確認済みにしたら、old を「以前の値」として持っているだけの人からは外す
      other <- env.newUser(Some(old), verified = false)
      still <- env.reload(u0)
      _ = assertEquals(still.verifiedEmail, Some(old))
      _ <- env.users.save(other.withEmail(Some(old), verified = true))
      released <- env.reload(u0)
      _ = assertEquals((released.email, released.verifiedEmail), (Some(next), None))
      c <- emailClaims(s, released)
      _ = assertEquals(c, (None, None))

      u5 <- env.users.save(released.withEmail(Some(next), verified = true)).map(_.toOption.get)
      u6 <- env.users.save(u5.copy(email = None)).map(_.toOption.get)
      _ = assertEquals(u6.verifiedEmail, None)
    } yield ()
  }
}
