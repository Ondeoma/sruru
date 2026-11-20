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
import sruru.core.{Domain, ErrorCode, User}
import sruru.db.*
import sruru.security.*
import sruru.shared.*

import java.util.UUID

/**
 * マルチドメイン: アクセスしたホスト名でポリシー・issuer・表示が変わること、セッション・認可コード・トークンが
 * 作ったドメインに結び付くこと. DB を使う（TEST_DATABASE_URL がなければ飛ばす）.
 */
class DomainSpec extends CatsEffectSuite {

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

  private val cfg = ApiConfig(publicUrl = "https://auth.example.test", cookieSecure = true)

  /** Main と同じ組み立て（外部への HTTP は使わない）. app は、要求ごとにドメインを決めるミドルウェアを通したもの. */
  private final class Env(xa: doobie.Transactor[IO]) {
    private val http = Client.fromHttpApp[IO](HttpApp.notFound)
    private val box = new SecretBox("sruru-test-secret-0123456789")
    val users = new UserStore(xa)
    val sessions = new SessionStore(xa)
    val tokens = new TokenStore(xa)
    val store = new DomainStore(xa)
    private val factors = new FactorStore(xa)
    private val apps = new AppStore(xa)
    private val settings = new SettingsStore(xa)
    private val fedStore = new FederationStore(xa)

    def services: IO[(Domains, PolicyService, HttpApp[IO])] =
      for {
        policies <- PolicyService.create(settings)
        domains <- Domains.create(store, policies, cfg)
        keys <- KeyService.create(tokens, box, "sruru")
        _ <- keys.ensure
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
        val fed = new FederationService(fedStore, dir, audit, box, http, new JobLock(xa, "test"), cfg)
        val gate = new AuthGate(auth, apps, tokens, dir, policies, audit)
        val oidc =
          new OidcRoutes(apps, tokens, sessions, dir, keys, new Claims(dir, apps), gate, auth, audit, http, cfg)
        val loginR = new LoginRoutes(
          login,
          fed,
          fedStore,
          auth,
          sessions,
          tokens,
          apps,
          dir,
          factors,
          settings,
          policies,
          audit,
          box,
          cfg
        )
        val domainR = new DomainRoutes(domains, dir, sessions, fedStore, audit, auth, cfg)
        (domains, policies, domains.middleware((loginR.routes <+> oidc.routes <+> domainR.routes).orNotFound))
      }

    /** ドメインを作る（テストごとに別のホスト名）. */
    def domain(policy: DomainPolicy, domains: Domains): IO[Domain] =
      store.create(s"d-${UUID.randomUUID().toString.take(8)}.example.test", "テスト", policy).map(_.get) <*
        domains.invalidate

    /** 管理者と、そのドメイン（空なら既定のホスト名）でログイン済みのブラウザの Cookie. */
    def admin(domain: String): IO[(User, RequestCookie)] =
      for {
        u <- users.create(NewUser("dom-" + UUID.randomUUID().toString.take(8), None, "管理 花子", isAdmin = true))
          .map(_.toOption.get)
        now <- IO.realTimeInstant
        t = Crypto.randomToken()
        bs <- sessions.createBrowser(Crypto.sha256(t), "127.0.0.1", None, now.plusSeconds(3600), domain)
        _ <- sessions.upsertLogin(bs.id, u.id, List("pwd"), "127.0.0.1", None, now.plusSeconds(3600))
      } yield (u, RequestCookie(cfg.cookieName, t))
  }

  private def withDb(name: String)(body: Env => IO[Unit]): Unit =
    test(name)(if dbCfg.isEmpty then IO(assume(false, "TEST_DATABASE_URL が未設定")) else body(Env(xaFixture())))

  private def get(app: HttpApp[IO],
                  path: String,
                  host: String,
                  cookie: Option[RequestCookie] = None): IO[(Status, Json)] = {
    val req = Request[IO](Method.GET, Uri.unsafeFromString(path)).putHeaders("Host" -> host)
    app.run(cookie.fold(req)(c => req.putHeaders(Cookie(c)))).flatMap(r =>
      r.as[Json].attempt.map(j => r.status -> j.getOrElse(Json.Null))
    )
  }

  private def code(j: Json): String = j.hcursor.get[String]("code").getOrElse("")

  withDb("ホスト名ごとに issuer・表示・ポリシーが変わる（登録のないホスト名は既定のまま）") { env =>
    for {
      sv <- env.services
      (domains, policies, app) = sv
      d <- env.domain(
        DomainPolicy(
          password = PasswordOverride(minLength = Some(6)),
          branding = DomainBranding(title = Some("取引先ポータル"), loginMessage = Some("取引先の方はこちら")),
          login = DomainLogin(cert = Some(false), providers = Some(Nil))
        ),
        domains
      )
      // OIDC の discovery: issuer・各エンドポイントは、アクセスしたホスト名のもの
      a <- get(app, "/.well-known/openid-configuration", d.host)
      _ = assertEquals(a._2.hcursor.get[String]("issuer"), Right(s"https://${d.host}"))
      _ = assertEquals(a._2.hcursor.get[String]("token_endpoint"), Right(s"https://${d.host}/oauth2/token"))
      b <- get(app, "/.well-known/openid-configuration", "auth.example.test")
      _ = assertEquals(b._2.hcursor.get[String]("issuer"), Right("https://auth.example.test"))
      c <- get(app, "/.well-known/openid-configuration", "unknown.example.test")
      _ = assertEquals(c._2.hcursor.get[String]("issuer"), Right("https://auth.example.test"))
      // ログインの前の画面の設定にも、ドメインの上書きが効く
      cc <- get(app, "/api/client-config", d.host)
      _ = assertEquals(cc._2.hcursor.get[String]("title"), Right("取引先ポータル"))
      _ = assertEquals(cc._2.hcursor.get[String]("loginMessage"), Right("取引先の方はこちら"))
      global <- policies.global
      c0 <- get(app, "/api/client-config", "auth.example.test")
      _ = assertEquals(c0._2.hcursor.get[String]("title"), Right(global.branding.title))
      // ポリシー: そのドメインの要求の中では上書きした値、外では全体の値
      inDomain <- Site.within(Some(d))(policies.get)
      _ = assertEquals(inDomain.password.minLength, 6)
      _ = assertEquals(inDomain.domain, d.host)
      outside <- policies.get
      _ = assertEquals(outside.password.minLength, global.password.minLength)
      _ <- env.store.delete(d.id)
    } yield ()
  }

  withDb("ブラウザのセッションは作ったドメインでだけ使える. 管理機能を閉じたドメインでは管理 API を使えない") { env =>
    for {
      sv <- env.services
      (domains, _, app) = sv
      d <- env.domain(DomainPolicy(admin = false), domains)
      onDomain <- env.admin(d.host)
      onPrimary <- env.admin("")
      // 既定のホスト名でログインした管理者は、既定のホスト名で管理 API を使える
      ok <- get(app, "/api/admin/domains", "auth.example.test", Some(onPrimary._2))
      _ = assertEquals(ok._1, Status.Ok)
      _ = assert(ok._2.hcursor.downField("domains").as[List[DomainDto]].exists(_.exists(_.id == d.id)), ok._2.noSpaces)
      // その Cookie をドメインのホスト名に持ち込んでも、ログインしていない扱い
      moved <- get(app, "/api/admin/domains", d.host, Some(onPrimary._2))
      _ = assertEquals(code(moved._2), ErrorCode.NotLoggedIn.code)
      // ドメインでログインした Cookie も、既定のホスト名では使えない
      back <- get(app, "/api/admin/domains", "auth.example.test", Some(onDomain._2))
      _ = assertEquals(code(back._2), ErrorCode.NotLoggedIn.code)
      // 管理機能を閉じたドメインでは、管理者でも使えない
      closed <- get(app, "/api/admin/domains", d.host, Some(onDomain._2))
      _ = assertEquals(closed._1, Status.Forbidden)
      _ = assertEquals(code(closed._2), ErrorCode.AdminDisabledOnDomain.code)
      _ <- env.store.delete(d.id)
    } yield ()
  }

  withDb("ドメインの追加・変更・削除: ホスト名の確認、開いているドメインを締め出す設定の拒否、削除でログインが終わる") { env =>
    def send(app: HttpApp[IO],
             m: Method,
             path: String,
             host: String,
             ck: RequestCookie,
             body: Json): IO[(Status, Json)] =
      app.run(
        Request[IO](
          m,
          Uri.unsafeFromString(path)
        ).withEntity(body).putHeaders("Host" -> host, Cookie(ck), "X-Sruru" -> "1")
      ).flatMap(r => r.as[Json].attempt.map(j => r.status -> j.getOrElse(Json.Null)))
    for {
      sv <- env.services
      (domains, _, app) = sv
      primary <- env.admin("")
      host = s"n-${UUID.randomUUID().toString.take(8)}.example.test"
      // 既定のホスト名・形の正しくないホスト名・値の正しくない上書きは登録できない
      e1 <- send(
        app,
        Method.POST,
        "/api/admin/domains",
        "auth.example.test",
        primary._2,
        DomainReq("auth.example.test").asJson
      )
      _ = assertEquals(code(e1._2), ErrorCode.InvalidInput.code)
      e2 <- send(app, Method.POST, "/api/admin/domains", "auth.example.test", primary._2, DomainReq("https://x").asJson)
      _ = assertEquals(code(e2._2), ErrorCode.InvalidInput.code)
      e3 <- send(
        app,
        Method.POST,
        "/api/admin/domains",
        "auth.example.test",
        primary._2,
        DomainReq(host, policy = DomainPolicy(login = DomainLogin(providers = Some(List("no-such-idp"))))).asJson
      )
      _ = assertEquals(code(e3._2), ErrorCode.InvalidInput.code)
      created <- send(
        app,
        Method.POST,
        "/api/admin/domains",
        "auth.example.test",
        primary._2,
        DomainReq(host.toUpperCase, "取引先", DomainPolicy(session = SessionOverride(idleMinutes = Some(0)))).asJson
      )
      _ = assertEquals(created._1, Status.Created)
      d = created._2.as[DomainDto].toOption.get
      _ = assertEquals(d.host, host)
      _ = assertEquals(d.url, s"https://$host")
      dup <- send(app, Method.POST, "/api/admin/domains", "auth.example.test", primary._2, DomainReq(host).asJson)
      _ = assertEquals(code(dup._2), ErrorCode.DomainHostTaken.code)
      // そのドメインを開いている管理者は、自分を締め出す設定（管理機能を閉じる・自分の IP を許可しない）を保存できない
      onDomain <- env.admin(host)
      lock1 <- send(
        app,
        Method.PUT,
        s"/api/admin/domains/${d.id}",
        host,
        onDomain._2,
        DomainReq(host, policy = DomainPolicy(admin = false)).asJson
      )
      _ = assertEquals(code(lock1._2), ErrorCode.DomainAdminLockout.code)
      lock2 <- send(
        app,
        Method.PUT,
        s"/api/admin/domains/${d.id}",
        host,
        onDomain._2,
        DomainReq(host, policy = DomainPolicy(ip = Some(IpOverride(allow = List("203.0.113.0/24"))))).asJson
      )
      _ = assertEquals(code(lock2._2), ErrorCode.DomainAdminLockout.code)
      del0 <- send(app, Method.DELETE, s"/api/admin/domains/${d.id}", host, onDomain._2, Json.obj())
      _ = assertEquals(code(del0._2), ErrorCode.DomainAdminLockout.code)
      // 既定のホスト名からなら変えられる. ホスト名は変えられない
      upd <- send(
        app,
        Method.PUT,
        s"/api/admin/domains/${d.id}",
        "auth.example.test",
        primary._2,
        DomainReq(host, "変更後", DomainPolicy(admin = false)).asJson
      )
      _ = assertEquals(upd._1, Status.Ok)
      _ = assertEquals(upd._2.as[DomainDto].map(_.policy.admin), Right(false))
      ren <- send(
        app,
        Method.PUT,
        s"/api/admin/domains/${d.id}",
        "auth.example.test",
        primary._2,
        DomainReq("other.example.test").asJson
      )
      _ = assertEquals(code(ren._2), ErrorCode.InvalidInput.code)
      // 消すと、そのドメインのログインも終わる
      before <- env.sessions.loginsOfDomain(host)
      _ = assertEquals(before.map(_._2), List(onDomain._1.id))
      del <- send(app, Method.DELETE, s"/api/admin/domains/${d.id}", "auth.example.test", primary._2, Json.obj())
      _ = assertEquals(del._1, Status.NoContent)
      after <- env.sessions.loginsOfDomain(host)
      _ = assertEquals(after, Nil)
    } yield ()
  }

  withDb("認可コード・リフレッシュトークンは、発行したドメインでだけ使える") { env =>
    for {
      u <- env.users.create(NewUser("tok-" + UUID.randomUUID().toString.take(8), None, "トークン 次郎")).map(_.toOption.get)
      appId <- new AppStore(xaFixture()).all.map(_.headOption.map(_.id))
      now <- IO.realTimeInstant
      _ <- appId.traverse_ { id =>
        val h = Crypto.sha256(Crypto.randomToken())
        val c = AuthCode(
          id,
          u.id,
          None,
          "https://rp/cb",
          List("openid"),
          None,
          None,
          None,
          now,
          Nil,
          now.plusSeconds(60),
          None,
          "a.example.test"
        )
        for {
          _ <- env.tokens.createCode(h, c)
          // ほかのドメイン・既定のホスト名のトークンのエンドポイントには「ない」（使用済みにもならない）
          r0 <- env.tokens.useCode(h, id, now)
          _ = assertEquals(r0, None)
          r1 <- env.tokens.useCode(h, id, now, "b.example.test")
          _ = assertEquals(r1, None)
          r2 <- env.tokens.useCode(h, id, now, "a.example.test")
          _ = assert(r2.exists(_.isRight), r2.toString)
          rh = Crypto.sha256(Crypto.randomToken())
          _ <- env.tokens.createRefresh(
            rh,
            UUID.randomUUID(),
            id,
            u.id,
            None,
            List("openid"),
            now,
            Nil,
            now.plusSeconds(60),
            "a.example.test"
          )
          rt <- env.tokens.refresh(rh)
          _ = assertEquals(rt.map(_.domain), Some("a.example.test"))
          used <- env.tokens.appsWithTokens(u.id, None)
          _ = assertEquals(used, Set((id, "a.example.test")))
        } yield ()
      }
    } yield ()
  }
}
