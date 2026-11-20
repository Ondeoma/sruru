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
import org.http4s.headers.{Authorization, Cookie, Location}
import org.http4s.implicits.*
import sruru.db.*
import sruru.security.*

import java.util.UUID

/** OAUTH_CLIENTS の読み込み（DB は使わない）. */
class OAuthClientSpec extends munit.FunSuite {
  private def one(scopes: String, secret: String = "skakapo-secret-0123456789") =
    s"""[{"id":"skakapo","secret":"$secret","redirectUri":"http://localhost:5199/api/connections/callback","name":"skakapo","scopes":$scopes}]"""

  test("read だけを許したクライアントを読める（scopes を省くと read）") {
    assertEquals(OAuthClient.parse(one("""["read"]""")).map(_.map(_.scopes)), Right(List(List("read"))))
    assertEquals(
      OAuthClient.parse("""[{"id":"a","secret":"0123456789abcdef","redirectUri":"http://x/cb"}]""").map(_.map(c =>
        (c.name, c.scopes)
      )),
      Right(List(("a", List("read"))))
    )
  }

  test("write・admin を許そうとしたり、シークレットが短かったりすると起動しない") {
    assert(OAuthClient.parse(one("""["read","write"]""")).isLeft)
    assert(OAuthClient.parse(one("""["admin"]""")).isLeft)
    assert(OAuthClient.parse(one("""["read"]""", "short")).isLeft)
    assert(OAuthClient.parse("not json").isLeft)
  }
}

/**
 * OAuth（認可コード + PKCE）: ログインへのリダイレクト・クライアントの確認・スコープ（read だけ）・トークンで MCP / REST の読み取り・
 * 管理の操作の拒否・リフレッシュ・連携の取り消し. DB を使う（TEST_DATABASE_URL がなければ飛ばす. 例: jdbc:postgresql://localhost:54360/sruru_test）.
 */
class OAuthSpec extends CatsEffectSuite {

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

  private val Redirect = "http://localhost:5199/api/connections/callback"
  private val Secret = "skakapo-secret-0123456789"
  private val cfg = ApiConfig(
    publicUrl = "http://localhost:9100",
    cookieSecure = false,
    oauthClients = List(OAuthClient("skakapo", Secret, Redirect, "skakapo"))
  )

  /** Main と同じ組み立て（外部への HTTP は使わない）. */
  private final class Env(xa: doobie.Transactor[IO]) {
    private val http = Client.fromHttpApp[IO](HttpApp.notFound)
    private val box = new SecretBox("sruru-test-secret-0123456789")
    val users = new UserStore(xa)
    private val groups = new GroupStore(xa)
    val sessions = new SessionStore(xa)
    private val factors = new FactorStore(xa)
    private val apps = new AppStore(xa)
    private val tokens = new TokenStore(xa)
    private val auditSt = new AuditStore(xa)
    private val settings = new SettingsStore(xa)
    private val fedStore = new FederationStore(xa)

    def routes: IO[HttpApp[IO]] =
      for {
        policies <- PolicyService.create(settings)
        keys <- KeyService.create(tokens, box, "sruru")
      } yield {
        val audit = new AuditService(auditSt)
        val mail = new MailService(new MailStore(xa), None, cfg)
        val dir = new Directory(
          users,
          groups,
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
        val admin = new AdminRoutes(
          dir,
          factors,
          sessions,
          tokens,
          apps,
          fedStore,
          fed,
          auditSt,
          keys,
          me,
          login,
          new Claims(dir, apps),
          policies,
          audit,
          mail,
          box,
          settings,
          new SiteIcon(http),
          auth,
          cfg
        )
        val rest = me.routes <+> admin.routes <+> new OAuthRoutes(new OAuthStore(xa), dir, auth, audit, cfg).routes
        (rest <+> new McpRoutes(rest, auth, cfg).routes).orNotFound
      }

    /** ログインしたブラウザの Cookie（管理者にしておき、それでもトークンでは管理の操作ができないことを確かめる）. */
    def loggedIn: IO[(sruru.core.User, RequestCookie)] =
      for {
        u <- users.create(NewUser(
          "oauth-" + UUID.randomUUID().toString.take(8),
          None,
          "連携 太郎",
          isAdmin = true
        )).map(_.toOption.get)
        now <- IO.realTimeInstant
        t = Crypto.randomToken()
        bs <- sessions.createBrowser(Crypto.sha256(t), "127.0.0.1", None, now.plusSeconds(3600))
        _ <- sessions.upsertLogin(bs.id, u.id, List("pwd"), "127.0.0.1", None, now.plusSeconds(3600))
      } yield (u, RequestCookie(cfg.cookieName, t))
  }

  private def withDb(name: String)(body: Env => IO[Unit]): Unit =
    test(name)(if dbCfg.isEmpty then IO(assume(false, "TEST_DATABASE_URL が未設定")) else body(Env(xaFixture())))

  private val verifier = "verifier-0123456789-0123456789-0123456789-abcdef"
  private def authzQuery(clientId: String = "skakapo", redirect: String = Redirect, scope: String = "read") =
    Uri.unsafeFromString("/oauth/authorize").withQueryParams(Map(
      "client_id" -> clientId,
      "redirect_uri" -> redirect,
      "response_type" -> "code",
      "state" -> "st",
      "code_challenge" -> Crypto.pkceS256(verifier),
      "code_challenge_method" -> "S256",
      "scope" -> scope
    ))

  private def location(r: Response[IO]): Uri = r.headers.get[Location].get.uri
  private val basic = Authorization(BasicCredentials("skakapo", Secret))
  private def bearer(t: String) = Authorization(Credentials.Token(AuthScheme.Bearer, t))

  /** 許可の画面を開いて「許可する」を押し、認可コードを受け取る. */
  private def authorize(app: HttpApp[IO], ck: RequestCookie): IO[String] =
    for {
      page <- app.run(Request[IO](Method.GET, authzQuery()).putHeaders(Cookie(ck)))
      _ = assertEquals(page.status, Status.Ok)
      html <- page.bodyText.compile.string
      _ = assert(html.contains("read") && html.contains("skakapo"), html)
      csrf = page.cookies.find(_.name == "sruru_oauth_csrf").get.content
      form = UrlForm((authzQuery().query.params.toSeq ++ Seq("csrf" -> csrf, "decision" -> "allow"))*)
      res <- app.run(Request[IO](
        Method.POST,
        uri"/oauth/authorize"
      ).withEntity(form).putHeaders(Cookie(ck, RequestCookie("sruru_oauth_csrf", csrf))))
      _ = assertEquals(res.status, Status.Found)
      loc = location(res)
      _ = assertEquals(loc.renderString.takeWhile(_ != '?'), Redirect)
      _ = assertEquals(loc.params.get("state"), Some("st"))
    } yield loc.params("code")

  private def token(app: HttpApp[IO], form: (String, String)*): IO[(Status, Json)] =
    app.run(Request[IO](Method.POST, uri"/oauth/token").withEntity(UrlForm(form*)).putHeaders(basic)).flatMap(r =>
      r.as[Json].map(r.status -> _)
    )

  private def rpc(app: HttpApp[IO], at: String, method: String, params: Json = Json.obj()): IO[(Status, Json)] =
    app.run(Request[IO](Method.POST, uri"/mcp").withEntity(Json.obj(
      "jsonrpc" -> "2.0".asJson,
      "id" -> 1.asJson,
      "method" -> method.asJson,
      "params" -> params
    )).putHeaders(bearer(at))).flatMap(r =>
      (if r.status == Status.Ok then r.as[Json] else IO.pure(Json.Null)).map(r.status -> _)
    )

  private def toolError(j: Json): Boolean = j.hcursor.downField("result").get[Boolean]("isError").getOrElse(true)

  withDb("未ログインはログインへ 302、知らない client・違う redirect_uri は 400、write は invalid_scope") { env =>
    for {
      app <- env.routes
      r1 <- app.run(Request[IO](Method.GET, authzQuery()))
      _ = assertEquals(r1.status, Status.Found)
      _ = assertEquals(location(r1).path.renderString, "/login")
      _ = assert(location(r1).params.get("returnTo").exists(_.startsWith("/oauth/authorize?")), location(r1))
      r2 <- app.run(Request[IO](Method.GET, authzQuery(clientId = "unknown")))
      _ = assertEquals(r2.status, Status.BadRequest)
      r3 <- app.run(Request[IO](Method.GET, authzQuery(redirect = "http://evil.example/cb")))
      _ = assertEquals(r3.status, Status.BadRequest)
      r4 <- app.run(Request[IO](Method.GET, authzQuery(scope = "read write")))
      _ = assertEquals(r4.status, Status.Found)
      _ = assertEquals(location(r4).params.get("error"), Some("invalid_scope"))
      r5 <- app.run(Request[IO](Method.GET, authzQuery(scope = "admin")))
      _ = assertEquals(location(r5).params.get("error"), Some("invalid_scope"))
      // PKCE なしは invalid_request
      r6 <- app.run(Request[IO](Method.GET, authzQuery().removeQueryParam("code_challenge")))
      _ = assertEquals(location(r6).params.get("error"), Some("invalid_request"))
    } yield ()
  }

  withDb("許可 → コード → トークン → MCP の tools/list・読み取りが通り、管理の操作は拒まれる") { env =>
    for {
      app <- env.routes
      lc <- env.loggedIn
      (u, ck) = lc
      code <- authorize(app, ck)
      // クライアントの認証がなければ 401
      noAuth <- app.run(Request[IO](
        Method.POST,
        uri"/oauth/token"
      ).withEntity(UrlForm("grant_type" -> "authorization_code", "code" -> code)))
      _ = assertEquals(noAuth.status, Status.Unauthorized)
      // code_verifier が違えば invalid_grant（コードは使われる）
      bad <- token(
        app,
        "grant_type" -> "authorization_code",
        "code" -> code,
        "redirect_uri" -> Redirect,
        "code_verifier" -> (verifier + "x")
      )
      _ = assertEquals(bad._2.hcursor.get[String]("error").toOption, Some("invalid_grant"))
      code2 <- authorize(app, ck)
      ok <- token(
        app,
        "grant_type" -> "authorization_code",
        "code" -> code2,
        "redirect_uri" -> Redirect,
        "code_verifier" -> verifier
      )
      _ = assertEquals(ok._1, Status.Ok, ok._2.noSpaces)
      at = ok._2.hcursor.get[String]("access_token").toOption.get
      rt = ok._2.hcursor.get[String]("refresh_token").toOption.get
      _ = assertEquals(ok._2.hcursor.get[String]("scope").toOption, Some("read"))
      // 同じコードは2回使えない
      again <- token(
        app,
        "grant_type" -> "authorization_code",
        "code" -> code2,
        "redirect_uri" -> Redirect,
        "code_verifier" -> verifier
      )
      _ = assertEquals(again._2.hcursor.get[String]("error").toOption, Some("invalid_grant"))

      list <- rpc(app, at, "tools/list")
      _ = assertEquals(list._1, Status.Ok)
      _ = assert(list._2.hcursor.downField("result").downField("tools").values.exists(_.nonEmpty), list._2.noSpaces)
      me <- rpc(app, at, "tools/call", Json.obj("name" -> "get_me".asJson))
      _ = assert(!toolError(me._2), me._2.noSpaces)
      _ = assert(me._2.noSpaces.contains(u.username))
      // 管理者でも、トークン（read）では管理の API は使えない
      groups <- rpc(app, at, "tools/call", Json.obj("name" -> "list_groups".asJson))
      _ = assert(toolError(groups._2), groups._2.noSpaces)
      create <- rpc(
        app,
        at,
        "tools/call",
        Json.obj(
          "name" -> "create_user".asJson,
          "arguments" -> Json.obj("username" -> "x".asJson, "name" -> "x".asJson)
        )
      )
      _ = assert(toolError(create._2), create._2.noSpaces)
      rMe <- app.run(Request[IO](Method.GET, uri"/api/me").putHeaders(bearer(at)))
      _ = assertEquals(rMe.status, Status.Ok)
      rAdm <- app.run(Request[IO](Method.GET, uri"/api/admin/users").putHeaders(bearer(at)))
      _ = assertEquals(rAdm.status, Status.Forbidden)
      rPost <- app.run(Request[IO](Method.POST, uri"/api/admin/groups").withEntity(Json.obj("name" ->
        "x".asJson)).putHeaders(bearer(at)))
      _ = assertEquals(rPost.status, Status.Forbidden)
      rTok <- app.run(Request[IO](
        Method.POST,
        uri"/api/me/tokens"
      ).withEntity(Json.obj("name" -> "x".asJson, "scopes" -> List("admin").asJson))
        .putHeaders(bearer(at)))
      _ = assertEquals(rTok.status, Status.Forbidden)

      // リフレッシュ: 新しいトークンが使え、前のアクセストークンは使えない. write へ広げることはできない
      wide <- token(app, "grant_type" -> "refresh_token", "refresh_token" -> rt, "scope" -> "read write")
      _ = assertEquals(wide._2.hcursor.get[String]("error").toOption, Some("invalid_scope"))
      ref <- token(app, "grant_type" -> "refresh_token", "refresh_token" -> rt)
      _ = assertEquals(ref._1, Status.Ok, ref._2.noSpaces)
      at2 = ref._2.hcursor.get[String]("access_token").toOption.get
      old <- rpc(app, at, "tools/list")
      _ = assertEquals(old._1, Status.Unauthorized)
      cur <- rpc(app, at2, "tools/list")
      _ = assertEquals(cur._1, Status.Ok)
      // 使用済みのリフレッシュトークンが使われたら、連携ごと取り消す
      reuse <- token(app, "grant_type" -> "refresh_token", "refresh_token" -> rt)
      _ = assertEquals(reuse._2.hcursor.get[String]("error").toOption, Some("invalid_grant"))
      gone <- rpc(app, at2, "tools/list")
      _ = assertEquals(gone._1, Status.Unauthorized)
    } yield ()
  }

  withDb("個人設定で連携を確かめ、取り消せる（API トークンの一覧では連携のトークンとわかる）") { env =>
    for {
      app <- env.routes
      lc <- env.loggedIn
      (_, ck) = lc
      code <- authorize(app, ck)
      ok <- token(
        app,
        "grant_type" -> "authorization_code",
        "code" -> code,
        "redirect_uri" -> Redirect,
        "code_verifier" -> verifier
      )
      at = ok._2.hcursor.get[String]("access_token").toOption.get
      rt = ok._2.hcursor.get[String]("refresh_token").toOption.get
      gs <- app.run(Request[IO](Method.GET, uri"/api/me/oauth").putHeaders(Cookie(ck))).flatMap(_.as[Json])
      _ = assertEquals(gs.asArray.map(_.flatMap(_.hcursor.get[String]("clientId").toOption)), Some(Vector("skakapo")))
      ts <- app.run(Request[IO](Method.GET, uri"/api/me/tokens").putHeaders(Cookie(ck))).flatMap(_.as[Json])
      _ =
        assertEquals(ts.asArray.map(_.flatMap(_.hcursor.get[String]("oauthClient").toOption)), Some(Vector("skakapo")))
      del <- app.run(Request[IO](
        Method.DELETE,
        uri"/api/me/oauth/skakapo"
      ).putHeaders(Cookie(ck), Header.Raw(org.typelevel.ci.CIString("X-Sruru"), "1")))
      _ = assertEquals(del.status, Status.NoContent)
      after <- rpc(app, at, "tools/list")
      _ = assertEquals(after._1, Status.Unauthorized)
      ref <- token(app, "grant_type" -> "refresh_token", "refresh_token" -> rt)
      _ = assertEquals(ref._2.hcursor.get[String]("error").toOption, Some("invalid_grant"))
    } yield ()
  }
}
