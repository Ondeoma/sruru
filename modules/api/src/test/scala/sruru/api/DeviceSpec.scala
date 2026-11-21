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
import org.http4s.headers.{Cookie, Location}
import sruru.core.*
import sruru.db.*
import sruru.security.*
import sruru.shared.*

import java.util.UUID

/**
 * デバイスフロー（RFC 8628）: 開始 → ポーリング（authorization_pending・slow_down）→ 利用者の確認（user_code・許可／拒否）→ トークン.
 * 期限切れ・device_code の再利用・グラントを持たないクライアント・誤った user_code の回数の制限・利用の制限・マルチドメイン.
 * あわせて、ネイティブアプリのリダイレクト URI（ループバックの任意のポート・カスタムスキーム. RFC 8252）を認可のエンドポイントで確かめる.
 * DB を使う（TEST_DATABASE_URL がなければ飛ばす）.
 */
class DeviceSpec extends CatsEffectSuite {

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

  private val Primary = "auth.example.test"
  private val cfg = ApiConfig(publicUrl = s"https://$Primary", cookieSecure = true)
  private val Device = OAuthGrants.DeviceCode

  /** Main と同じ組み立て（外部への HTTP は使わない）. app は、要求ごとにドメインを決めるミドルウェアを通したもの. */
  private final class Env(val xa: doobie.Transactor[IO]) {
    private val http = Client.fromHttpApp[IO](HttpApp.notFound)
    private val box = new SecretBox("sruru-test-secret-0123456789")
    val users = new UserStore(xa)
    val sessions = new SessionStore(xa)
    val tokens = new TokenStore(xa)
    val devices = new DeviceStore(xa)
    val domainStore = new DomainStore(xa)
    val apps = new AppStore(xa)
    private val factors = new FactorStore(xa)
    private val settings = new SettingsStore(xa)
    private val fedStore = new FederationStore(xa)

    def services: IO[(Domains, HttpApp[IO])] =
      for {
        policies <- PolicyService.create(settings)
        domains <- Domains.create(domainStore, policies, cfg)
        keys <- KeyService.create(tokens, box, "sruru")
        _ <- keys.ensure
        // ほかのテスト・前回の実行の分を持ち越さない（テストの要求はどれも同じ IP「-」になる）
        _ <- sql"delete from login_throttle where key like 'device:%'".update.run.transact(xa)
        _ <- sql"delete from device_codes".update.run.transact(xa)
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
          new OidcRoutes(
            apps,
            tokens,
            devices,
            sessions,
            dir,
            keys,
            new Claims(dir, apps),
            gate,
            auth,
            audit,
            http,
            cfg
          )
        val device = new DeviceRoutes(apps, devices, tokens, factors, gate, auth, audit, cfg)
        val loginR = new LoginRoutes(
          login,
          new MagicLinkService(dir, login, sessions, factors, tokens, apps, audit, mail, cfg),
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
        val resume =
          new ResumeRoutes(tokens, Map("oidc" -> oidc.resume, DeviceRoutes.Protocol -> device.resume), gate)
        (domains, domains.middleware((loginR.routes <+> oidc.routes <+> device.routes <+> resume.routes).orNotFound))
      }

    /** OIDC の公開クライアント（テストごとに別の client_id）. */
    def client(grants: List[String],
               restrictAccess: Boolean = false,
               requireMfa: Boolean = false,
               redirectUris: List[String] = Nil,
               secret: Option[String] = None): IO[(Application, OidcClientConfig)] = {
      val now = java.time.Instant.now()
      val id = UUID.randomUUID()
      val slug = "dev-" + id.toString.take(8)
      val a =
        Application(id, slug, "テスト CLI", "", "oidc", true, None, false, None, requireMfa, Nil, restrictAccess, now, now)
      val c = OidcClientConfig(
        id,
        slug,
        secret.map(Crypto.sha256),
        redirectUris,
        Nil,
        grants,
        List("openid", "profile", "offline_access"),
        "implicit",
        "id",
        "RS256",
        300,
        300,
        3600,
        false,
        None
      )
      apps.create(a, Some(c), None).map(r => (r.toOption.get, c))
    }

    /** 利用者と、そのドメイン（空なら既定のホスト名）でログイン済みのブラウザの Cookie. */
    def user(domain: String = ""): IO[(User, RequestCookie)] =
      for {
        u <- users.create(NewUser("dev-" + UUID.randomUUID().toString.take(8), None, "端末 太郎")).map(_.toOption.get)
        now <- IO.realTimeInstant
        t = Crypto.randomToken()
        bs <- sessions.createBrowser(Crypto.sha256(t), "127.0.0.1", None, now.plusSeconds(3600), domain)
        _ <- sessions.upsertLogin(bs.id, u.id, List("pwd"), "127.0.0.1", None, now.plusSeconds(3600))
      } yield (u, RequestCookie(cfg.cookieName, t))

    /** 前のポーリングから十分に時間がたったことにする. */
    def rewind: IO[Unit] =
      sql"update device_codes set last_poll_at = last_poll_at - interval '1 hour'".update.run.transact(xa).void
  }

  private def withDb(name: String)(body: Env => IO[Unit]): Unit =
    test(name)(if dbCfg.isEmpty then IO(assume(false, "TEST_DATABASE_URL が未設定")) else body(Env(xaFixture())))

  private def json(r: Response[IO]): IO[(Status, Json)] =
    r.as[Json].attempt.map(j => r.status -> j.getOrElse(Json.Null))

  /** 端末からの要求（フォーム）. */
  private def form(app: HttpApp[IO], path: String, fields: (String, String)*)(using host: String): IO[(Status, Json)] =
    app.run(
      Request[IO](Method.POST, Uri.unsafeFromString(path)).withEntity(UrlForm(fields*)).putHeaders("Host" -> host)
    ).flatMap(json)

  private def start(app: HttpApp[IO], c: OidcClientConfig, scope: String = "openid profile")(using
    String): IO[(Status, Json)] =
    form(app, "/oauth2/device_authorization", "client_id" -> c.clientId, "scope" -> scope)

  private def poll(app: HttpApp[IO], c: OidcClientConfig, deviceCode: String)(using String): IO[(Status, Json)] =
    form(app, "/oauth2/token", "grant_type" -> Device, "client_id" -> c.clientId, "device_code" -> deviceCode)

  /** 画面からの要求（Cookie と X-Sruru ヘッダー付き）. */
  private def screen(app: HttpApp[IO], path: String, ck: Option[RequestCookie], body: Json, csrf: Boolean = true)(using
    host: String): IO[(Status, Json)] = {
    val req = Request[IO](Method.POST, Uri.unsafeFromString(path)).withEntity(body).putHeaders("Host" -> host)
    val r2 = ck.fold(req)(c => req.putHeaders(Cookie(c)))
    app.run(if csrf then r2.putHeaders("X-Sruru" -> "1") else r2).flatMap(json)
  }

  private def verify(app: HttpApp[IO], ck: RequestCookie, userCode: String)(using String): IO[(Status, Json)] =
    screen(app, "/api/device/verify", Some(ck), DeviceVerifyReq(userCode).asJson)

  /** ブラウザでのリダイレクト先（Location）. */
  private def follow(app: HttpApp[IO], path: String, ck: RequestCookie)(using host: String): IO[String] =
    app.run(Request[IO](Method.GET, Uri.unsafeFromString(path)).putHeaders("Host" -> host, Cookie(ck))).map(r =>
      r.headers.get[Location].map(_.uri.renderString).getOrElse(s"(${r.status.code})")
    )

  private def str(j: Json, k: String): String = j.hcursor.get[String](k).getOrElse("")
  private def code(j: Json): String = str(j, "code")
  private def error(j: Json): String = str(j, "error")

  /** user_code を入力して、許可／拒否の画面（/device?req=…）まで進む. 認可の要求の ID を返す. */
  private def toConfirm(app: HttpApp[IO], ck: RequestCookie, userCode: String)(using String): IO[UUID] =
    for {
      v <- verify(app, ck, userCode)
      _ = assertEquals(v._1, Status.Ok, v._2.noSpaces)
      to = str(v._2, "redirect")
      _ = assert(to.startsWith("/auth/resume?req="), to)
      next <- follow(app, to, ck)
      _ = assert(next.startsWith("/device?req="), next)
    } yield UUID.fromString(next.stripPrefix("/device?req="))

  private def decide(app: HttpApp[IO], ck: RequestCookie, req: UUID, approve: Boolean)(using
    String): IO[(Status, Json)] =
    screen(app, "/api/device/decide", Some(ck), ConsentReq(req, approve).asJson)

  withDb("開始 → authorization_pending → slow_down → 許可 → トークン. device_code は1回だけ（再利用でトークンを失効させる）") { env =>
    given String = Primary
    for {
      sv <- env.services
      (_, app) = sv
      ac <- env.client(List(Device, "refresh_token"))
      (a, c) = ac
      u <- env.user()
      // discovery に載る
      d <- app.run(Request[IO](Method.GET, Uri.unsafeFromString("/.well-known/openid-configuration")).putHeaders(
        "Host" -> Primary
      )).flatMap(json)
      _ = assertEquals(str(d._2, "device_authorization_endpoint"), s"https://$Primary/oauth2/device_authorization")
      _ = assert(d._2.hcursor.get[List[String]]("grant_types_supported").exists(_.contains(Device)), d._2.noSpaces)
      // 開始
      s <- start(app, c, "openid profile unknown_scope")
      _ = assertEquals(s._1, Status.Ok, s._2.noSpaces)
      deviceCode = str(s._2, "device_code")
      userCode = str(s._2, "user_code")
      _ = assert(deviceCode.length >= 43, deviceCode)
      _ = assert(userCode.matches("[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}"), userCode)
      _ = assertEquals(str(s._2, "verification_uri"), s"https://$Primary/device")
      _ = assertEquals(str(s._2, "verification_uri_complete"), s"https://$Primary/device?user_code=$userCode")
      _ = assertEquals(s._2.hcursor.get[Int]("expires_in"), Right(600))
      _ = assertEquals(s._2.hcursor.get[Int]("interval"), Right(5))
      // DB には device_code そのものを残さない（ハッシュだけ）
      row <- env.devices.byUserCode(userCode.replace("-", ""), "", java.time.Instant.now()).map(_.get)
      _ = assertEquals(row.scopes, List("openid", "profile"))
      // 許可を待っている間
      p1 <- poll(app, c, deviceCode)
      _ = assertEquals((p1._1, error(p1._2)), (Status.BadRequest, "authorization_pending"))
      // 間隔（5秒）より早いポーリングは slow_down. 以後の間隔が 5 秒延びる
      p2 <- poll(app, c, deviceCode)
      _ = assertEquals((p2._1, error(p2._2)), (Status.BadRequest, "slow_down"))
      i2 <- env.devices.find(row.id).map(_.get.intervalSeconds)
      _ = assertEquals(i2, 10)
      _ <- env.rewind
      p3 <- poll(app, c, deviceCode)
      _ = assertEquals(error(p3._2), "authorization_pending")
      // 利用者: コードを入力（小文字・ハイフンなしでもよい）→ 確認の画面 → 許可
      req <- toConfirm(app, u._2, userCode.toLowerCase.replace("-", " "))
      // 確認の画面に出す内容（アプリ・スコープ・入力したコード）
      shown <- app.run(Request[IO](Method.GET, Uri.unsafeFromString(s"/api/auth-requests/$req")).putHeaders(
        "Host" -> Primary
      )).flatMap(json)
      dto = shown._2.as[AuthRequestDto].toOption.get
      _ = assertEquals(
        (dto.app.name, dto.scopes.map(_.name), dto.userCode),
        (a.name, List("openid", "profile"), Some(userCode))
      )
      // 画面を開いただけでは許可にならない
      _ <- env.rewind
      p4 <- poll(app, c, deviceCode)
      _ = assertEquals(error(p4._2), "authorization_pending")
      // CSRF 対策のヘッダーがなければ許可できない
      noCsrf <- screen(app, "/api/device/decide", Some(u._2), ConsentReq(req, true).asJson, csrf = false)
      _ = assertEquals(code(noCsrf._2), ErrorCode.CsrfHeaderMissing.code)
      // ほかの利用者のブラウザでは、その要求を許可できない
      other <- env.user()
      stolen <- decide(app, other._2, req, true)
      _ = assertEquals(code(stolen._2), ErrorCode.DeviceRequestExpired.code)
      ok <- decide(app, u._2, req, true)
      _ = assertEquals((ok._1, str(ok._2, "redirect")), (Status.Ok, "/device?done=approved"))
      // 許可の後は、同じ user_code をもう使えない
      again <- verify(app, u._2, userCode)
      _ = assertEquals(code(again._2), ErrorCode.DeviceCodeInvalid.code)
      // 許可の直後でも、間隔より早ければ slow_down
      early <- poll(app, c, deviceCode)
      _ = assertEquals(error(early._2), "slow_down")
      // ほかのクライアントが device_code を出しても「ない」ものとして扱う（使用済みにもならない）
      oc <- env.client(List(Device))
      _ <- env.rewind
      foreign <- poll(app, oc._2, deviceCode)
      _ = assertEquals(error(foreign._2), "invalid_grant")
      _ <- env.rewind
      t <- poll(app, c, deviceCode)
      _ = assertEquals(t._1, Status.Ok, t._2.noSpaces)
      _ = assertEquals(str(t._2, "token_type"), "Bearer")
      _ = assertEquals(str(t._2, "scope"), "openid profile")
      _ = assert(str(t._2, "access_token").nonEmpty && str(t._2, "id_token").nonEmpty, t._2.noSpaces)
      refresh = str(t._2, "refresh_token")
      _ = assert(refresh.nonEmpty)
      // ID トークンの sub は許可した利用者
      sub = Jose.header(str(t._2, "id_token")).toOption.fold("")(_ =>
        io.circe.parser.parse(new String(
          java.util.Base64.getUrlDecoder.decode(str(t._2, "id_token").split('.')(1)),
          "UTF-8"
        )).toOption.fold("")(str(_, "sub"))
      )
      _ = assertEquals(sub, u._1.id.toString)
      // device_code の再利用: 拒否し、その device_code で出したリフレッシュトークンも失効させる
      _ <- env.rewind
      reuse <- poll(app, c, deviceCode)
      _ = assertEquals((reuse._1, error(reuse._2)), (Status.BadRequest, "invalid_grant"))
      rt <- form(
        app,
        "/oauth2/token",
        "grant_type" -> "refresh_token",
        "client_id" -> c.clientId,
        "refresh_token" -> refresh
      )
      _ = assertEquals(error(rt._2), "invalid_grant")
      // 監査ログ: 開始・許可
      logged <- sql"select action from audit_log where target_id = ${a.id.toString} order by at".query[String].to[List]
        .transact(env.xa)
      _ = assertEquals(logged, List("device.start", "device.approve"))
      _ <- env.apps.delete(a.id) *> env.apps.delete(oc._1.id)
    } yield ()
  }

  withDb("URL エンコードされていない本文は、500 ではなく invalid_request（400）にする") { env =>
    env.services.flatMap { (_, app) =>
      val raw = Request[IO](Method.POST, Uri.unsafeFromString("/oauth2/token"))
        .withEntity("grant_type=x&scope=openid profile")
        .withContentType(headers.`Content-Type`(MediaType.application.`x-www-form-urlencoded`))
        .putHeaders("Host" -> Primary)
      app.run(raw).attempt.map {
        case Left(e: OAuthFailure) =>
          assertEquals(e.error.error, "invalid_request")
          assertEquals(OAuthEndpoint.response(e.error).status, Status.BadRequest)
        case other => fail(s"OAuthFailure になるはず: $other")
      }
    }
  }

  withDb("拒否すると access_denied. 期限が切れると expired_token（user_code も使えない）") { env =>
    given String = Primary
    for {
      sv <- env.services
      (_, app) = sv
      ac <- env.client(List(Device))
      (a, c) = ac
      u <- env.user()
      // 拒否
      s1 <- start(app, c)
      req <- toConfirm(app, u._2, str(s1._2, "user_code"))
      no <- decide(app, u._2, req, false)
      _ = assertEquals((no._1, str(no._2, "redirect")), (Status.Ok, "/device?done=denied"))
      p <- poll(app, c, str(s1._2, "device_code"))
      _ = assertEquals((p._1, error(p._2)), (Status.BadRequest, "access_denied"))
      // 拒否の後に許可はできない（要求は消えている）
      late <- decide(app, u._2, req, true)
      _ = assertEquals(code(late._2), ErrorCode.DeviceRequestExpired.code)
      logged <- sql"select action from audit_log where target_id = ${a.id.toString} order by at".query[String].to[List]
        .transact(env.xa)
      _ = assertEquals(logged, List("device.start", "device.deny"))
      // 期限切れ: 確認の画面まで進んだ後に切れた場合も、許可できない
      s2 <- start(app, c)
      req2 <- toConfirm(app, u._2, str(s2._2, "user_code"))
      _ <-
        sql"update device_codes set expires_at = now() - interval '1 second' where user_code = ${str(s2._2, "user_code").replace("-", "")}"
          .update.run.transact(env.xa)
      ex <- poll(app, c, str(s2._2, "device_code"))
      _ = assertEquals((ex._1, error(ex._2)), (Status.BadRequest, "expired_token"))
      v <- verify(app, u._2, str(s2._2, "user_code"))
      _ = assertEquals(code(v._2), ErrorCode.DeviceCodeInvalid.code)
      d2 <- decide(app, u._2, req2, true)
      _ = assertEquals(code(d2._2), ErrorCode.DeviceRequestExpired.code)
      // 掃除: 期限切れで未使用の行は消える
      n <- env.devices.purge(java.time.Instant.now())
      _ = assert(n >= 1, n.toString)
      _ <- env.apps.delete(a.id)
    } yield ()
  }

  withDb("デバイスコードのグラントを選んでいないクライアント・知らないクライアント・使えないスコープは断る") { env =>
    given String = Primary
    for {
      sv <- env.services
      (_, app) = sv
      ac <- env.client(List("authorization_code", "refresh_token"))
      (a, c) = ac
      s <- start(app, c)
      _ = assertEquals((s._1, error(s._2)), (Status.BadRequest, "unauthorized_client"))
      t <- poll(app, c, "no-such-device-code")
      _ = assertEquals((t._1, error(t._2)), (Status.BadRequest, "unauthorized_client"))
      unknown <- form(app, "/oauth2/device_authorization", "client_id" -> "no-such-client")
      _ = assertEquals((unknown._1, error(unknown._2)), (Status.Unauthorized, "invalid_client"))
      dc <- env.client(List(Device))
      bad <- start(app, dc._2, "admin")
      _ = assertEquals((bad._1, error(bad._2)), (Status.BadRequest, "invalid_scope"))
      none <- poll(app, dc._2, "no-such-device-code")
      _ = assertEquals((none._1, error(none._2)), (Status.BadRequest, "invalid_grant"))
      missing <- form(app, "/oauth2/token", "grant_type" -> Device, "client_id" -> dc._2.clientId)
      _ = assertEquals((missing._1, error(missing._2)), (Status.BadRequest, "invalid_request"))
      _ <- env.apps.delete(a.id) *> env.apps.delete(dc._1.id)
    } yield ()
  }

  withDb("user_code の入力にはログインが要る. 誤った入力は利用者ごとに数え、上限を超えると正しいコードも受け付けない") { env =>
    given String = Primary
    for {
      sv <- env.services
      (_, app) = sv
      ac <- env.client(List(Device))
      (a, c) = ac
      u <- env.user()
      s <- start(app, c)
      userCode = str(s._2, "user_code")
      // ログインしていない・CSRF 対策のヘッダーがない
      anon <- screen(app, "/api/device/verify", None, DeviceVerifyReq(userCode).asJson)
      _ = assertEquals((anon._1, code(anon._2)), (Status.Unauthorized, ErrorCode.NotLoggedIn.code))
      noCsrf <- screen(app, "/api/device/verify", Some(u._2), DeviceVerifyReq(userCode).asJson, csrf = false)
      _ = assertEquals(code(noCsrf._2), ErrorCode.CsrfHeaderMissing.code)
      // 誤ったコード（形が違うものも数える）を上限まで
      wrong <- (1 to DeviceFlow.MaxUserFailures).toList.traverse(i =>
        verify(app, u._2, if i % 2 == 0 then "BBBB-BBBB" else "not a code")
      )
      _ = assert(wrong.forall(r => code(r._2) == ErrorCode.DeviceCodeInvalid.code), wrong.map(_._2.noSpaces).toString)
      // 上限に達したら、正しいコードでも断る
      blocked <- verify(app, u._2, userCode)
      _ = assertEquals((blocked._1, code(blocked._2)), (Status.TooManyRequests, ErrorCode.DeviceTooManyAttempts.code))
      // ほかの利用者は（同じ IP の上限に達するまでは）使える
      other <- env.user()
      _ <- toConfirm(app, other._2, userCode)
      // 同じ IP からの誤りが続けば、ほかの利用者も止まる
      more <- (1 to (DeviceFlow.MaxIpFailures - DeviceFlow.MaxUserFailures)).toList.traverse { _ =>
        env.user().flatMap(x => verify(app, x._2, "CCCC-CCCC"))
      }
      _ = assert(more.forall(r => code(r._2) == ErrorCode.DeviceCodeInvalid.code), more.map(_._2.noSpaces).toString)
      fresh <- env.user()
      ipBlocked <- verify(app, fresh._2, userCode)
      _ = assertEquals(code(ipBlocked._2), ErrorCode.DeviceTooManyAttempts.code)
      // 監査ログに失敗が残る
      failures <-
        sql"select count(*) from audit_log where action = 'device.verify' and not success and actor_id = ${u._1.id}".query[
          Int
        ].unique.transact(env.xa)
      _ = assertEquals(failures, DeviceFlow.MaxUserFailures + 1)
      _ <- sql"delete from login_throttle where key like 'device:%'".update.run.transact(env.xa)
      _ <- env.apps.delete(a.id)
    } yield ()
  }

  withDb("アプリケーションの利用の制限（グループ・多要素認証）は、通常の認可と同じように見る") { env =>
    given String = Primary
    for {
      sv <- env.services
      (_, app) = sv
      u <- env.user()
      // 利用できるグループに入っていない利用者は、確認の画面に進めない
      rc <- env.client(List(Device), restrictAccess = true)
      s1 <- start(app, rc._2)
      v1 <- verify(app, u._2, str(s1._2, "user_code"))
      to1 <- follow(app, str(v1._2, "redirect"), u._2)
      _ = assert(to1.startsWith("/error?message="), to1)
      p1 <- poll(app, rc._2, str(s1._2, "device_code"))
      _ = assertEquals(error(p1._2), "authorization_pending")
      // 多要素認証が必須のアプリは、2つ目の要素の確認（step-up）へ. 確認が済むまで許可できない
      mc <- env.client(List(Device), requireMfa = true)
      s2 <- start(app, mc._2)
      v2 <- verify(app, u._2, str(s2._2, "user_code"))
      resume = str(v2._2, "redirect")
      to2 <- follow(app, resume, u._2)
      req = resume.stripPrefix("/auth/resume?req=")
      _ = assertEquals(to2, s"/login?req=$req&stepup=1")
      d2 <- decide(app, u._2, UUID.fromString(req), true)
      _ = assertEquals((d2._1, str(d2._2, "redirect")), (Status.Ok, s"/login?req=$req&stepup=1"))
      _ <- env.rewind
      p2 <- poll(app, mc._2, str(s2._2, "device_code"))
      _ = assertEquals(error(p2._2), "authorization_pending")
      // 無効にしたアプリケーションは開始できない
      _ <- env.apps.save(mc._1.copy(enabled = false))
      s3 <- start(app, mc._2)
      _ = assertEquals((s3._1, error(s3._2)), (Status.Unauthorized, "invalid_client"))
      _ <- env.apps.delete(rc._1.id) *> env.apps.delete(mc._1.id)
    } yield ()
  }

  withDb("未完了の要求の件数に上限がある（クライアントごと・全体）. 許可・拒否・期限切れの分は数えない") { env =>
    for {
      _ <- env.services
      ac <- env.client(List(Device))
      bc <- env.client(List(Device))
      now <- IO.realTimeInstant
      rnd = new java.security.SecureRandom()
      make = (appId: UUID, perApp: Int, total: Int) =>
        env.devices.create(
          Crypto.sha256(Crypto.randomToken()),
          UserCodes.generate(rnd),
          appId,
          Nil,
          "",
          5,
          now.plusSeconds(600),
          now,
          perApp,
          total
        )
      a1 <- make(ac._1.id, 2, 3)
      a2 <- make(ac._1.id, 2, 3)
      _ = assert(a1.isRight && a2.isRight)
      a3 <- make(ac._1.id, 2, 3)
      _ = assertEquals(a3, Left(DeviceCreateError.TooMany))
      // ほかのクライアントは、全体の上限まで
      b1 <- make(bc._1.id, 2, 3)
      _ = assert(b1.isRight)
      b2 <- make(bc._1.id, 2, 3)
      _ = assertEquals(b2, Left(DeviceCreateError.TooMany))
      // 同じ user_code は作れない（呼び出し側が作り直す）
      dup <- env.devices.create(
        Crypto.sha256(Crypto.randomToken()),
        a1.toOption.get.userCode,
        bc._1.id,
        Nil,
        "",
        5,
        now.plusSeconds(600),
        now,
        9,
        9
      )
      _ = assertEquals(dup, Left(DeviceCreateError.Collision))
      // 決着した分は数えない
      u <- env.user()
      _ <- env.devices.decide(a1.toOption.get.id, false, u._1.id, UUID.randomUUID(), now, Nil, now)
      a4 <- make(ac._1.id, 2, 3)
      _ = assert(a4.isRight, a4.toString)
      _ <- env.apps.delete(ac._1.id) *> env.apps.delete(bc._1.id)
    } yield ()
  }

  withDb("マルチドメイン: 確認の URL は要求を受けたホスト名のもの. 確認もトークンも同じホスト名でだけ") { env =>
    for {
      sv <- env.services
      (domains, app) = sv
      d <- env.domainStore.create(s"d-${UUID.randomUUID().toString.take(8)}.example.test", "テスト", DomainPolicy())
        .map(_.get) <* domains.invalidate
      ac <- env.client(List(Device))
      (a, c) = ac
      s <- start(app, c)(using d.host)
      userCode = str(s._2, "user_code")
      deviceCode = str(s._2, "device_code")
      _ = assertEquals(str(s._2, "verification_uri"), s"https://${d.host}/device")
      _ = assertEquals(str(s._2, "verification_uri_complete"), s"https://${d.host}/device?user_code=$userCode")
      // 既定のホスト名では、そのコードは「ない」
      onPrimary <- env.user()
      v0 <- verify(app, onPrimary._2, userCode)(using Primary)
      _ = assertEquals(code(v0._2), ErrorCode.DeviceCodeInvalid.code)
      p0 <- poll(app, c, deviceCode)(using Primary)
      _ = assertEquals(error(p0._2), "invalid_grant")
      // そのドメインでログインした利用者が許可する
      onDomain <- env.user(d.host)
      req <- toConfirm(app, onDomain._2, userCode)(using d.host)
      ok <- decide(app, onDomain._2, req, true)(using d.host)
      _ = assertEquals(ok._1, Status.Ok, ok._2.noSpaces)
      p1 <- poll(app, c, deviceCode)(using Primary)
      _ = assertEquals(error(p1._2), "invalid_grant")
      t <- poll(app, c, deviceCode)(using d.host)
      _ = assertEquals(t._1, Status.Ok, t._2.noSpaces)
      iss = io.circe.parser.parse(new String(
        java.util.Base64.getUrlDecoder.decode(str(t._2, "access_token").split('.')(1)),
        "UTF-8"
      )).toOption.fold("")(str(_, "iss"))
      _ = assertEquals(iss, s"https://${d.host}")
      _ <- env.apps.delete(a.id) *> env.domainStore.delete(d.id)
    } yield ()
  }

  withDb("ループバックのリダイレクト URI: 公開クライアントはポートだけ違ってよい. トークンの交換は、認可で使った値との完全一致") { env =>
    given String = Primary
    val verifier = Crypto.randomToken()
    def authorize(app: HttpApp[IO], c: OidcClientConfig, ck: RequestCookie, redirectUri: String): IO[String] =
      follow(
        app,
        Uri.unsafeFromString("/oauth2/authorize").withQueryParams(Map(
          "client_id" -> c.clientId,
          "response_type" -> "code",
          "scope" -> "openid",
          "state" -> "st",
          "redirect_uri" -> redirectUri,
          "code_challenge" -> Crypto.pkceS256(verifier),
          "code_challenge_method" -> "S256"
        )).renderString,
        ck
      )
    def exchange(app: HttpApp[IO], c: OidcClientConfig, location: String, redirectUri: String) =
      form(
        app,
        "/oauth2/token",
        "grant_type" -> "authorization_code",
        "client_id" -> c.clientId,
        "code" -> Uri.unsafeFromString(location).params("code"),
        "redirect_uri" -> redirectUri,
        "code_verifier" -> verifier
      )
    for {
      sv <- env.services
      (_, app) = sv
      registered = List(
        "http://127.0.0.1/callback",
        "http://[::1]/callback",
        "http://localhost:3000/callback",
        "com.example.app:/callback"
      )
      pc <- env.client(List("authorization_code"), redirectUris = registered)
      u <- env.user()
      // ポートだけ違うループバック（IPv4・IPv6）は通り、要求したポートへ戻る
      ok4 <- authorize(app, pc._2, u._2, "http://127.0.0.1:51234/callback")
      _ = assert(ok4.startsWith("http://127.0.0.1:51234/callback?code="), ok4)
      ok6 <- authorize(app, pc._2, u._2, "http://[::1]:40123/callback")
      _ = assert(ok6.startsWith("http://[::1]:40123/callback?code="), ok6)
      // カスタムスキームへは 303 の Location で戻す
      custom <- authorize(app, pc._2, u._2, "com.example.app:/callback")
      _ = assert(custom.startsWith("com.example.app:/callback?code="), custom)
      // パス・ホストの違い、localhost のポート違い、登録のないスキームは断る（エラーの画面. クライアントへは戻さない）
      bad <- List(
        "http://127.0.0.1:51234/other",
        "http://127.0.0.2:51234/callback",
        "http://localhost:3001/callback",
        "http://evil.example:51234/callback",
        "https://127.0.0.1:51234/callback",
        "com.example.other:/callback"
      ).traverse(authorize(app, pc._2, u._2, _))
      _ = assert(bad.forall(_.startsWith("/error?message=")), bad.toString)
      // トークンの交換: 認可で使った値（ポートまで）と違う redirect_uri は通らない
      wrong <- exchange(app, pc._2, ok4, "http://127.0.0.1:9/callback")
      _ = assertEquals((wrong._1, error(wrong._2)), (Status.BadRequest, "invalid_grant"))
      right <- exchange(app, pc._2, ok6, "http://[::1]:40123/callback")
      _ = assertEquals(right._1, Status.Ok, right._2.noSpaces)
      _ = assert(str(right._2, "id_token").nonEmpty)
      // 機密クライアントは、ループバックでも完全一致だけ
      cc <- env.client(List("authorization_code"), redirectUris = registered, secret = Some("s3cret-0123456789"))
      c0 <- authorize(app, cc._2, u._2, "http://127.0.0.1:51234/callback")
      _ = assert(c0.startsWith("/error?message="), c0)
      c1 <- authorize(app, cc._2, u._2, "http://127.0.0.1/callback")
      _ = assert(c1.startsWith("http://127.0.0.1/callback?code="), c1)
      _ <- env.apps.delete(pc._1.id) *> env.apps.delete(cc._1.id)
    } yield ()
  }
}
