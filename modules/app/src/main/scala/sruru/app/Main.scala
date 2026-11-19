package sruru.app

import sruru.core.ErrorCode

import sbirds.shared.AppError

import sbirds.http.Errors

import cats.effect.*
import cats.syntax.all.*
import com.comcast.ip4s.*
import doobie.implicits.*
import fs2.io.file.Path
import fs2.io.net.Network
import fs2.io.net.tls.TLSParameters
import org.http4s.*
import org.http4s.dsl.io.*
import org.http4s.ember.client.EmberClientBuilder
import org.http4s.ember.server.EmberServerBuilder
import org.http4s.server.middleware.{EntityLimiter, ErrorHandling}
import org.http4s.server.staticcontent.*
import sruru.api.*
import sruru.db.*
import sbirds.mail.{SmtpConfig, SmtpMailer}
import sbirds.observe.{HttpClientTelemetry, HttpTelemetry, Metrics, RumRoutes, Telemetry}
import sruru.security.SecretBox

import scala.concurrent.duration.*

final case class TlsConfig(
  keystore: String,
  password: String,
  port: Int)

final case class AppConfig(
  port: Int,
  db: DbConfig,
  api: ApiConfig,
  staticDir: Option[String],
  smtp: Option[SmtpConfig],
  appSecret: String,
  tls: Option[TlsConfig])

object Main extends IOApp.Simple {

  // ログにトレースの ID・操作したユーザーを載せるため、IOLocal の文脈を Java のライブラリから見えるようにする
  // （IORuntime を作る前に設定する必要がある. オブジェクトの初期化は main より先に動く）
  Telemetry.prepare()

  private val version =
    Option(getClass.getPackage.getImplementationVersion).orElse(sys.env.get("APP_VERSION")).getOrElse("dev")

  private given org.typelevel.log4cats.LoggerFactory[IO] = org.typelevel.log4cats.slf4j.Slf4jFactory.create[IO]

  /** バックエンドのパス（画面の index.html を返さない）. */
  private val backendPrefixes = Set(
    "api",
    "auth",
    "oauth2",
    "oauth",
    "saml",
    "scim",
    "mcp",
    ".well-known",
    "avatars",
    "app-icons",
    "brand-logos",
    "healthz"
  )

  /** トレース・メトリクス・アクセスログの対象（画像・/healthz は除く）. クエリ（?code=・?state=・SAMLRequest）は記録しない. */
  private val tracedPrefixes = List("/api", "/auth", "/oauth2", "/oauth", "/saml", "/scim", "/mcp", "/.well-known")

  def run: IO[Unit] =
    for {
      cfg <- Config.load
      n <- migrateWithRetry(cfg)
      _ <- sbirds.observe.Log.println(s"[sruru] database migrated ($n migration(s) applied); node ${cfg.api.nodeId}")
      _ <- (for {
        _ <- Telemetry.resource("sruru", version, runtime)
        xa <- Database.transactor(cfg.db)
        _ <- gauges(xa)
        // 大きなヘッダーを返すサイトもある. 外への呼び出し（外部の IdP・バックチャネルログアウト・プッシュ）もトレースに出す（traceparent を付けて送る）
        http <- EmberClientBuilder.default[IO].withTimeout(
          30.seconds
        ).withMaxResponseHeaderSize(64 * 1024).build.map(HttpClientTelemetry(_))
        box = new SecretBox(cfg.appSecret)
        users = new UserStore(xa)
        groups = new GroupStore(xa)
        sessions = new SessionStore(xa)
        factors = new FactorStore(xa)
        apps = new AppStore(xa)
        tokens = new TokenStore(xa)
        auditStore = new AuditStore(xa)
        settings = new SettingsStore(xa)
        fedStore = new FederationStore(xa)
        mails = new MailStore(xa)
        lock = new JobLock(xa, cfg.api.nodeId)
        policies <- Resource.eval(PolicyService.create(settings))
        keys <- Resource.eval(KeyService.create(tokens, box, "sruru"))
        _ <- Resource.eval(keys.ensure)
        pushStore = new sbirds.push.PushStore(xa)
        push <- Resource.eval(sbirds.push.PushService.create(pushStore, http, cfg.api.publicUrl, "sruru"))
        audit = new AuditService(auditStore, Some(push))
        mail = new MailService(mails, cfg.smtp.map(new SmtpMailer(_)), cfg.api)
        notifier = new LogoutNotifier(apps, tokens, keys, http, cfg.api)
        dir = new Directory(users, groups, factors, sessions, tokens, policies, notifier, cfg.api)
        auth = new SessionAuth(sessions, factors, dir, policies, cfg.api)
        login = new LoginService(dir, sessions, factors, tokens, apps, fedStore, policies, audit, mail, box, cfg.api)
        fed = new FederationService(fedStore, dir, audit, box, http, lock, cfg.api)
        gate = new AuthGate(auth, apps, tokens, dir, policies, audit)
        claims = new Claims(dir, apps, cfg.api.publicUrl)
        oidc = new OidcRoutes(apps, tokens, sessions, dir, keys, claims, gate, auth, audit, http, cfg.api)
        saml = new SamlRoutes(apps, tokens, sessions, dir, keys, gate, auth, audit, cfg.api)
        loginR = new LoginRoutes(
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
          cfg.api
        )
        me =
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
            cfg.api
          )
        adminR = new AdminRoutes(
          dir,
          factors,
          sessions,
          tokens,
          apps,
          fedStore,
          fed,
          auditStore,
          keys,
          me,
          login,
          claims,
          policies,
          audit,
          mail,
          box,
          settings,
          new SiteIcon(http),
          auth,
          cfg.api
        )
        scim = new ScimRoutes(dir, sessions, tokens, policies, audit, auth, cfg.api)
        oauth = new OAuthRoutes(new OAuthStore(xa), dir, auth, audit, cfg.api)
        resume = new ResumeRoutes(tokens, Map("oidc" -> oidc.resume, "saml" -> saml.resume), gate)
        _ <- Resource.eval(setupNotice(loginR))
        loops = List[IO[Unit]](
          mail.loop,
          fed.loop,
          purgeLoop(sessions, dir, tokens, factors, auditStore, mails, settings, policies, lock),
          Loops.every(
            10.minutes,
            1.hour,
            ErrorCode.DynamicGroupsRecomputeFailed
          )(lock.exclusive("dynamic-groups", 50.minutes)(dir.recomputeAll))
        )
        _ <- loops.traverse_(_.background)
        rest = healthRoutes(xa, cfg.api.nodeId) <+> loginR.routes <+> me.routes <+> adminR.routes <+> oidc.routes <+>
          oauth.routes <+> saml.routes <+>
          resume.routes <+> scim.routes <+> RumRoutes.routes <+> new PushRoutes(pushStore, push, auth).routes
        app = rest <+> new McpRoutes(rest, auth, cfg.api).routes
        all = cfg.staticDir.fold(app)(d => app <+> spa(d))
        // 本文は 2MB まで（画像は 512KB まで. それより大きな要求で資源を使い切らないように）
        httpApp <- HttpTelemetry(
          securityHeaders(cfg.api.cookieSecure)(EntityLimiter.httpApp(
            ErrorHandling.Custom.recoverWith(all.orNotFound)(handler),
            2L * 1024 * 1024
          )),
          tracedPrefixes
        )
        _ <- EmberServerBuilder.default[IO]
          .withHost(ipv4"0.0.0.0")
          .withPort(Port.fromInt(cfg.port).getOrElse(port"8080"))
          .withShutdownTimeout(5.seconds)
          .withHttpApp(httpApp)
          .build
        _ <- cfg.tls.traverse_ { t =>
          // クライアント証明書を求める（提示しなくても接続はできる. 証明書でのログインのときだけ使う）
          Resource.eval(Network[IO].tlsContext.fromKeyStoreFile(
            fs2.io.file.Path(t.keystore),
            t.password.toCharArray,
            t.password.toCharArray
          ))
            .flatMap(ctx =>
              EmberServerBuilder.default[IO].withHost(
                ipv4"0.0.0.0"
              ).withPort(Port.fromInt(t.port).getOrElse(port"8443"))
                .withTLS(
                  ctx,
                  TLSParameters(wantClientAuth = true)
                ).withShutdownTimeout(5.seconds).withHttpApp(httpApp).build
            )
            .evalTap(_ => sbirds.observe.Log.println(s"[sruru] listening on :${t.port} (TLS, client certificates)"))
        }
        _ <- Resource.eval(sbirds.observe.Log.println(s"[sruru] listening on :${cfg.port} (${cfg.api.publicUrl})"))
      } yield ()).useForever
    } yield ()

  /** DB（Patroni のプライマリ）が使えるまで待ってからマイグレーションする. 複数ノード同時起動でも Flyway のロックで1回だけ適用される. */
  private def migrateWithRetry(
    cfg: AppConfig,
    attempt: Int = 1
  ): IO[Int] =
    Database.migrate(cfg.db).handleErrorWith { e =>
      if attempt >= 60 then IO.raiseError(e)
      else
        sbirds.observe.Log.report(ErrorCode.DatabaseNotReady, s"${e.getMessage.take(120)}; retry $attempt/60") *>
          IO.sleep(2.seconds) *> migrateWithRetry(cfg, attempt + 1)
    }

  /** DB から定期的に読むメトリクス（skorimako のダッシュボード・アラート用）. */
  private def gauges(
    xa: doobie.Transactor[IO]
  ): Resource[IO, Unit] = {
    def q(
      sqlText: doobie.Fragment
    ): IO[Long] = sqlText.query[Long].unique.transact(xa)
    List(
      Metrics.gauge(
        "sruru.users.active",
        "有効なユーザーの数（サービスアカウントを除く）"
      )(q(sql"select count(*) from users where not disabled and not is_service")),
      Metrics.gauge("sruru.users.locked", "ロック中のユーザーの数")(q(sql"select count(*) from users where locked_until > now()")),
      Metrics.gauge(
        "sruru.users.active_24h",
        "24時間以内にログインしたユーザーの数"
      )(q(sql"select count(*) from users where last_login_at > now() - interval '24 hours'")),
      Metrics.gauge("sruru.apps.enabled", "有効なアプリケーションの数")(q(sql"select count(*) from applications where enabled")),
      Metrics.gauge(
        "sruru.sessions.active",
        "有効なログイン（セッション）の数"
      )(q(sql"select count(*) from logins where expires_at > now()")),
      Metrics.gauge(
        "sruru.mail.outbox",
        "送信待ちのメールの数"
      )(q(sql"select count(*) from mail_outbox where sent_at is null and attempts < 10"))
    ).sequence_
  }

  private def setupNotice(
    login: LoginRoutes
  ): IO[Unit] =
    // セットアップのトークンは秘密の値なので、ロガー（OTLP で skorimako に送られる）を通さず標準出力にだけ出す
    login.setupToken.flatMap(_.traverse_(t =>
      IO.println(s"[sruru] 管理者がいません。画面の /setup で最初の管理者を作ってください。セットアップのトークン: $t")
    ))

  /** ロードバランサー用のヘルスチェック. DB（プライマリ）に書けない状態なら 503. */
  private def healthRoutes(
    xa: doobie.Transactor[IO],
    node: String
  ): HttpRoutes[IO] = HttpRoutes.of[IO] {
    case GET -> Root / "healthz" =>
      sql"select not pg_is_in_recovery()".query[Boolean].unique.transact(xa).timeout(3.seconds).attempt.flatMap {
        case Right(true) => text(Status.Ok, s"ok $node")
        case Right(false) => text(Status.ServiceUnavailable, "database is read-only (not primary)")
        // 例外の内容は認証なしの応答に出さず、ログにだけ残す
        case Left(e) => sbirds.observe.Log.report(ErrorCode.HealthCheckFailed, e.getMessage, e) *>
            text(Status.ServiceUnavailable, "database unavailable")
      }
  }

  private def text(
    status: Status,
    body: String
  ): IO[Response[IO]] =
    IO.pure(Response[IO](status).withEntity(body)(using EntityEncoder.stringEncoder))

  private val handler: PartialFunction[Throwable, IO[Response[IO]]] = {
    case _: EntityLimiter.EntityTooLarge => Errors.respond(AppError(ErrorCode.RequestTooLarge))
    case e: AppError => Errors.respond(e)
    case e => Errors.respond(AppError(ErrorCode.Unexpected, None, Some(e)))
  }

  /** RUM の読み込み先（CSP の script-src・connect-src に足す. 未設定なら足さない）. */
  private lazy val rumOrigin: Option[String] = RumRoutes.origin

  /** すべての応答に付けるヘッダー（埋め込み・MIME の推測の禁止）. 画面には CSP も付ける. */
  private def securityHeaders(
    https: Boolean
  )(
    app: HttpApp[IO]
  ): HttpApp[IO] = HttpApp[IO] { req =>
    app.run(req).map { r =>
      val base0 = r.putHeaders(
        "X-Content-Type-Options" -> "nosniff",
        "Referrer-Policy" -> "strict-origin-when-cross-origin",
        "X-Frame-Options" -> "DENY"
      )
      // 公開の URL が https なら、以後 http で接続させない（Cookie の盗み見・SSL ストリップを防ぐ）
      val base =
        if https then base0.putHeaders("Strict-Transport-Security" -> "max-age=31536000; includeSubDomains") else base0
      val html = r.contentType.exists(_.mediaType == MediaType.text.html)
      if html && r.headers.get(org.typelevel.ci.CIString("Content-Security-Policy")).isEmpty then {
        // 画面のブラウザの観測（skorimako の RUM）はログインした後の画面だけで読む. ログイン・同意・パスワードの再設定などの画面では
        // 外部のスクリプトを許さない（画面の Observe もその画面で開いたページでは読み込まない）
        val rum = rumOrigin.filterNot(_ => sruru.shared.Pages.isPublic(req.pathInfo.renderString)).fold("")(" " + _)
        base.putHeaders("Content-Security-Policy" ->
          s"default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'; script-src 'self'$rum; connect-src 'self'$rum; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self' https: http:")
      } else base
    }
  }

  /** 期限切れのセッション・トークン・監査ログの掃除（1時間ごと. 1ノードだけ）. */
  private def purgeLoop(
    sessions: SessionStore,
    dir: Directory,
    tokens: TokenStore,
    factors: FactorStore,
    audit: AuditStore,
    mails: MailStore,
    settings: SettingsStore,
    policies: PolicyService,
    lock: JobLock
  ): IO[Unit] =
    Loops.every(2.minutes, 1.hour, ErrorCode.PurgeFailed)(lock.exclusive("purge", 50.minutes) {
      for {
        now <- IO.realTimeInstant
        p <- policies.get
        // 消したログインは、トークンの失効とバックチャネルの通知まで行う（自動で終わったログインのトークンを残さない）
        ended <- sessions.purgeLogins(now)
        _ <- ended.traverse_(
          (
            lid,
            uid
          ) => dir.endLogin(uid, lid)
        )
        // 無操作の時間はユーザーごと（グループの上書き）. 全体とグループのうち最も短い時間を過ぎたものを候補にして、ユーザーごとに判定する
        gs <- dir.groups.all
        idles = (p.session.idleMinutes :: gs.flatMap(_.policy.flatMap(_.session.idleMinutes))).filter(_ > 0)
        cand <- idles.minOption.fold(IO.pure(List.empty[(java.util.UUID, java.util.UUID, java.time.Instant)]))(mi =>
          sessions.idleLogins(now.minusSeconds(mi.toLong * 60))
        )
        _ <- cand.groupBy(_._2).toList.traverse_ {
          (
            uid,
            ls
          ) =>
            dir.users.find(uid).flatMap(_.traverse_(u =>
              dir.policyFor(u).flatMap { up =>
                ls.filter(l =>
                  up.session.idleMinutes > 0 && l._3.plusSeconds(up.session.idleMinutes.toLong * 60).isBefore(now)
                )
                  .traverse_(l => sessions.deleteLogin(l._1).flatMap(_.traverse_(_ => dir.endLogin(uid, l._1))))
              }
            ))
        }
        _ <- sessions.purgeExpired(now)
        _ <- tokens.purge(now)
        _ <- factors.purgeThrottle(now.minusSeconds(86400))
        _ <- factors.purgeEmailTokens(now)
        _ <- mails.purge(now.minusSeconds(30L * 86400))
        // 全体・グループのどこからも使われていないロゴ（上げてから1日たったもの）
        logos = (p.branding.logo.toList ++ gs.flatMap(_.policy.flatMap(_.branding.logo))).flatMap(l =>
          scala.util.Try(java.util.UUID.fromString(l)).toOption
        )
        _ <- settings.purgeLogos(logos.toSet, now.minusSeconds(86400))
        _ <-
          IO.whenA(p.audit.retentionDays > 0)(audit.purge(now.minusSeconds(p.audit.retentionDays.toLong * 86400)).void)
      } yield ()
    })

  /** ビルド済みの画面の配信. 存在しないパスは index.html（SPA）. */
  private def spa(
    dir: String
  ): HttpRoutes[IO] = {
    val files = fileService[IO](FileService.Config(dir))
    val index = HttpRoutes.of[IO] {
      case req @ GET -> _
          if !backendPrefixes.contains(req.pathInfo.segments.headOption.map(_.decoded()).getOrElse("")) =>
        StaticFile.fromPath(Path(dir) / "index.html", Some(req)).getOrElseF(NotFound())
    }
    HttpRoutes[IO] { req =>
      val cc =
        if req.pathInfo.renderString.startsWith("/assets/") then "public, max-age=31536000, immutable" else "no-cache"
      (files <+> index).run(req).map(_.putHeaders("Cache-Control" -> cc))
    }
  }
}
