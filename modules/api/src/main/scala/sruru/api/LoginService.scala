package sruru.api

import sbirds.shared.AppError

import cats.effect.*
import cats.syntax.all.*
import io.circe.Json
import io.circe.syntax.*
import sruru.core.*
import sruru.db.*
import sruru.security.*
import sruru.shared.*

import java.time.Instant
import java.util.UUID

/**
 * ログインの流れ. 本人確認（パスワード・クライアント証明書・外部の IdP）→ 必要なら パスワードの変更・2つ目の要素・認証アプリの登録 → 完了.
 * 途中の状態は login_flows に保存する（ブラウザのセッションに結び付け、15分で切れる）.
 */
final class LoginService(dir: Directory,
                         sessions: SessionStore,
                         factors: FactorStore,
                         tokens: TokenStore,
                         apps: AppStore,
                         fedStore: FederationStore,
                         policies: PolicyService,
                         audit: AuditService,
                         mail: MailService,
                         box: SecretBox,
                         cfg: ApiConfig) {

  private val FlowTtl = 15L * 60
  private val EmailMaxTry = 5
  // ロック中も同じ文言（ロックの有無やパスワードの正誤を、ロック中の応答で知られないように）
  private val Generic = "ユーザー名またはパスワードが違うか、アカウントが一時的にロックされています"

  // ------------------------------------------------------------------ 認可の要求の表示

  private val scopeLabels = Map(
    "openid" -> "ログインの確認（ID）",
    "profile" -> "名前・ユーザー名・アイコン",
    "email" -> "メールアドレス",
    "groups" -> "所属グループ",
    "phone" -> "電話番号",
    "offline_access" -> "ログアウト後も使い続ける（リフレッシュトークン）"
  )

  /** アプリケーションの概要を作る関数（アイコン・起動の URL は、この要求のホスト名のもの）. */
  def appBrief: IO[Application => AppBriefDto] = cfg.url.map(base => appBrief(_, base))

  private def appBrief(a: Application, base: String): AppBriefDto =
    AppBriefDto(
      a.id,
      a.slug,
      a.name,
      a.iconUpdatedAt.map(t => s"$base/app-icons/${a.id}?v=${t.getEpochSecond}"),
      a.launchUrl.orElse(Option.when(a.protocol == "saml")(s"$base/saml/idp/${a.slug}")),
      a.description,
      a.protocol
    )

  def requestDto(id: UUID): IO[Option[AuthRequestDto]] =
    (Time.now.flatMap(now => tokens.request(id, now)), appBrief).flatMapN((req, appBrief) =>
      req.flatTraverse { r =>
        apps.find(r.appId).map(_.map { a =>
          val c = r.params.hcursor
          val scopes = c.get[String]("scope").toOption.toList.flatMap(_.split(' ').filter(_.nonEmpty))
          AuthRequestDto(
            r.id,
            appBrief(a),
            scopes.map(s => ScopeDto(s, scopeLabels.getOrElse(s, s))),
            c.get[String]("prompt").toOption.toList.flatMap(_.split(' ').toList),
            c.get[String]("login_hint").toOption,
            c.get[String]("user_code").toOption
          )
        })
      }
    )

  // ------------------------------------------------------------------ 画面に返す状態

  private def maskEmail(e: String): String = {
    val (l, d) = e.span(_ != '@')
    (if l.length <= 2 then l.take(1) + "*" else l.take(2) + "*" * math.min(6, l.length - 2)) + d
  }

  private def methods(u: User, p: PoliciesDto): IO[List[String]] =
    (factors.totps(u.id), factors.recoveryRemaining(u.id)).mapN {
      (ts, rec) =>
        List(
          Option.when(p.mfa.allowTotp && ts.exists(_.confirmed))("totp"),
          // 確認済みのアドレスだけ（未確認のアドレスへ2つ目の要素を送らない）
          Option.when(p.mfa.allowEmail && u.email.isDefined && u.emailVerified)("email"),
          Option.when(rec > 0)("recovery")
        ).flatten
    }

  def dto(f: LoginFlow, extra: FlowDto => FlowDto = identity): IO[FlowDto] =
    for {
      u <- f.userId.flatTraverse(dir.users.find)
      p <- u.fold(policies.get)(dir.policyFor)
      ms <- u.filter(_ => f.stage == "mfa").fold(IO.pure(Nil))(methods(_, p))
      req <- f.authRequestId.flatTraverse(requestDto)
      rules <- if f.stage == "change_password" || f.stage == "identify" then
        u.fold(dir.passwordRules)(dir.passwordRulesFor)
      else IO.pure(Nil)
      sent = f.data.hcursor.get[Boolean]("emailSent").getOrElse(false)
    } yield extra(FlowDto(
      f.id,
      f.stage,
      u.map(x => FlowUserDto(x.username, x.name, dir.pictureUrl(x, p))),
      ms,
      u.flatMap(_.email).map(maskEmail),
      sent,
      None,
      Nil,
      rules,
      None,
      req
    ))

  private def withFlow[A](bs: BrowserSession, id: UUID)(f: LoginFlow => Res[A]): Res[A] =
    Time.now.flatMap(now => sessions.flow(id, bs.id, now)).flatMap {
      case None => Res.fail(AppError(ErrorCode.LoginExpired))
      case Some(x) => f(x)
    }

  private def withUser[A](f: LoginFlow)(g: User => Res[A]): Res[A] =
    f.userId.flatTraverse(dir.users.find).flatMap {
      case Some(u) if !u.disabled => g(u)
      case _ => Res.fail(AppError(ErrorCode.LoginExpired))
    }

  // ------------------------------------------------------------------ 開始

  /** 同じサイトの中のパスだけ（制御文字・空白・バックスラッシュを含むものは、ブラウザが //外部 と解釈しうるので拒否する）. */
  private def safeReturn(s: Option[String]): Option[String] =
    s.filter(r =>
      r.startsWith("/") && !r.startsWith("//") && r.length <= 2000 &&
        r.forall(ch => ch > ' ' && ch != '\\' && ch != '\u007f')
    )

  def start(c: ReqCtx, bs: BrowserSession, req: LoginStartReq, current: Option[(Login, User)]): Res[FlowDto] =
    for {
      now <- Time.now
      reqOk <- req.requestId.flatTraverse(id => tokens.request(id, now)).map(r => req.requestId.isEmpty || r.isDefined)
      res <- if !reqOk then Res.fail(ErrorCode.AuthRequestExpired)
      else
        sessions.createFlow(bs.id, req.requestId, safeReturn(req.returnTo), now.plusSeconds(FlowTtl)).flatMap { f =>
          current.filter(_ => req.stepUp) match {
            // 多要素認証の追加（使用中のアカウントのまま2つ目の要素だけ求める）
            case Some((l, u)) =>
              val f2 = f.copy(userId = Some(u.id), amr = l.amr, data = Json.obj("stepUp" -> true.asJson))
              sessions.saveFlow(f2) *> advance(c, bs, f2, u).map(Right(_))
            case None => dto(f).map(Right(_))
          }
        }
    } yield res

  def get(bs: BrowserSession, id: UUID): Res[FlowDto] = withFlow(bs, id)(f => dto(f).map(Right(_)))

  // ------------------------------------------------------------------ パスワード

  private def windowStart(p: PoliciesDto, now: Instant) = now.minusSeconds(p.lockout.ipWindowMinutes.toLong * 60)

  /** この IP からの失敗が上限に達しているか（ログインのほか、ログイン後のパスワードの確認でも使う）. */
  def throttled(c: ReqCtx): IO[Boolean] =
    (policies.get, Time.now).flatMapN {
      (p, now) =>
        if p.lockout.ipMaxFailures <= 0 then IO.pure(false)
        else
          factors.throttleCount("ip:" + IpRules.throttleKey(c.ip), windowStart(p, now)).map(_ >=
            p.lockout.ipMaxFailures)
    }

  /** 失敗を記録する（IP ごとの回数・ユーザーのロック・監査ログ）. */
  private def failed(c: ReqCtx, u: Option[User], action: String, reason: String, extra: Json = Json.obj()): IO[Unit] =
    countFailure(c, u) *>
      audit.log(
        c,
        u,
        "web",
        action,
        u.flatMap(audit.userTarget),
        success = false,
        detail = Json.obj("reason" -> reason.asJson).deepMerge(extra)
      )

  /**
   * 失敗を数える（IP ごとの回数・ユーザーのロック. ロックしたときは監査ログに user.locked を残す）.
   * ログイン後のパスワードの確認（MeRoutes）でも同じ数え方をする（失敗の監査ログは呼び出し側で残す）.
   */
  def countFailure(c: ReqCtx, u: Option[User]): IO[Unit] =
    for {
      p <- policies.get
      now <- Time.now
      _ <- factors.throttleFail("ip:" + IpRules.throttleKey(c.ip), windowStart(p, now))
      up <- u.fold(IO.pure(p))(dir.policyFor)
      _ <- u.filter(_ => up.lockout.enabled).traverse_ { x =>
        val p = up
        val until = if p.lockout.lockMinutes > 0 then now.plusSeconds(p.lockout.lockMinutes.toLong * 60)
        else Instant.parse("9999-12-31T00:00:00Z")
        dir.users.recordFailure(x.id, p.lockout.maxFailures, until).flatMap {
          (n, lockedUntil) =>
            IO.whenA(lockedUntil.exists(_.isAfter(now)) && !x.locked(now))(
              audit.log(
                c,
                Some(x),
                "web",
                "user.locked",
                audit.userTarget(x),
                detail = Json.obj("failures" -> n.asJson)
              )
            )
        }
      }
    } yield ()

  private def precheck(c: ReqCtx): IO[Option[AppError]] =
    // IP 制限・試行の制限
    sessionsIp(c).flatMap {
      case false => IO.pure(Some(AppError(ErrorCode.LoginIpDenied)))
      case true => throttled(c).map(t => Option.when(t)(AppError(ErrorCode.LoginTooManyFailures)))
    }

  private def sessionsIp(c: ReqCtx): IO[Boolean] = policies.get.map(p => IpRules.allowedBy(c.ip, p.ip))

  // スパンにはユーザー名・パスワードを載せない（結果は監査ログ → AuditMetrics で数える）
  def password(c: ReqCtx, bs: BrowserSession, req: PasswordLoginReq): Res[FlowDto] =
    sbirds.observe.Telemetry.span("login.password")(
      withFlow(bs, req.flowId) { f =>
        precheck(c).flatMap {
          case Some(e) => Res.fail(e)
          case None =>
            for {
              now <- Time.now
              u <- dir.users.byLoginName(req.username.trim)
              res <- u match {
                case None =>
                  IO.blocking(Passwords.verify(req.password, Passwords.dummy)) *>
                    failed(
                      c,
                      None,
                      "login.failure",
                      s"unknown user: ${req.username.take(64)}"
                    ).as(Left(AppError(ErrorCode.LoginFailed)))
                case Some(x) if x.isService || x.passwordHash.isEmpty =>
                  IO.blocking(Passwords.verify(req.password, Passwords.dummy)) *>
                    failed(c, Some(x), "login.failure", "password not set").as(Left(AppError(ErrorCode.LoginFailed)))
                case Some(x) if x.locked(now) =>
                  // ロック中はパスワードを確かめない（正誤で応答を変えると、ロック中に総当たりできてしまう）. IP ごとの失敗としては数える
                  IO.blocking(Passwords.verify(req.password, Passwords.dummy)) *>
                    failed(c, None, "login.failure", s"locked: ${x.username}").as(Left(AppError(ErrorCode.LoginFailed)))
                case Some(x) =>
                  IO.blocking(Passwords.verify(req.password, x.passwordHash.get)).flatMap {
                    case false =>
                      failed(c, Some(x), "login.failure", "wrong password").as(Left(AppError(ErrorCode.LoginFailed)))
                    case true if x.disabled =>
                      audit.log(
                        c,
                        Some(x),
                        "web",
                        "login.failure",
                        audit.userTarget(x),
                        success = false,
                        detail = Json.obj("reason" -> "disabled".asJson)
                      )
                        .as(Left(AppError(ErrorCode.AccountDisabled)))
                    case true =>
                      // パスワードで本人確認をやり直したので、多要素認証の追加（stepUp）の扱いはやめる
                      val f2 =
                        f.copy(userId = Some(x.id), amr = List(Amr.Pwd), data = f.data.mapObject(_.remove("stepUp")))
                      // 失敗の回数はログインの完了（多要素認証の後）で戻す. ここで戻すと、2つ目の要素の総当たりでロックを回避できる
                      sessions.saveFlow(f2) *> advance(c, bs, f2, x).map(Right(_))
                  }
              }
            } yield res
        }
      }
    )

  // ------------------------------------------------------------------ 次の段階

  private def appRequiresMfa(f: LoginFlow): IO[Boolean] =
    f.authRequestId.fold(IO.pure(false))(id =>
      Time.now.flatMap(now => tokens.request(id, now)).flatMap(_.fold(IO.pure(false))(r =>
        apps.find(r.appId).map(_.exists(_.requireMfa))
      ))
    )

  /** 本人確認の後に何が必要かを決める. */
  def advance(c: ReqCtx, bs: BrowserSession, f: LoginFlow, u: User): IO[FlowDto] =
    for {
      now <- Time.now
      m <- dir.membership(u)
      p <- dir.policyFor(u, m)
      hasTotp <- dir.hasTotp(u.id)
      appMfa <- appRequiresMfa(f)
      stepUp = isStepUp(f)
      needPw = f.amr.contains(Amr.Pwd) && (u.mustChangePassword || dir.passwordExpired(u, p, now))
      required = dir.mfaRequired(u, m, p) || appMfa || stepUp
      needMfa = !Amr.isMulti(f.amr) && ((p.mfa.mode != "off" && (required || hasTotp)) || appMfa || stepUp)
      ms <- methods(u, p)
      res <-
        // パスワードの変更は多要素認証の後（パスワードだけを知る人に変えさせない）. 多要素の追加（stepUp）では求めない
        // （盗んだ Cookie から、今のパスワードを知らずに変えられないように. 次の通常のログインで求める）
        // グループの上書きの IP 制限は、ユーザーが分かったところで確かめる
        if !IpRules.allowedBy(c.ip, p.ip) then
          sessions.deleteFlow(f.id).as(FlowDto(f.id, "error", message = Some("この IP アドレスからはログインできません")))
        else if needMfa && ms.exists(_ != "recovery") then save(f.copy(stage = "mfa"))
        // 多要素認証の追加（stepUp）では、登録済みの要素（回復コードを含む）だけ受け付け、新しい要素は登録させない
        // （盗んだ Cookie だけで自分の認証アプリを登録し、多要素認証を済ませたことにできないように.
        //  登録は、パスワードでログインし直すか、直近のログインが要る設定の画面から行う）
        else if needMfa && stepUp && ms.nonEmpty then save(f.copy(stage = "mfa"))
        else if needMfa && stepUp then
          sessions.deleteFlow(f.id).as(FlowDto(f.id, "error", message = Some(ErrorCode.MfaEnrollNotInStepUp.message)))
        else if needMfa && required && p.mfa.allowTotp then save(f.copy(stage = "enroll_mfa"))
        else if needMfa && required then
          IO.pure(FlowDto(f.id, "error", message = Some("多要素認証の方法が登録されていません。管理者に連絡してください")))
        else if needPw && !stepUp then save(f.copy(stage = "change_password"))
        else complete(c, bs, f, u)
    } yield res

  private def save(f: LoginFlow): IO[FlowDto] = sessions.saveFlow(f) *> dto(f)

  /** ログインを完了する（ブラウザのセッションにアカウントを加えて使用中にする）. */
  def complete(c: ReqCtx, bs: BrowserSession, f: LoginFlow, u: User): IO[FlowDto] =
    for {
      p <- dir.policyFor(u)
      now <- Time.now
      ls <- sessions.logins(bs.id, now)
      stepUp = isStepUp(f)
      // 多要素認証の追加で、すでにある要素を確かめていない（すでに多要素だった）なら、
      // 認証の時刻も期限も進めない（Cookie だけで「直近のログイン」・prompt=login・max_age を満たしたり、期限を延ばし続けたりできないように）
      keep = stepUp && !f.data.hcursor.get[Boolean](Proved).getOrElse(false)
      res <-
        // 多要素認証の追加は、使用中のログインに要素を足すだけ. そのログインが（ログアウトなどで）もう無ければ、
        // パスワードなしで新しいログインを作らせない
        if stepUp && !ls.exists(_.userId == u.id) then
          sessions.deleteFlow(f.id).as(FlowDto(f.id, "error", message = Some("ログインが終わっています。もう一度ログインしてください")))
        else
          for {
            // 同時にログインできるアカウントの数を超えるなら、いちばん古いものを外す
            _ <- IO.whenA(!ls.exists(_.userId == u.id) && ls.size >= math.max(1, p.session.maxAccounts))(
              ls.sortBy(_.lastSeenAt).headOption.traverse_(o =>
                sessions.removeLogin(bs.id, o.userId).flatMap(_.traverse_(dir.endLogin(o.userId, _)))
              )
            )
            _ <- sessions.upsertLogin(
              bs.id,
              u.id,
              f.amr,
              c.ip,
              c.userAgent,
              ls.find(_.userId == u.id).filter(_ => keep).map(_.expiresAt)
                .getOrElse(now.plusSeconds(p.session.lifetimeHours.toLong * 3600)),
              keepAuthTime = keep
            )
            _ <- dir.users.touchLogin(u.id)
            _ <-
              dir.recomputeUser(u).handleErrorWith(e => sbirds.observe.Log.report(ErrorCode.DynamicGroupsFailed, "", e))
            _ <- audit.log(
              c,
              Some(u),
              "web",
              "login.success",
              audit.userTarget(u),
              detail = Json.obj(
                "amr" -> f.amr.distinct.asJson,
                "requestId" -> f.authRequestId.map(_.toString).asJson
              )
            )
            _ <- sessions.deleteFlow(f.id)
          } yield FlowDto(
            f.id,
            "done",
            redirect = Some(f.authRequestId.fold(f.returnTo.getOrElse("/"))(id => s"/auth/resume?req=$id"))
          )
    } yield res

  // ------------------------------------------------------------------ 2つ目の要素

  private def addMfa(f: LoginFlow, method: String): LoginFlow = f.copy(amr = (f.amr ++ List(method, Amr.Mfa)).distinct)

  /** 多要素認証の追加（使用中のアカウントのまま、2つ目の要素だけ求める流れ）か. */
  private def isStepUp(f: LoginFlow): Boolean = f.data.hcursor.get[Boolean]("stepUp").getOrElse(false)

  /** この流れの中で、すでに登録してある要素（2つ目の要素・証明書・外部の IdP）を確かめた印（login_flows.data）. */
  private val Proved = "proved"
  private def proved(f: LoginFlow): LoginFlow = f.copy(data = f.data.deepMerge(Json.obj(Proved -> true.asJson)))

  def mfa(c: ReqCtx, bs: BrowserSession, req: MfaReq): Res[FlowDto] =
    sbirds.observe.Telemetry.span("login.mfa", "method" -> AuditMetrics.mfaMethod(req.method))(
      withFlow(bs, req.flowId) { f =>
        withUser(f) { u =>
          if f.stage != "mfa" then Res.fail(ErrorCode.LoginStepInvalid)
          else
            (throttled(c), dir.policyFor(u), Time.now).flatMapN {
              (thr, p, now) =>
                if thr then Res.fail(AppError(ErrorCode.TooManyAttempts))
                else if u.locked(now) then Res.fail(ErrorCode.AccountLocked)
                else {
                  val ok: IO[Option[String]] = req.method match {
                    case "totp" if p.mfa.allowTotp =>
                      factors.totps(u.id).flatMap(_.filter(_.confirmed).collectFirstSomeM { d =>
                        box.decrypt(d.secretEnc).flatMap(s =>
                          Totp.verify(s, req.code, now.getEpochSecond, d.lastUsedStep)
                        ) match {
                          case Some(step) => factors.useTotp(d.id, step).map(Option.when(_)(Amr.Otp))
                          case None => IO.pure(None)
                        }
                      })
                    case "email" if p.mfa.allowEmail && u.emailVerified =>
                      factors.emailToken(u.id, "login", now).flatMap {
                        case Some(t) if t.attempts < EmailMaxTry =>
                          // 回数の確認と加算は1つの SQL で行う（並列に送って上限を超えられないように）
                          factors.emailTokenAttempt(t.id, EmailMaxTry).flatMap {
                            case true
                                if Crypto.constantTimeEquals(Crypto.sha256(req.code.filter(_.isDigit)), t.tokenHash) =>
                              factors.consumeEmailToken(t.id).map(Option.when(_)(Amr.Email))
                            case _ => IO.pure(None)
                          }
                        case _ => IO.pure(None)
                      }
                    case "recovery" =>
                      val code = req.code.toLowerCase.filter(_.isLetterOrDigit)
                      factors.useRecoveryCode(u.id, Crypto.sha256(code)).map(Option.when(_)(Amr.Otp))
                    case _ => IO.pure(None)
                  }
                  ok.flatMap {
                    case Some(m) =>
                      val f2 = proved(addMfa(f, m))
                      audit.log(
                        c,
                        Some(u),
                        "web",
                        "login.mfa",
                        audit.userTarget(u),
                        detail = Json.obj("method" -> req.method.asJson)
                      ) *>
                        sessions.saveFlow(f2) *> advance(c, bs, f2, u).map(Right(_))
                    case None =>
                      failed(
                        c,
                        Some(u),
                        "login.mfa",
                        s"wrong ${req.method} code",
                        Json.obj("method" -> req.method.take(20).asJson)
                      ).as(Left(AppError(ErrorCode.CodeInvalidOrExpired)))
                  }
                }
            }
        }
      }
    )

  /** メールでワンタイムコードを送る. */
  def sendEmailCode(c: ReqCtx, bs: BrowserSession, flowId: UUID): Res[FlowDto] =
    withFlow(bs, flowId) { f =>
      withUser(f) { u =>
        (dir.policyFor(u), Time.now).flatMapN {
          (p, now) =>
            val last = f.data.hcursor.get[Long]("emailAt").getOrElse(0L)
            // 確認済みのアドレスだけ（methods と同じ条件. 未確認のアドレスへ2つ目の要素を送らない）
            if f.stage != "mfa" || !p.mfa.allowEmail || u.email.isEmpty || !u.emailVerified then
              Res.fail(ErrorCode.EmailCodeDisabled)
            else if now.getEpochSecond - last < 30 then Res.fail(AppError(ErrorCode.EmailCodeTooSoon))
            else {
              val code = Crypto.randomDigits(6)
              for {
                _ <- factors.createEmailToken(
                  u.id,
                  "login",
                  Crypto.sha256(code),
                  now.plusSeconds(p.mfa.emailCodeMinutes.toLong * 60)
                )
                _ <- mail.send(
                  u.email.get,
                  s"${p.branding.title} のログインのコード: $code",
                  s"${u.name} さん\n\nログインのコードは $code です（${p.mfa.emailCodeMinutes}分間有効）。\n" +
                    s"心当たりがない場合は、このメールを破棄し、パスワードの変更をご検討ください。\n\nIP アドレス: ${c.ip}\n"
                )
                f2 = f.copy(data =
                  f.data.deepMerge(Json.obj("emailAt" -> now.getEpochSecond.asJson, "emailSent" -> true.asJson))
                )
                _ <- sessions.saveFlow(f2)
                d <- dto(f2)
              } yield Right(d)
            }
        }
      }
    }

  // ------------------------------------------------------------------ 認証アプリの登録（必須のとき）

  def enrollTotp(bs: BrowserSession, flowId: UUID): Res[FlowDto] =
    withFlow(bs, flowId) { f =>
      withUser(f) { u =>
        if f.stage != "enroll_mfa" then Res.fail(ErrorCode.LoginStepInvalid)
        // 多要素認証の追加（stepUp）の途中では登録させない（advance でもこの段階へは進めないが、ここでも断る）
        else if isStepUp(f) then Res.fail(ErrorCode.MfaEnrollNotInStepUp)
        else
          dir.policyFor(u).flatMap { p =>
            val secret = Totp.newSecret()
            factors.deleteUnconfirmedTotps(u.id) *> factors.addTotp(u.id, "認証アプリ", box.encrypt(secret)).flatMap { d =>
              dto(
                f,
                _.copy(totpSetup = Some(TotpSetupDto(d.id, secret, Totp.uri(p.branding.title, u.username, secret))))
              ).map(Right(_))
            }
          }
      }
    }

  /** 認証アプリのコードを確かめて登録を終える. 回復コードを返す（この1回だけ表示する）. */
  def verifyEnroll(c: ReqCtx, bs: BrowserSession, req: FlowTotpVerifyReq): Res[FlowDto] =
    withFlow(bs, req.flowId) { f =>
      withUser(f) { u =>
        factors.totp(req.deviceId).flatMap {
          case _ if isStepUp(f) => Res.fail(ErrorCode.MfaEnrollNotInStepUp)
          case Some(d) if d.userId == u.id && !d.confirmed && f.stage == "enroll_mfa" =>
            Time.now.flatMap { now =>
              box.decrypt(d.secretEnc).flatMap(s => Totp.verify(s, req.code, now.getEpochSecond, 0)) match {
                case None => Res.fail(AppError(ErrorCode.TotpCodeWrong))
                case Some(step) =>
                  for {
                    _ <- factors.confirmTotp(d.id, step)
                    codes <- newRecoveryCodes(u.id)
                    _ <- audit.log(c, Some(u), "web", "mfa.totp.enroll", audit.userTarget(u))
                    f2 = addMfa(f, Amr.Otp).copy(stage = "show_recovery")
                    _ <- sessions.saveFlow(f2)
                    d2 <- dto(f2, _.copy(recoveryCodes = codes))
                  } yield Right(d2)
              }
            }
          case _ => Res.fail(ErrorCode.MfaEnrollRestart)
        }
      }
    }

  def newRecoveryCodes(userId: UUID): IO[List[String]] = {
    val codes = List.fill(10)(Crypto.randomCode(10))
    factors.setRecoveryCodes(userId, codes.map(Crypto.sha256)).as(codes.map(c => c.take(5) + "-" + c.drop(5)))
  }

  /** 回復コードを確認した後に続ける. */
  def continue(c: ReqCtx, bs: BrowserSession, flowId: UUID): Res[FlowDto] =
    withFlow(bs, flowId)(f =>
      withUser(f)(u => if f.stage == "show_recovery" then advance(c, bs, f, u).map(Right(_)) else dto(f).map(Right(_)))
    )

  // ------------------------------------------------------------------ パスワードの変更（期限切れ・管理者の指定）

  def changePassword(c: ReqCtx, bs: BrowserSession, req: FlowPasswordReq): Res[FlowDto] =
    withFlow(bs, req.flowId) { f =>
      withUser(f) { u =>
        if f.stage != "change_password" then Res.fail(ErrorCode.LoginStepInvalid)
        else
          dir.setPassword(u, req.password, mustChange = false, keepLogin = None).flatMap {
            case Left(e) => Res.fail(ErrorCode.InvalidInput, e)
            case Right(_) =>
              audit.log(
                c,
                Some(u),
                "web",
                "user.password.change",
                audit.userTarget(u),
                detail = Json.obj("reason" -> "required".asJson)
              ) *>
                dir.users.find(u.id).flatMap(u2 =>
                  advance(c, bs, f.copy(stage = "identify"), u2.getOrElse(u)).map(Right(_))
                )
          }
      }
    }

  // ------------------------------------------------------------------ ほかの方法での本人確認（証明書・外部の IdP）

  def externalAuthenticated(c: ReqCtx,
                            bs: BrowserSession,
                            flowId: UUID,
                            u: User,
                            amr: List[String],
                            action: String,
                            detail: Json): Res[FlowDto] =
    withFlow(bs, flowId) { f =>
      // IP アドレスの制限は、パスワード以外の方法でも同じように効かせる
      (sessionsIp(c), Time.now).flatMapN {
        (ipOk, now) =>
          if !ipOk then Res.fail(ErrorCode.LoginIpDenied)
          else if u.disabled then
            audit.log(
              c,
              Some(u),
              "web",
              "login.failure",
              audit.userTarget(u),
              success = false,
              detail = detail.deepMerge(Json.obj("reason" -> "disabled".asJson))
            ).as(Left(AppError(ErrorCode.AccountDisabled)))
          else if u.locked(now) then Res.fail(ErrorCode.AccountLocked)
          else
            // 多要素認証の追加の途中なら、同じユーザーであること
            if f.userId.exists(_ != u.id) then Res.fail(ErrorCode.AuthenticatedAsOtherAccount)
            else {
              val f2 = proved(f.copy(userId = Some(u.id), amr = (f.amr ++ amr).distinct))
              audit.log(c, Some(u), "web", action, audit.userTarget(u), detail = detail) *> sessions.saveFlow(f2) *>
                advance(c, bs, f2, u).map(Right(_))
            }
      }
    }

  /** 失敗の記録（外部の IdP・証明書）. */
  def externalFailed(c: ReqCtx, u: Option[User], action: String, reason: String): IO[Unit] =
    failed(c, u, action, reason)

  // ------------------------------------------------------------------ パスワードを忘れた

  /**
   * パスワードの再設定のメールを送る. 宛先は確認済みのアドレスだけ（本人が変えて確認待ちのアドレスには送らない.
   * 未確認のアドレスは他人のものかもしれず、再設定のリンクを渡すとアカウントを取られる）.
   * byAdmin: 管理者が画面から送るとき. 管理者が宛先を見て送るので、いま登録されているアドレスに送る.
   */
  def forgot(c: ReqCtx, req: ForgotReq, byAdmin: Boolean = false): IO[Unit] =
    // メールの送りすぎを防ぐ（同じ IP アドレスから15分に10回まで）
    (
      throttled(c),
      policies.get,
      Time.now.flatMap(now => factors.throttleFail("forgot:" + IpRules.throttleKey(c.ip), now.minusSeconds(15 * 60)))
    ).flatMapN {
      (thr, p, n) =>
        IO.unlessA(thr || n > 10) {
          dir.users.byLoginName(req.username.trim).flatMap {
            case Some(u) if !u.disabled && !u.isService && resetAddress(u, byAdmin).isDefined && u.source == "local" =>
              val t = Crypto.randomToken()
              Time.now.flatMap(now =>
                factors.createEmailToken(u.id, "reset", Crypto.sha256(t), now.plusSeconds(30 * 60))
              ) *>
                dir.policyFor(u).flatMap(up =>
                  mail.send(
                    resetAddress(u, byAdmin).get,
                    s"${up.branding.title} のパスワードの再設定",
                    s"${u.name} さん\n\n次のリンクからパスワードを再設定してください（30分間有効）。\n${cfg.urlOf(up.domain)}/reset-password?token=$t\n\n" +
                      s"心当たりがない場合は、このメールを破棄してください。\n\nIP アドレス: ${c.ip}\n"
                  )
                ) *>
                audit.log(c, Some(u), "web", "user.password.reset_request", audit.userTarget(u))
            case other =>
              audit.log(
                c,
                other,
                "web",
                "user.password.reset_request",
                other.flatMap(audit.userTarget),
                success = false,
                detail = Json.obj("username" -> req.username.take(64).asJson)
              )
          }
        }
    }

  /** 再設定のメールの宛先. */
  private def resetAddress(u: User, byAdmin: Boolean): Option[String] = if byAdmin then u.email else u.verifiedEmail

  def reset(c: ReqCtx, req: ResetReq): Res[Unit] =
    Time.now.flatMap(now => factors.emailTokenByHash("reset", Crypto.sha256(req.token.trim), now)).flatMap {
      case None => Res.fail(ErrorCode.ResetLinkInvalid)
      case Some(t) =>
        dir.users.find(t.userId).flatMap {
          case Some(u) if !u.disabled =>
            // 条件を確かめてから、トークンを使用済みにする（同時に2回使われても1回だけ通す）
            dir.checkPassword(Some(u), req.password).flatMap {
              case Left(e) => Res.fail(ErrorCode.InvalidInput, e)
              case Right(_) =>
                factors.consumeEmailToken(t.id).flatMap {
                  case false => Res.fail(ErrorCode.ResetLinkInvalid)
                  case true =>
                    dir.setPassword(u, req.password, mustChange = false, keepLogin = None).flatMap {
                      case Left(e) => Res.fail(ErrorCode.InvalidInput, e)
                      case Right(_) => dir.users.unlock(u.id) *>
                          audit.log(c, Some(u), "web", "user.password.reset", audit.userTarget(u)).as(Right(()))
                    }
                }
            }
          case _ => Res.fail(ErrorCode.AccountUnusable)
        }
    }

  // ------------------------------------------------------------------ 自分でアカウントを作る

  def register(c: ReqCtx, bs: BrowserSession, req: RegisterReq): Res[FlowDto] =
    policies.get.flatMap { p =>
      if !p.branding.selfRegistration then Res.fail(ErrorCode.SignupDisabled)
      else
        precheck(c).flatMap {
          case Some(e) => Res.fail(e)
          case None =>
            withFlow(bs, req.flowId) { f =>
              (
                dir.validUsername(req.username),
                dir.validEmail(Some(req.email)).flatMap(_.toRight("メールアドレスを入力してください"))
              ).tupled match {
                case Left(e) => Res.fail(ErrorCode.InvalidInput, e)
                case Right((name, email)) =>
                  dir.users.byEmail(email).flatMap {
                    case _ :: _ => Res.fail(AppError(ErrorCode.EmailInUse, "このメールアドレスはすでに使われています"))
                    case Nil =>
                      dir.checkPassword(None, req.password).flatMap {
                        case Left(e) => Res.fail(ErrorCode.InvalidInput, e)
                        case Right(_) =>
                          Directory.hash(req.password).flatMap(h =>
                            dir.users.create(NewUser(
                              name,
                              Some(email),
                              req.name.trim.take(200).some.filter(_.nonEmpty).getOrElse(name),
                              passwordHash = Some(h)
                            ))
                          ).flatMap {
                            case Left(e) => Res.fail(e)
                            case Right(u) =>
                              audit.log(c, Some(u), "web", "user.register", audit.userTarget(u)) *> {
                                val f2 = f.copy(userId = Some(u.id), amr = List(Amr.Pwd))
                                sessions.saveFlow(f2) *> advance(c, bs, f2, u).map(Right(_))
                              }
                          }
                      }
                  }
              }
            }
        }
    }
}
