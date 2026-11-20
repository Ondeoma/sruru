package sruru.api

import cats.effect.*
import cats.syntax.all.*
import io.circe.Json
import io.circe.syntax.*
import org.http4s.*
import org.http4s.circe.CirceEntityCodec.*
import sruru.core.*
import sruru.db.*
import sruru.security.*
import sruru.shared.*

import java.util.UUID

/** デバイスフロー（RFC 8628）の決まった値. */
object DeviceFlow {

  /** device_code・user_code の有効期限（秒）. */
  val TtlSeconds = 600L

  /** 端末がポーリングする間隔（秒）と、早すぎるポーリング（slow_down）のたびに延ばす秒数（RFC 8628 3.5）. */
  val IntervalSeconds = 5
  val SlowDownSeconds = 5

  /**
   * 未完了の要求の上限（クライアントごと・全体）. 開始のエンドポイントは、認証のない公開クライアントからも、
   * 同じ IP の多くの端末からも呼ばれるので、IP ごとの回数では数えず、件数で DB があふれないようにする.
   * 全体の上限は、user_code の当てずっぽう（20^8 通りのうち未完了の件数だけが当たり）の確率も抑える.
   */
  val MaxPendingPerApp = 500
  val MaxPendingTotal = 5000

  /** 誤った user_code の入力の上限（利用者ごと・IP ごと. FailureWindowSeconds の間）. 総当たりへの対策. */
  val MaxUserFailures = 10
  val MaxIpFailures = 30
  val FailureWindowSeconds = 15L * 60

  private val rnd = new java.security.SecureRandom()
  def newUserCode(): String = UserCodes.generate(rnd)
}

/**
 * デバイスフロー（RFC 8628. Device Authorization Grant）: 端末からの開始（/oauth2/device_authorization）と、
 * 利用者がブラウザで行う確認（/device の画面: user_code の入力 → ログイン・利用の制限の確認 → 許可／拒否）.
 * 端末からのポーリング（トークンの発行）は OidcRoutes のトークンのエンドポイント.
 */
final class DeviceRoutes(protected val apps: AppStore,
                         devices: DeviceStore,
                         tokens: TokenStore,
                         factors: FactorStore,
                         gate: AuthGate,
                         val auth: SessionAuth,
                         audit: AuditService,
                         protected val cfg: ApiConfig) extends RouteSupport with OAuthEndpoint {

  val routes: HttpRoutes[IO] = HttpRoutes.of[IO] {
    case req @ POST -> Root / "oauth2" / "device_authorization" => postOauth2DeviceAuthorization(req)
    case req @ POST -> Root / "api" / "device" / "verify" => postDeviceVerify(req)
    case req @ POST -> Root / "api" / "device" / "decide" => postDeviceDecide(req)
  }

  private def postOauth2DeviceAuthorization(req: Request[IO]): IO[Response[IO]] =
    cors(here(start(req)))

  private def postDeviceVerify(req: Request[IO]): IO[Response[IO]] =
    csrf(req)(body[DeviceVerifyReq](req)(r => here(verify(req, r))))

  private def postDeviceDecide(req: Request[IO]): IO[Response[IO]] =
    csrf(req)(body[ConsentReq](req)(r => here(decide(req, r))))

  // ------------------------------------------------------------------ 端末からの開始

  /** 端末からの開始（RFC 8628 3.1・3.2）. クライアントの認証はトークンのエンドポイントと同じ（公開クライアントは client_id だけ）. */
  private def start(req: Request[IO])(using Here): IO[Response[IO]] =
    params(req).flatMap { f =>
      clientAuth(req, f).flatMap {
        case Left(e) => oauthErr(e)
        case Right((app, c)) =>
          val requested = scopeList(f.getOrElse("scope", ""))
          val scopes = requested.filter(c.scopes.contains)
          if !c.grantTypes.contains(OAuthGrants.DeviceCode) then
            oauthErr(OAuthError("unauthorized_client", "このクライアントではデバイスフローを使えません"))
          else if requested.nonEmpty && scopes.isEmpty then oauthErr(OAuthError("invalid_scope", "使えるスコープがありません"))
          else create(req, app, scopes, 5)
      }
    }

  private def create(req: Request[IO], app: Application, scopes: List[String], attempts: Int)(using
    h: Here): IO[Response[IO]] =
    Time.now.flatMap { now =>
      // device_code は十分に長い乱数（256 ビット）. DB にはハッシュだけを残す
      val deviceCode = Crypto.randomToken()
      devices.create(
        Crypto.sha256(deviceCode),
        DeviceFlow.newUserCode(),
        app.id,
        scopes,
        h.domain,
        DeviceFlow.IntervalSeconds,
        now.plusSeconds(DeviceFlow.TtlSeconds),
        now,
        DeviceFlow.MaxPendingPerApp,
        DeviceFlow.MaxPendingTotal
      ).flatMap {
        case Left(DeviceCreateError.Collision) if attempts > 1 => create(req, app, scopes, attempts - 1)
        case Left(DeviceCreateError.Collision) =>
          sbirds.observe.Log.report(ErrorCode.DeviceCodeCollision, app.slug) *>
            oauthErr(OAuthError("server_error", "コードを作れませんでした", Status.InternalServerError))
        case Left(DeviceCreateError.TooMany) =>
          sbirds.observe.Log.report(ErrorCode.DevicePendingLimit, app.slug) *>
            oauthErr(OAuthError(
              "temporarily_unavailable",
              "確認待ちの要求が多すぎます。しばらくしてからお試しください",
              Status.TooManyRequests
            )).map(_.putHeaders("Retry-After" -> "60"))
        case Right(d) =>
          val userCode = UserCodes.format(d.userCode)
          ctx(req).flatMap(c =>
            audit.log(
              c,
              None,
              "oidc",
              "device.start",
              audit.appTarget(app),
              detail = Json.obj("scopes" -> scopes.asJson)
            )
          ) *>
            json(Json.obj(
              "device_code" -> deviceCode.asJson,
              "user_code" -> userCode.asJson,
              // 確認の画面は、要求を受けたホスト名のもの（マルチドメイン）
              "verification_uri" -> s"$iss/device".asJson,
              "verification_uri_complete" -> s"$iss/device?user_code=$userCode".asJson,
              "expires_in" -> DeviceFlow.TtlSeconds.asJson,
              "interval" -> d.intervalSeconds.asJson
            ))
      }
    }

  // ------------------------------------------------------------------ 利用者の確認

  /** 確認の画面では、再認証・アカウントの選択は求めない（ログイン・IP 制限・利用できるグループ・多要素認証は AuthGate が見る）. */
  private val opts = GateOpts(forceLogin = false, passive = false, maxAge = None, selectAccount = false)

  private val Expired = "端末の要求の有効期限が切れたか、すでに処理されています。端末で最初からやり直してください"

  /**
   * user_code の入力. ログインした利用者だけが試せて、誤った入力は利用者ごと・IP ごとに数える（総当たりへの対策）.
   * 合っていれば認可の要求（protocol = device）を作り、通常の認可と同じ流れ（/auth/resume → AuthGate）へ進む.
   */
  private def verify(req: Request[IO], r: DeviceVerifyReq)(using h: Here): IO[Response[IO]] =
    auth.activeFor(req).flatMap {
      case None => err(ErrorCode.NotLoggedIn)
      case Some((bs, _, u)) =>
        (ctx(req), Time.now).flatMapN {
          (c, now) =>
            val since = now.minusSeconds(DeviceFlow.FailureWindowSeconds)
            val limits = List(
              s"device:user:${u.id}" -> DeviceFlow.MaxUserFailures,
              "device:ip:" + IpRules.throttleKey(c.ip) -> DeviceFlow.MaxIpFailures
            )
            def refused(reason: String) =
              audit.log(
                c,
                Some(u),
                "web",
                "device.verify",
                success = false,
                detail = Json.obj("reason" -> reason.asJson)
              )
            limits.existsM((k, max) => factors.throttleCount(k, since).map(_ >= max)).flatMap {
              case true => refused("throttled") *> err(ErrorCode.DeviceTooManyAttempts)
              case false =>
                UserCodes.normalize(r.userCode).flatTraverse(devices.byUserCode(_, h.domain, now)).flatMap {
                  case None =>
                    limits.traverse_((k, _) => factors.throttleFail(k, since)) *> refused("user_code") *>
                      err(ErrorCode.DeviceCodeInvalid)
                  case Some(d) =>
                    tokens.createRequest(
                      d.appId,
                      DeviceRoutes.Protocol,
                      Json.obj(
                        "device" -> d.id.asJson,
                        "scope" -> d.scopes.mkString(" ").asJson,
                        "user_code" -> UserCodes.format(d.userCode).asJson,
                        // コードを入力したブラウザ・利用者に結び付ける（要求の ID を知る他人のブラウザに持ち越せないように）
                        "verifiedBy" -> AuthRequests.mark(bs.id, u.id)
                      ),
                      d.expiresAt,
                      h.domain
                    ).flatMap(ar => Ok(RedirectDto(s"/auth/resume?req=${ar.id}")))
                }
            }
        }
    }

  /** 認可の要求が指す、未完了のデバイスフローの要求と、そのアプリケーション（このグラントを選んだクライアントだけ）. */
  private def pending(r: AuthRequest): IO[Option[(DeviceCode, Application)]] =
    (
      r.params.hcursor.get[UUID]("device").toOption.flatTraverse(devices.find),
      apps.find(r.appId),
      apps.oidc(r.appId),
      Time.now
    ).mapN {
      (d, app, c, now) =>
        (d.filter(x => x.status == "pending" && x.expiresAt.isAfter(now) && x.appId == r.appId), app)
          .tupled.filter(_ => c.exists(_.grantTypes.contains(OAuthGrants.DeviceCode)))
    }

  /**
   * user_code の入力・ログイン（多要素認証の追加を含む）の後に来る. 通常の認可と同じ判定（AuthGate）を通ったら、
   * 許可／拒否の画面へ. verification_uri_complete で来たときも、この画面は省かない（フィッシング対策. RFC 8628 5.4）.
   */
  def resume(req: Request[IO], r: AuthRequest): IO[Response[IO]] =
    pending(r).flatMap {
      case None => tokens.deleteRequest(r.id) *> gate.errorPage(Expired)
      case Some((_, app)) =>
        gate.check(req, r, app, opts).flatMap {
          case Gate.Interact(path, _) => gate.redirect(path)
          case Gate.Deny(_, msg) => tokens.deleteRequest(r.id) *> gate.errorPage(msg)
          // コードを入力したのと別のアカウントに切り替わっていたら、コードの入力からやり直す
          case Gate.Proceed(bs, _, user, _) if !AuthRequests.markedBy(r, "verifiedBy", bs, user.id) =>
            tokens.deleteRequest(r.id) *> gate.redirect("/device")
          case Gate.Proceed(_, _, _, _) => gate.redirect(s"/device?req=${r.id}")
        }
    }

  /** 許可／拒否. 許可は、もう一度 AuthGate を通してから記録する（画面を開いた後に条件が変わっていないか）. */
  private def decide(req: Request[IO], r: ConsentReq)(using h: Here): IO[Response[IO]] =
    auth.activeFor(req).flatMap {
      case None => err(ErrorCode.NotLoggedIn)
      case Some((bs, login, u)) =>
        Time.now.flatMap(now => tokens.request(r.requestId, now)).map(
          // 要求を受けたドメインでだけ. コードを入力したブラウザ・利用者だけ
          _.filter(ar =>
            ar.protocol == DeviceRoutes.Protocol && ar.domain == h.domain &&
              AuthRequests.markedBy(ar, "verifiedBy", bs, u.id)
          )
        ).flatMap(_.flatTraverse(ar => pending(ar).map(_.map((d, app) => (ar, d, app))))).flatMap {
          case None => err(ErrorCode.DeviceRequestExpired)
          case Some((ar, d, app)) =>
            def record(approve: Boolean) =
              Time.now.flatMap(now => devices.decide(d.id, approve, u.id, login.id, login.authTime, login.amr, now))
                .flatMap {
                  case false => err(ErrorCode.DeviceRequestExpired)
                  case true =>
                    tokens.deleteRequest(ar.id) *> ctx(req).flatMap(c =>
                      audit.log(
                        c,
                        Some(u),
                        "web",
                        if approve then "device.approve" else "device.deny",
                        audit.appTarget(app),
                        detail = Json.obj("scopes" -> d.scopes.asJson)
                      )
                    ) *> Ok(RedirectDto("/device?done=" + (if approve then "approved" else "denied")))
                }
            if !r.approve then record(false)
            else
              gate.check(req, ar, app, opts).flatMap {
                case Gate.Proceed(_, _, _, _) => record(true)
                case Gate.Interact(path, _) => Ok(RedirectDto(path))
                case Gate.Deny(_, msg) => tokens.deleteRequest(ar.id) *> err(ErrorCode.DeviceNotAllowed, msg)
              }
        }
    }
}

object DeviceRoutes {

  /** 認可の要求（auth_requests）の種類. /auth/resume が DeviceRoutes.resume に渡す. */
  val Protocol = "device"
}
