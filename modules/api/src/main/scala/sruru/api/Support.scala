package sruru.api

import cats.effect.*
import cats.syntax.all.*
import io.circe.{Decoder, Encoder, Json}
import org.http4s.*
import org.http4s.circe.CirceEntityCodec.*
import org.http4s.dsl.Http4sDsl
import org.typelevel.ci.CIString
import sruru.core.*
import sruru.db.*
import sruru.shared.*

import java.time.Instant
import java.util.UUID
import scala.concurrent.duration.*

final case class ApiConfig(
    publicUrl: String,
    cookieSecure: Boolean,
    version: String = "0.1.0",
    cookieName: String = "sruru_session",
    maxAvatarBytes: Int = 512 * 1024,
    devMode: Boolean = false,
    mailEnabled: Boolean = false,
    nodeId: String = "node"
):
  /** OIDC の issuer（末尾の / なし）. */
  def issuer: String = publicUrl

/** 処理の失敗（HTTP の応答に変換する）. */
enum Fail:
  case NotFound(msg: String)
  case Forbidden(msg: String)
  case Invalid(msg: String)
  case Conflict(msg: String)
  case Unauthorized(msg: String)
  case TooMany(msg: String)
  /** 直近のログインが必要（画面はログインの画面へ移って、もう一度ログインしてもらう）. */
  case Reauth(msg: String)

  def message: String = this match
    case NotFound(m)     => m
    case Forbidden(m)    => m
    case Invalid(m)      => m
    case Conflict(m)     => m
    case Unauthorized(m) => m
    case TooMany(m)      => m
    case Reauth(m)       => m

object Fail:
  def from(e: StoreError): Fail = e match
    case StoreError.NotFound(w) => Fail.NotFound(s"$w が見つかりません")
    case StoreError.Invalid(m)  => Fail.Invalid(m)
    case StoreError.Conflict(m) => Fail.Conflict(m)

type Res[A] = IO[Either[Fail, A]]

extension [A](io: IO[Either[StoreError, A]]) def orFail: Res[A] = io.map(_.left.map(Fail.from))

object Res:
  def ok[A](a: A): Res[A]                 = IO.pure(Right(a))
  def fail[A](f: Fail): Res[A]            = IO.pure(Left(f))
  def invalid[A](msg: String): Res[A]     = IO.pure(Left(Fail.Invalid(msg)))
  def notFound[A](msg: String): Res[A]    = IO.pure(Left(Fail.NotFound(msg)))
  def forbidden[A](msg: String): Res[A]   = IO.pure(Left(Fail.Forbidden(msg)))
  def fromOption[A](o: Option[A], f: => Fail): Either[Fail, A] = o.toRight(f)

/** 直近のログイン（本人の重要な変更の前に求める）. */
object RecentAuth:
  val Seconds = 600L
  val Message = "本人確認のため、もう一度ログインしてください"
  def recent(p: Principal, now: java.time.Instant): Boolean =
    p.via.isInstanceOf[Via.Web] && p.login.exists(_.authTime.isAfter(now.minusSeconds(Seconds)))

/** 要求元（監査ログ・IP 制限に使う）. */
final case class ReqCtx(ip: String, userAgent: Option[String])

object ReqCtx:
  val system: ReqCtx = ReqCtx("-", None)

/** API の利用者の認証の経路. */
enum Via:
  case Web(browser: BrowserSession, login: Login)
  case Token(id: UUID, scopes: Set[String], mcp: Boolean)

  def label: String = this match
    case Web(_, _)            => "web"
    case Token(_, _, true)    => "mcp"
    case Token(_, _, false)   => "api"

/** 認証済みの利用者. isAdmin はグループによる管理者を含む. */
final case class Principal(user: User, membership: Membership, isAdmin: Boolean, via: Via):
  def id: UUID = user.id
  def canRead: Boolean = via match
    case Via.Token(_, s, _) => s.contains(TokenScopes.Read) || s.contains(TokenScopes.Write) || s.contains(TokenScopes.Admin)
    case _                  => true
  def canWrite: Boolean = via match
    case Via.Token(_, s, _) => s.contains(TokenScopes.Write) || s.contains(TokenScopes.Admin)
    case _                  => true
  /** 管理 API（管理者で、トークンなら admin スコープ）. */
  def canAdmin: Boolean = isAdmin && (via match
    case Via.Token(_, s, _) => s.contains(TokenScopes.Admin)
    case _                  => true)
  def canScim: Boolean = isAdmin && (via match
    case Via.Token(_, s, _) => s.contains(TokenScopes.Scim) || s.contains(TokenScopes.Admin)
    case _                  => false)
  def login: Option[Login] = via match
    case Via.Web(_, l) => Some(l)
    case _             => None

/** *Routes に共通の補助（エラー応答・認証・リクエスト本文）. */
trait RouteSupport extends Http4sDsl[IO]:
  protected def auth: SessionAuth

  protected def err(status: Status, msg: String): IO[Response[IO]] =
    Response[IO](status).withEntity(ErrorDto(msg)).putHeaders("Cache-Control" -> "no-store").pure[IO]

  protected def fail(f: Fail): IO[Response[IO]] = f match
    case Fail.NotFound(m)     => err(Status.NotFound, m)
    case Fail.Forbidden(m)    => err(Status.Forbidden, m)
    case Fail.Invalid(m)      => err(Status.BadRequest, m)
    case Fail.Conflict(m)     => err(Status.Conflict, m)
    case Fail.Unauthorized(m) => err(Status.Unauthorized, m)
    case Fail.TooMany(m)      => err(Status.TooManyRequests, m)
    case Fail.Reauth(m)       => err(Status.Unauthorized, m).map(_.putHeaders("X-Sruru-Reauth" -> "1"))

  protected def respond[A](r: Res[A])(f: A => IO[Response[IO]]): IO[Response[IO]] = r.flatMap(_.fold(fail, f))

  protected def okJson[A: Encoder](r: Res[A]): IO[Response[IO]] = respond(r)(a => Ok(a).map(_.putHeaders("Cache-Control" -> "no-store")))

  protected def noContent(r: Res[Unit]): IO[Response[IO]] = respond(r)(_ => NoContent())

  /** 本文を読む（読めなければ 400）. */
  protected def body[A: Decoder](req: Request[IO])(f: A => IO[Response[IO]]): IO[Response[IO]] =
    req.as[Json].attempt.flatMap {
      case Left(e) if tooLarge(e) => err(Status.PayloadTooLarge, "送られたデータが大きすぎます")
      case Left(_) => err(Status.BadRequest, "JSON の本文を読めません")
      case Right(j) =>
        j.as[A] match
          case Left(e)  => err(Status.BadRequest, s"本文の形式が正しくありません: ${e.getMessage.take(200)}")
          case Right(a) => f(a)
    }

  /** 本文の大きさの上限（Main の EntityLimiter）を超えたか. */
  private def tooLarge(e: Throwable): Boolean =
    Iterator.iterate(e)(_.getCause).takeWhile(_ != null).take(10).exists(_.isInstanceOf[org.http4s.server.middleware.EntityLimiter.EntityTooLarge])

  protected def ctx(req: Request[IO]): IO[ReqCtx] = auth.reqCtx(req)

  /** ログインしていなければ 401. 更新系を read スコープのトークンで送ったら 403. 画面からの更新系は CSRF 対策のヘッダーが必要. */
  protected def authed(req: Request[IO])(f: Principal => IO[Response[IO]]): IO[Response[IO]] =
    auth.principal(req).flatMap {
      case None => err(Status.Unauthorized, "ログインしてください")
      case Some(p) =>
        val write = !Set(Method.GET, Method.HEAD, Method.OPTIONS).contains(req.method)
        if write && !p.canWrite then err(Status.Forbidden, "このトークンは参照専用です（write スコープが必要です）")
        else if !write && !p.canRead then err(Status.Forbidden, "このトークンでは使えません（read スコープが必要です）")
        else if write && p.via.isInstanceOf[Via.Web] && req.headers.get(CIString("X-Sruru")).isEmpty then
          err(Status.Forbidden, "不正な要求です（X-Sruru ヘッダーがありません）")
        else f(p)
    }

  /**
   * 画面（Cookie）からだけ使える操作. 認証の要素・メールアドレス・パスワードなど、アカウントの乗っ取りにつながる変更は
   * 漏れた API トークンでは行えないようにする.
   */
  protected def webOnly(req: Request[IO])(f: Principal => IO[Response[IO]]): IO[Response[IO]] =
    authed(req)(p => if p.via.isInstanceOf[Via.Web] then f(p) else err(Status.Forbidden, "この操作は画面から行ってください（API トークンでは使えません）"))

  /**
   * 本人の重要な変更（メールアドレス・多要素認証・回復コード・証明書・API トークン）: 画面から、直近にログインしたときだけ.
   * 盗まれた Cookie だけでは、乗っ取りを長引かせる変更をさせない.
   */
  protected def recentAuth(req: Request[IO])(f: Principal => IO[Response[IO]]): IO[Response[IO]] =
    webOnly(req)(p => Time.now.flatMap(now => if RecentAuth.recent(p, now) then f(p) else fail(Fail.Reauth(RecentAuth.Message))))

  /** 管理者の操作のうち、アカウントの乗っ取りにつながるもの（パスワード・多要素認証・証明書・トークン）. API トークンでは使えない. */
  protected def adminWeb(req: Request[IO])(f: Principal => IO[Response[IO]]): IO[Response[IO]] =
    admin(req)(p => if p.via.isInstanceOf[Via.Web] then f(p) else err(Status.Forbidden, "この操作は画面から行ってください（API トークンでは使えません）"))

  /** 管理者のみ（トークンは admin スコープ. 管理画面の IP 制限も確かめる）. */
  protected def admin(req: Request[IO])(f: Principal => IO[Response[IO]]): IO[Response[IO]] =
    authed(req) { p =>
      if !p.canAdmin then err(Status.Forbidden, "管理者だけが使えます")
      else auth.adminIpAllowed(req).ifM(f(p), err(Status.Forbidden, "この IP アドレスからは管理機能を使えません"))
    }

  /** 監査ログに書く（要求元はこの要求から）. */
  protected def audited(a: AuditService, req: Request[IO], p: Principal, action: String, target: Option[(String, String, String)] = None,
      detail: Json = Json.obj()): IO[Unit] =
    ctx(req).flatMap(c => a.byPrincipal(c, p, action, target, detail = detail))

  protected def uuidParam(s: String): Option[UUID] = scala.util.Try(UUID.fromString(s)).toOption

  object UuidVar:
    def unapply(s: String): Option[UUID] = scala.util.Try(UUID.fromString(s)).toOption

  protected def q(req: Request[IO], name: String): Option[String] = req.params.get(name).map(_.trim).filter(_.nonEmpty)
  protected def qInt(req: Request[IO], name: String, default: Int, max: Int): Int =
    q(req, name).flatMap(_.toIntOption).map(n => math.max(0, math.min(n, max))).getOrElse(default)

/** 時間. */
object Time:
  def now: IO[Instant] = IO.realTimeInstant

/** 設定（ポリシー）の控え. 5秒ごとに DB から読み直す（ほかのノードでの変更も数秒で反映される）. */
final class PolicyService(settings: SettingsStore, cache: Ref[IO, Option[(Long, PoliciesDto)]]):
  def get: IO[PoliciesDto] =
    (cache.get, IO.monotonic).flatMapN { (c, now) =>
      c match
        case Some((at, p)) if now.toMillis - at < 5000 => IO.pure(p)
        case _ => settings.getAs[PoliciesDto]("policies", PoliciesDto()).flatTap(p => cache.set(Some(now.toMillis -> p)))
    }

  def put(p: PoliciesDto): IO[Unit] = settings.put("policies", p) *> cache.set(None)

object PolicyService:
  def create(settings: SettingsStore): IO[PolicyService] = Ref.of[IO, Option[(Long, PoliciesDto)]](None).map(new PolicyService(settings, _))

/** 監査ログの書き込み. */
final class AuditService(store: AuditStore):
  def log(c: ReqCtx, actor: Option[User], via: String, action: String, target: Option[(String, String, String)] = None,
      success: Boolean = true, detail: Json = Json.obj()): IO[Unit] =
    store.append(AuditEntry(actor.map(_.id), actor.map(_.username), via, action, target.map(_._1), target.map(_._2), target.map(_._3),
      Some(c.ip), c.userAgent, success, detail)).void.handleErrorWith(e => IO.println(s"[sruru] audit write failed: $e"))

  def byPrincipal(c: ReqCtx, p: Principal, action: String, target: Option[(String, String, String)] = None, success: Boolean = true,
      detail: Json = Json.obj()): IO[Unit] =
    log(c, Some(p.user), p.via.label, action, target, success, detail)

  def userTarget(u: User): Option[(String, String, String)] = Some(("user", u.id.toString, u.username))
  def groupTarget(g: Group): Option[(String, String, String)] = Some(("group", g.id.toString, g.name))
  def appTarget(a: Application): Option[(String, String, String)] = Some(("application", a.id.toString, a.slug))

/** 定期処理（失敗しても止めない）. */
object Loops:
  def every(initial: FiniteDuration, interval: FiniteDuration, name: String)(action: IO[Unit]): IO[Nothing] =
    Periodic.run(initial, interval)(e => s"[sruru] $name failed: $e")(action)
