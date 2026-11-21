package sruru.api

import sbirds.db.*
import sbirds.shared.AppError

import cats.effect.*
import org.http4s.*
import sruru.core.*
import sruru.db.*
import sruru.shared.*

import java.time.Instant
import java.util.UUID
import scala.concurrent.duration.*

final case class ApiConfig(publicUrl: String,
                           cookieSecure: Boolean,
                           version: String = "0.1.0",
                           cookieName: String = "sruru_session",
                           maxAvatarBytes: Int = 512 * 1024,
                           devMode: Boolean = false,
                           mailEnabled: Boolean = false,
                           nodeId: String = "node",
                           oauthClients: List[OAuthClient] = Nil,
                           /** マジックリンクの有効期限（分） */
                           magicLinkMinutes: Int = 15) {

  private val scheme = publicUrl.takeWhile(_ != ':')

  /** ドメイン（ホスト名. 既定なら空）の公開 URL（末尾の / なし）. スキームは PUBLIC_URL と同じ. */
  def urlOf(domain: String): String = if domain.isEmpty then publicUrl else s"$scheme://$domain"

  /** この要求のホスト名の公開 URL（OIDC の issuer・各種のリンクの元）. 要求の外では PUBLIC_URL. */
  def url: IO[String] = Site.host.map(urlOf)

  def here: IO[Here] = Site.host.map(d => Here(urlOf(d), d))
}

/** サーバーで組み立てる HTML の画面. */
object Html {
  def escape(s: String): String =
    s.replace("&", "&amp;").replace("\"", "&quot;").replace("<", "&lt;").replace(">", "&gt;").replace("'", "&#39;")

  /** HTML の応答（CirceEntityCodec の import があっても JSON の文字列にしないよう、Encoder を明示する）. */
  def response(html: String, csp: String, status: Status = Status.Ok): Response[IO] =
    Response[IO](status).withEntity(html)(using EntityEncoder.stringEncoder).withContentType(headers.`Content-Type`(
      MediaType.text.html,
      Charset.`UTF-8`
    ))
      .putHeaders("Content-Security-Policy" -> csp, "Cache-Control" -> "no-store")
}

/** 処理の結果（失敗は AppError: エラーコードと文言）. */
type Res[A] = IO[Either[AppError, A]]

object Res {
  def ok[A](a: A): Res[A] = IO.pure(Right(a))
  def fail[A](e: AppError): Res[A] = IO.pure(Left(e))
  def fail[A](code: ErrorCode, detail: String | Null = null): Res[A] = IO.pure(Left(AppError(code, Option(detail))))
  def fromOption[A](o: Option[A], f: => AppError): Either[AppError, A] = o.toRight(f)
}

/** 直近のログイン（本人の重要な変更の前に求める）. */
object RecentAuth {
  val Seconds = 600L
  val Message = "本人確認のため、もう一度ログインしてください"
  def recent(p: Principal, now: java.time.Instant): Boolean =
    p.via.isInstanceOf[Via.Web] && p.login.exists(_.authTime.isAfter(now.minusSeconds(Seconds)))
}

/** 要求元（監査ログ・IP 制限に使う）. */
final case class ReqCtx(ip: String, userAgent: Option[String])

object ReqCtx {
  val system: ReqCtx = ReqCtx("-", None)
}

/** API の利用者の認証の経路. */
enum Via {
  case Web(
    browser: BrowserSession,
    login: Login)
  case Token(
    id: UUID,
    scopes: Set[String],
    mcp: Boolean)

  def label: String = this match {
    case Web(_, _) => "web"
    case Token(_, _, true) => "mcp"
    case Token(_, _, false) => "api"
  }
}

/** 認証済みの利用者. isAdmin はグループによる管理者を含む. */
final case class Principal(user: User, membership: Membership, isAdmin: Boolean, via: Via) {
  def id: UUID = user.id
  def canRead: Boolean = via match {
    case Via.Token(_, s, _) => s.contains(TokenScopes.Read) || s.contains(TokenScopes.Write) ||
      s.contains(TokenScopes.Admin)
    case _ => true
  }
  def canWrite: Boolean = via match {
    case Via.Token(_, s, _) => s.contains(TokenScopes.Write) || s.contains(TokenScopes.Admin)
    case _ => true
  }

  /** 管理 API（管理者で、トークンなら admin スコープ）. */
  def canAdmin: Boolean = isAdmin &&
    (via match {
      case Via.Token(_, s, _) => s.contains(TokenScopes.Admin)
      case _ => true
    })
  def canScim: Boolean = isAdmin &&
    (via match {
      case Via.Token(_, s, _) => s.contains(TokenScopes.Scim) || s.contains(TokenScopes.Admin)
      case _ => false
    })
  def login: Option[Login] = via match {
    case Via.Web(_, l) => Some(l)
    case _ => None
  }
}

/** 時間. */
object Time {
  def now: IO[Instant] = IO.realTimeInstant
}

/** 定期処理（失敗しても止めない）. */
object Loops {
  def every(initial: FiniteDuration, interval: FiniteDuration, code: ErrorCode)(action: IO[Unit]): IO[Nothing] =
    Periodic.run(initial, interval, code)(action)
}
