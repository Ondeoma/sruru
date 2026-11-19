package sruru.api

import sbirds.http.Errors
import sbirds.shared.AppError

import cats.effect.*
import io.circe.{Decoder, Encoder, Json}
import org.http4s.*
import org.http4s.circe.CirceEntityCodec.*
import org.http4s.dsl.Http4sDsl
import org.typelevel.ci.CIString
import sruru.core.*

import java.util.UUID

/**
 * *Routes に共通の補助（エラー応答・認証・リクエスト本文）.
 */
trait RouteSupport extends Http4sDsl[IO] {
  protected def auth: SessionAuth

  /** エラーの応答（コード付きでログに出る. キャッシュさせない）. detail を省くとコードの既定の文言. */
  protected def err(
    code: ErrorCode,
    detail: String | Null = null
  ): IO[Response[IO]] = fail(AppError(code, Option(detail)))

  /** 直近のログインが必要なとき（ReauthRequired）は、画面がログインの画面へ移るよう X-Sruru-Reauth を付ける. */
  protected def fail(
    e: AppError
  ): IO[Response[IO]] =
    Errors.respond(e).map { r =>
      val r2 = r.putHeaders("Cache-Control" -> "no-store")
      if (e.code == ErrorCode.ReauthRequired) r2.putHeaders("X-Sruru-Reauth" -> "1") else r2
    }

  protected def respond[A](
    r: Res[A]
  )(
    f: A => IO[Response[IO]]
  ): IO[Response[IO]] = r.flatMap(_.fold(fail, f))

  protected def okJson[A: Encoder](
    r: Res[A]
  ): IO[Response[IO]] = respond(r)(a => Ok(a).map(_.putHeaders("Cache-Control" -> "no-store")))

  protected def noContent(
    r: Res[Unit]
  ): IO[Response[IO]] = respond(r)(_ => NoContent())

  /** 本文を読む（読めなければ 400）. */
  protected def body[A: Decoder](
    req: Request[IO]
  )(
    f: A => IO[Response[IO]]
  ): IO[Response[IO]] =
    req.as[Json].attempt.flatMap {
      case Left(e) if tooLarge(e) => err(ErrorCode.RequestTooLarge)
      case Left(_) => err(ErrorCode.JsonBodyUnreadable)
      case Right(j) =>
        j.as[A] match {
          case Left(e) => err(ErrorCode.RequestBodyInvalid, s"本文の形式が正しくありません: ${e.getMessage.take(200)}")
          case Right(a) => f(a)
        }
    }

  /** 本文の大きさの上限（Main の EntityLimiter）を超えたか. */
  private def tooLarge(
    e: Throwable
  ): Boolean =
    Iterator.iterate(e)(
      _.getCause
    ).takeWhile(_ != null).take(10).exists(_.isInstanceOf[org.http4s.server.middleware.EntityLimiter.EntityTooLarge])

  protected def ctx(
    req: Request[IO]
  ): IO[ReqCtx] = auth.reqCtx(req)

  /** ログインしていなければ 401. 更新系を read スコープのトークンで送ったら 403. 画面からの更新系は CSRF 対策のヘッダーが必要. */
  protected def authed(
    req: Request[IO]
  )(
    f: Principal => IO[Response[IO]]
  ): IO[Response[IO]] =
    auth.principal(req).flatMap {
      case None => err(ErrorCode.NotLoggedIn)
      case Some(p) =>
        // 操作したユーザーを、トレース（スパンの属性）とこの中のログに載せる
        sbirds.observe.Telemetry.withUser(p.id.toString, p.user.username) {
          val write = !Set(Method.GET, Method.HEAD, Method.OPTIONS).contains(req.method)
          if write && !p.canWrite then err(ErrorCode.TokenNeedsWrite)
          else if !write && !p.canRead then err(ErrorCode.TokenNeedsRead)
          else if write && p.via.isInstanceOf[Via.Web] && req.headers.get(CIString("X-Sruru")).isEmpty then
            err(ErrorCode.CsrfHeaderMissing)
          else f(p)
        }
    }

  /**
   * 画面（Cookie）からだけ使える操作. 認証の要素・メールアドレス・パスワードなど、アカウントの乗っ取りにつながる変更は
   * 漏れた API トークンでは行えないようにする.
   */
  protected def webOnly(
    req: Request[IO]
  )(
    f: Principal => IO[Response[IO]]
  ): IO[Response[IO]] =
    authed(req)(p =>
      if p.via.isInstanceOf[Via.Web] then f(p) else err(ErrorCode.UiOnly)
    )

  /**
   * 本人の重要な変更（メールアドレス・多要素認証・回復コード・証明書・API トークン）: 画面から、直近にログインしたときだけ.
   * 盗まれた Cookie だけでは、乗っ取りを長引かせる変更をさせない.
   */
  protected def recentAuth(
    req: Request[IO]
  )(
    f: Principal => IO[Response[IO]]
  ): IO[Response[IO]] =
    webOnly(req)(p =>
      Time.now.flatMap(now => if RecentAuth.recent(p, now) then f(p) else fail(AppError(ErrorCode.ReauthRequired)))
    )

  /** 管理者の操作のうち、アカウントの乗っ取りにつながるもの（パスワード・多要素認証・証明書・トークン）. API トークンでは使えない. */
  protected def adminWeb(
    req: Request[IO]
  )(
    f: Principal => IO[Response[IO]]
  ): IO[Response[IO]] =
    admin(req)(p =>
      if p.via.isInstanceOf[Via.Web] then f(p) else err(ErrorCode.UiOnly)
    )

  /** 管理者のみ（トークンは admin スコープ. 管理画面の IP 制限も確かめる）. */
  protected def admin(
    req: Request[IO]
  )(
    f: Principal => IO[Response[IO]]
  ): IO[Response[IO]] =
    authed(req) { p =>
      if !p.canAdmin then err(ErrorCode.AdminOnly)
      else auth.adminIpAllowed(req).ifM(f(p), err(ErrorCode.AdminIpDenied))
    }

  /** 監査ログに書く（要求元はこの要求から）. */
  protected def audited(
    a: AuditService,
    req: Request[IO],
    p: Principal,
    action: String,
    target: Option[(String, String, String)] = None,
    detail: Json = Json.obj()
  ): IO[Unit] =
    ctx(req).flatMap(c => a.byPrincipal(c, p, action, target, detail = detail))

  protected def uuidParam(
    s: String
  ): Option[UUID] = scala.util.Try(UUID.fromString(s)).toOption

  object UuidVar {
    def unapply(
      s: String
    ): Option[UUID] = scala.util.Try(UUID.fromString(s)).toOption
  }

  protected def q(
    req: Request[IO],
    name: String
  ): Option[String] = req.params.get(name).map(_.trim).filter(_.nonEmpty)
  protected def qInt(
    req: Request[IO],
    name: String,
    default: Int,
    max: Int
  ): Int =
    q(req, name).flatMap(_.toIntOption).map(n => math.max(0, math.min(n, max))).getOrElse(default)
}
