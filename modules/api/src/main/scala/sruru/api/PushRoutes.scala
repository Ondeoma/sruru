package sruru.api

import sruru.core.ErrorCode

import cats.effect.*
import io.circe.Decoder
import org.http4s.*

import java.util.UUID

/**
 * プッシュ通知（PWA）の購読（sbirds.push.PushRoutes）. アカウントの安全にかかわる出来事（パスワードの変更・ロックなど. AuditService）を知らせる.
 * 端末の登録は画面からだけ.
 */
final class PushRoutes(store: sbirds.push.PushStore, push: sbirds.push.PushService, protected val auth: SessionAuth)
  extends RouteSupport { self =>

  private val host = new sbirds.push.PushRoutes.Host {
    def authed(req: Request[IO])(f: UUID => IO[Response[IO]]): IO[Response[IO]] = self.authed(req)(p => f(p.id))
    def interactive(req: Request[IO])(f: UUID => IO[Response[IO]]): IO[Response[IO]] = self.webOnly(req)(p => f(p.id))
    def body[A: Decoder](req: Request[IO])(f: A => IO[Response[IO]]): IO[Response[IO]] = self.body[A](req)(f)
  }

  val routes: HttpRoutes[IO] = new sbirds.push.PushRoutes(
    store,
    push,
    host,
    notAllowed = ErrorCode.PushServiceNotAllowed,
    invalid = ErrorCode.PushSubscriptionInvalid
  ).routes
}
