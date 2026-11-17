package sruru.api

import cats.effect.*
import io.circe.{Decoder, Json}
import org.http4s.*
import org.http4s.circe.CirceEntityCodec.*
import org.typelevel.ci.CIString
import sruru.push.{PushService, PushStore, Subscription, WebPush}

/**
 * プッシュ通知（PWA）の購読. アカウントの安全にかかわる出来事（パスワードの変更・ロックなど. AuditService）を知らせる.
 *  - `GET /api/push`: VAPID の公開鍵と、自分の購読の数
 *  - `POST /api/push/subscriptions`（PushSubscription.toJSON() の形）: この端末で受け取る（画面からだけ）
 *  - `DELETE /api/push/subscriptions`（{"endpoint": …}）: この端末で受け取るのをやめる
 */
final class PushRoutes(store: PushStore, push: PushService, protected val auth: SessionAuth) extends RouteSupport:

  private final case class Keys(p256dh: String, auth: String) derives Decoder
  private final case class SubscribeReq(endpoint: String, keys: Keys) derives Decoder
  private final case class EndpointReq(endpoint: String) derives Decoder

  val routes: HttpRoutes[IO] = HttpRoutes.of[IO] {
    case req @ GET -> Root / "api" / "push" =>
      authed(req)(p => store.count(p.id).flatMap(n => Ok(Json.obj("publicKey" -> Json.fromString(push.publicKey), "subscriptions" -> Json.fromInt(n)))))

    case req @ POST -> Root / "api" / "push" / "subscriptions" =>
      webOnly(req)(p => body[SubscribeReq](req) { r =>
        if !WebPush.allowedEndpoint(r.endpoint) then err(Status.BadRequest, "このプッシュのサービスには送れません")
        else if r.keys.p256dh.length > 200 || r.keys.auth.length > 100 || r.endpoint.length > 2000 then err(Status.BadRequest, "購読の内容が正しくありません")
        else store.subscribe(p.id, Subscription(r.endpoint, r.keys.p256dh, r.keys.auth),
          req.headers.get(CIString("User-Agent")).map(_.head.value.take(300))) *> NoContent()
      })

    case req @ DELETE -> Root / "api" / "push" / "subscriptions" =>
      authed(req)(p => body[EndpointReq](req)(r => store.unsubscribe(p.id, r.endpoint) *> NoContent()))
  }
