package sruru.api

import cats.effect.*
import cats.syntax.all.*
import io.circe.Json
import io.circe.syntax.*
import org.http4s.*
import org.http4s.client.Client
import sruru.core.*
import sruru.db.*
import sruru.security.*

import java.util.UUID
import scala.concurrent.duration.*

/** バックチャネルのログアウト（OpenID Connect Back-Channel Logout 1.0）. 失敗しても止めない（別のファイバーで送る）. */
final class LogoutNotifier(apps: AppStore, tokens: TokenStore, keys: KeyService, http: Client[IO], cfg: ApiConfig) {

  /** そのログイン（None ならそのユーザー）にトークンを出したアプリへ送る. */
  def send(u: User, loginId: Option[UUID]): IO[Unit] =
    (apps.allOidc, tokens.appsWithTokens(u.id, loginId)).mapN((cs, used) =>
      cs.filter(c => used(c.appId) && c.backchannelLogoutUri.isDefined)
    )
      .flatMap(_.traverse_ { c =>
        (apps.find(c.appId), Time.now).tupled.flatMap {
          case (Some(app), now) if app.enabled =>
            keys.active(c.signingAlg).flatMap { k =>
              val lt = Jose.sign(
                k,
                Json.obj(
                  "iss" -> cfg.issuer.asJson,
                  "aud" -> c.clientId.asJson,
                  "iat" -> now.getEpochSecond.asJson,
                  "exp" -> now.plusSeconds(120).getEpochSecond.asJson,
                  "jti" -> UUID.randomUUID().toString.asJson,
                  "sub" -> Claims.sub(u, c).asJson,
                  "sid" -> loginId.map(_.toString).asJson,
                  "events" -> Json.obj("http://schemas.openid.net/event/backchannel-logout" -> Json.obj())
                ),
                "logout+jwt"
              )
              val r = Request[IO](
                Method.POST,
                Uri.unsafeFromString(c.backchannelLogoutUri.get)
              ).withEntity(UrlForm("logout_token" -> lt))
              sbirds.observe.Telemetry.span("logout.backchannel", "client_id" -> c.clientId)(http.run(r).use(_ =>
                IO.unit
              ).timeout(5.seconds)) *>
                sbirds.observe.Metrics.count("sruru.logout.backchannel", "result" -> "sent")
            }.handleErrorWith(e =>
              sbirds.observe.Metrics.count("sruru.logout.backchannel", "result" -> "failed") *>
                sbirds.observe.Log.report(ErrorCode.BackchannelLogoutFailed, s"${c.clientId}: ${e.getMessage}", e)
            )
          case _ => IO.unit
        }
      }).start.void
}
