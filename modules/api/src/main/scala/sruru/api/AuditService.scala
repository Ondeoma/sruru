package sruru.api

import cats.effect.*
import cats.syntax.all.*
import io.circe.Json
import sruru.core.*
import sruru.db.*

import java.util.UUID

/**
 * 監査ログの書き込み. 認証・アカウントの出来事はすべてここを通るので、業務のメトリクス（AuditMetrics）と、
 * 本人へのプッシュ通知（アカウントの安全にかかわる出来事）もここで出す.
 */
final class AuditService(
  store: AuditStore,
  push: Option[sbirds.push.PushService] = None) {
  def log(
    c: ReqCtx,
    actor: Option[User],
    via: String,
    action: String,
    target: Option[(String, String, String)] = None,
    success: Boolean = true,
    detail: Json = Json.obj()
  ): IO[Unit] =
    store.append(AuditEntry(
      actor.map(_.id),
      actor.map(_.username),
      via,
      action,
      target.map(_._1),
      target.map(_._2),
      target.map(_._3),
      Some(c.ip),
      c.userAgent,
      success,
      detail
    )).void.handleErrorWith(e => sbirds.observe.Log.report(ErrorCode.AuditWriteFailed, "", e)) *>
      AuditMetrics.record(action, via, success, detail) *>
      IO.whenA(success)(notifyUser(action, target))

  /** 本人へのプッシュ通知（PWA）. 秘密の値（コード・リンク）は載せず、出来事と確かめる画面だけを知らせる. */
  private def notifyUser(
    action: String,
    target: Option[(String, String, String)]
  ): IO[Unit] =
    (
      push,
      target.collect { case ("user", id, _) => id }.flatMap(id => scala.util.Try(UUID.fromString(id)).toOption),
      AuditMetrics.alert(action)
    ).tupled
      .traverse_ { case (ps, uid, (title, body)) =>
        ps.send(uid, sbirds.push.PushMessage(title, body, "/me/security", Some(action))).start.void
      }

  def byPrincipal(
    c: ReqCtx,
    p: Principal,
    action: String,
    target: Option[(String, String, String)] = None,
    success: Boolean = true,
    detail: Json = Json.obj()
  ): IO[Unit] =
    log(c, Some(p.user), p.via.label, action, target, success, detail)

  def userTarget(
    u: User
  ): Option[(String, String, String)] = Some(("user", u.id.toString, u.username))
  def groupTarget(
    g: Group
  ): Option[(String, String, String)] = Some(("group", g.id.toString, g.name))
  def appTarget(
    a: Application
  ): Option[(String, String, String)] = Some(("application", a.id.toString, a.slug))
}
