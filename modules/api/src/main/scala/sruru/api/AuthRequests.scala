package sruru.api

import io.circe.Json
import sruru.db.*

import java.time.Instant
import java.util.UUID

/** 要求の有効期限. */
object AuthRequests {
  val TtlSeconds = 30L * 60
  def expires(now: Instant): Instant = now.plusSeconds(TtlSeconds)

  /**
   * 要求に付ける印（同意した・アカウントを選んだ）. ブラウザのセッションとユーザーに結び付けて、
   * 要求の ID を知る他人のブラウザや、同じブラウザの別のアカウントに持ち越せないようにする.
   */
  def mark(bs: UUID, user: UUID): Json = Json.fromString(s"$bs:$user")

  def markedBy(r: AuthRequest, key: String, bs: BrowserSession, user: UUID): Boolean =
    r.params.hcursor.get[String](key).toOption.contains(s"${bs.id}:$user")
}
