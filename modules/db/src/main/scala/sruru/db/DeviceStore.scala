package sruru.db

import sbirds.db.*
import cats.effect.*
import cats.syntax.all.*
import doobie.*
import doobie.implicits.*
import doobie.postgres.implicits.*
import doobie.postgres.sqlstate

import java.time.Instant
import java.util.UUID

/** デバイスフロー（RFC 8628）の要求. userCode はハイフンなしの 8 文字. */
final case class DeviceCode(id: UUID,
                            userCode: String,
                            appId: UUID,
                            scopes: List[String],
                            /** 要求を受けたドメイン（既定のホスト名なら空）. 確認もトークンの発行も同じドメインでだけ */
                            domain: String,
                            intervalSeconds: Int,
                            lastPollAt: Option[Instant],
                            status: String,
                            userId: Option[UUID],
                            loginId: Option[UUID],
                            authTime: Option[Instant],
                            amr: List[String],
                            createdAt: Instant,
                            expiresAt: Instant,
                            usedAt: Option[Instant])

/** 作れなかった理由. */
enum DeviceCreateError {

  /** 未完了の要求が上限に達している（クライアントごと・全体）. */
  case TooMany

  /** user_code が重なった（作り直して、もう一度）. */
  case Collision
}

/** device_code でのポーリングの結果. */
enum DevicePoll {

  /** 見つからない（別のクライアント・別のドメインのものも「ない」ものとして扱う）. */
  case Unknown
  case Expired

  /** 間隔より早いポーリング. 以後の間隔（延ばした後の秒数）. */
  case SlowDown(
    interval: Int)
  case Pending
  case Denied

  /** 許可済み. この呼び出しで使用済みにした（1回だけ）. */
  case Approved(
    d: DeviceCode)

  /** すでにトークンを発行した device_code の再利用. */
  case Reused(
    d: DeviceCode)
}

/** デバイスフローの要求（device_code・user_code）. */
final class DeviceStore(xa: Transactor[IO]) extends TxStore(xa) {

  private val cols =
    fr"id, user_code, app_id, scopes, domain, interval_seconds, last_poll_at, status, user_id, login_id, auth_time, amr, created_at, expires_at, used_at"

  /**
   * 要求を作る. 未完了（許可も拒否もされておらず、期限内）の要求が、そのクライアントで maxPerApp 件・全体で maxTotal 件に
   * 達していれば作らない（認証のない公開クライアントからも呼べるので、DB があふれないように）.
   */
  def create(hash: Array[Byte],
             userCode: String,
             appId: UUID,
             scopes: List[String],
             domain: String,
             intervalSeconds: Int,
             expiresAt: Instant,
             now: Instant,
             maxPerApp: Int,
             maxTotal: Int): IO[Either[DeviceCreateError, DeviceCode]] = {
    val d = DeviceCode(
      UUID.randomUUID(),
      userCode,
      appId,
      scopes,
      domain,
      intervalSeconds,
      None,
      "pending",
      None,
      None,
      None,
      Nil,
      now,
      expiresAt,
      None
    )
    val pending = fr"from device_codes where status = 'pending' and expires_at > $now"
    val insert =
      // 期限の切れた行（掃除の前）が同じ user_code を持っていたら、先に消す
      sql"delete from device_codes where user_code = $userCode and expires_at <= $now".update.run *>
        sql"""insert into device_codes (id, device_code_hash, user_code, app_id, scopes, domain, interval_seconds, created_at, expires_at)
              values (${d.id}, $hash, $userCode, $appId, ${scopes.toArray}, $domain, $intervalSeconds, $now, $expiresAt)""".update.run
    tx(
      (
        (fr"select count(*)" ++ pending ++ fr"and app_id = $appId").query[Int].unique,
        (fr"select count(*)" ++ pending).query[Int].unique
      ).tupled.flatMap {
        (perApp, total) =>
          if perApp >= maxPerApp || total >= maxTotal then
            (Left(DeviceCreateError.TooMany): Either[DeviceCreateError, DeviceCode]).pure[ConnectionIO]
          else insert.as(Right(d): Either[DeviceCreateError, DeviceCode])
      }
    ).recover {
      case e: java.sql.SQLException if e.getSQLState == sqlstate.class23.UNIQUE_VIOLATION.value =>
        Left(DeviceCreateError.Collision)
    }
  }

  def find(id: UUID): IO[Option[DeviceCode]] =
    tx((fr"select" ++ cols ++ fr"from device_codes where id = $id").query[DeviceCode].option)

  /** 利用者が入力した user_code の要求（未完了・期限内・そのドメインのものだけ）. */
  def byUserCode(userCode: String, domain: String, now: Instant): IO[Option[DeviceCode]] =
    tx((fr"select" ++ cols ++ fr"""from device_codes where user_code = $userCode and domain = $domain
          and status = 'pending' and expires_at > $now""").query[DeviceCode].option)

  /** 許可・拒否を記録する（未完了・期限内のものだけ. 先に決めたほうが勝つ）. */
  def decide(id: UUID,
             approve: Boolean,
             userId: UUID,
             loginId: UUID,
             authTime: Instant,
             amr: List[String],
             now: Instant): IO[Boolean] = {
    val status = if approve then "approved" else "denied"
    tx(sql"""update device_codes set status = $status, user_id = $userId, login_id = $loginId, auth_time = $authTime,
               amr = ${amr.toArray}
             where id = $id and status = 'pending' and expires_at > $now""".update.run.map(_ > 0))
  }

  /**
   * 端末からのポーリング（appId のクライアント・発行したドメインのものだけ）. 間隔より早ければ間隔を slowDownBy 秒延ばす.
   * 許可済みなら使用済みにして返す（同時に来ても、行のロックで1回だけ）.
   */
  def poll(hash: Array[Byte], appId: UUID, domain: String, now: Instant, slowDownBy: Int): IO[DevicePoll] = tx(
    (fr"select" ++ cols ++
      fr"from device_codes where device_code_hash = $hash and app_id = $appId and domain = $domain for update").query[
      DeviceCode
    ].option.flatMap {
      case None => (DevicePoll.Unknown: DevicePoll).pure[ConnectionIO]
      // 使用済みなら期限が過ぎていても再利用として扱う（発行したトークンを失効させるため. 行は1日残る）
      case Some(d) if d.usedAt.isDefined => (DevicePoll.Reused(d): DevicePoll).pure[ConnectionIO]
      case Some(d) if !d.expiresAt.isAfter(now) => (DevicePoll.Expired: DevicePoll).pure[ConnectionIO]
      case Some(d) if d.lastPollAt.exists(_.plusSeconds(d.intervalSeconds.toLong).isAfter(now)) =>
        val next = d.intervalSeconds + slowDownBy
        sql"update device_codes set interval_seconds = $next, last_poll_at = $now where id = ${d.id}".update.run.as(
          DevicePoll.SlowDown(next): DevicePoll
        )
      case Some(d) =>
        d.status match {
          case "approved" =>
            sql"update device_codes set used_at = $now, last_poll_at = $now where id = ${d.id}".update.run.as(
              DevicePoll.Approved(d): DevicePoll
            )
          case other =>
            sql"update device_codes set last_poll_at = $now where id = ${d.id}".update.run.as(
              if other == "denied" then DevicePoll.Denied else DevicePoll.Pending
            )
        }
    }
  )

  /** 期限切れの要求を消す. トークンを発行したものは、再利用を検出できるよう期限の後も1日残す（認可コードと同じ）. */
  def purge(now: Instant): IO[Int] = tx(
    sql"""delete from device_codes where (used_at is null and expires_at < $now)
          or expires_at < $now - interval '1 day'""".update.run
  )
}
