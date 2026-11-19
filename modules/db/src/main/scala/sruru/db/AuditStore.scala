package sruru.db

import cats.effect.*
import doobie.*
import doobie.implicits.*
import doobie.postgres.implicits.*
import io.circe.Json

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.UUID

/** 監査ログに書く内容. */
final case class AuditEntry(
  actorId: Option[UUID],
  actorName: Option[String],
  via: String,
  action: String,
  targetType: Option[String] = None,
  targetId: Option[String] = None,
  targetName: Option[String] = None,
  ip: Option[String] = None,
  userAgent: Option[String] = None,
  success: Boolean = true,
  detail: Json = Json.obj())

final case class AuditRow(
  id: Long,
  at: Instant,
  actorId: Option[UUID],
  actorName: Option[String],
  via: String,
  action: String,
  targetType: Option[String],
  targetId: Option[String],
  targetName: Option[String],
  ip: Option[String],
  userAgent: Option[String],
  success: Boolean,
  detail: Json,
  prevHash: Option[Array[Byte]],
  hash: Array[Byte])

final case class AuditQuery(
  q: Option[String] = None,
  action: Option[String] = None,
  actorId: Option[UUID] = None,
  targetId: Option[String] = None,
  from: Option[Instant] = None,
  to: Option[Instant] = None,
  success: Option[Boolean] = None,
  via: Option[String] = None,
  limit: Int = 100,
  offset: Int = 0)

/**
 * 監査ログ. 各行は1つ前の行のハッシュを含めたハッシュを持つ（ハッシュの鎖）. 途中の行を書き換えたり消したりすると検証で分かる.
 * 書き込みは advisory lock で1つずつ行う（複数ノードでも鎖が分岐しない）.
 */
final class AuditStore(
  xa: Transactor[IO]) extends TxStore(xa) {
  import Codecs.given

  private def canonical(
    at: Instant,
    e: AuditEntry
  ): String =
    List(
      at.toString,
      e.actorId.fold("")(_.toString),
      e.actorName.getOrElse(""),
      e.via,
      e.action,
      e.targetType.getOrElse(""),
      e.targetId.getOrElse(""),
      e.targetName.getOrElse(""),
      e.ip.getOrElse(""),
      e.userAgent.getOrElse(""),
      e.success.toString,
      e.detail.dropNullValues.noSpacesSortKeys
    ).mkString("\u001f")

  def hashOf(
    prev: Option[Array[Byte]],
    at: Instant,
    e: AuditEntry
  ): Array[Byte] = {
    val md = MessageDigest.getInstance("SHA-256")
    prev.foreach(md.update)
    md.update(canonical(at, e).getBytes(StandardCharsets.UTF_8))
    md.digest()
  }

  def append(
    e: AuditEntry
  ): IO[Long] = {
    val at = Instant.now().truncatedTo(ChronoUnit.MICROS)
    tx(for {
      _ <- sql"select pg_advisory_xact_lock(7213002)".query[Unit].unique
      prev <- sql"select hash from audit_log order by id desc limit 1".query[Array[Byte]].option
      h = hashOf(prev, at, e)
      id <-
        sql"""insert into audit_log (at, actor_id, actor_name, via, action, target_type, target_id, target_name, ip, user_agent, success,
                      detail, prev_hash, hash)
                    values ($at, ${e.actorId}, ${e.actorName}, ${e.via}, ${e.action}, ${e.targetType}, ${e.targetId}, ${e.targetName},
                      ${e.ip}, ${e.userAgent.map(
            _.take(500)
          )}, ${e.success}, ${e.detail}, $prev, $h) returning id""".query[Long].unique
    } yield id)
  }

  private val cols =
    fr"id, at, actor_id, actor_name, via, action, target_type, target_id, target_name, ip, user_agent, success, detail, prev_hash, hash"

  private def conds(
    q: AuditQuery
  ): List[Fragment] = List(
    q.q.map(_.trim).filter(_.nonEmpty).map { s =>
      val like = "%" + s.toLowerCase + "%"
      fr"(lower(action) like $like or lower(coalesce(actor_name, '')) like $like or lower(coalesce(target_name, '')) like $like or coalesce(ip, '') like $like or lower(detail::text) like $like)"
    },
    q.action.filter(_.nonEmpty).map(a => fr"action like ${a + "%"}"),
    q.actorId.map(a => fr"actor_id = $a"),
    q.targetId.filter(_.nonEmpty).map(t => fr"target_id = $t"),
    q.from.map(f => fr"at >= $f"),
    q.to.map(t => fr"at < $t"),
    q.success.map(s => fr"success = $s"),
    q.via.filter(_.nonEmpty).map(v => fr"via = $v")
  ).flatten

  def search(
    q: AuditQuery
  ): IO[(List[AuditRow], Int)] = tx(
    for {
      rows <-
      (fr"select" ++ cols ++ fr"from audit_log" ++ Sql.whereAnd(conds(q)) ++
        fr"order by id desc limit ${q.limit} offset ${q.offset}").query[AuditRow].to[List]
      total <- (fr"select count(*) from audit_log" ++ Sql.whereAnd(conds(q))).query[Int].unique
    } yield (rows, total)
  )

  /** 書き出し（古い順. CSV 用）. */
  def stream(
    q: AuditQuery
  ): fs2.Stream[IO, AuditRow] =
    (fr"select" ++ cols ++ fr"from audit_log" ++ Sql.whereAnd(conds(q)) ++ fr"order by id").query[
      AuditRow
    ].stream.transact(xa)

  /** ハッシュの鎖を検証する. 結果は (確かめた行数, 最初に壊れていた行の ID). */
  def verify
    : IO[(Long, Option[Long])] = (fr"select" ++ cols ++ fr"from audit_log order by id").query[AuditRow].stream.transact(
    xa
  )
    .fold((0L, Option.empty[Long], Option.empty[Array[Byte]], true)) { case ((n, broken, prev, first), r) =>
      if broken.isDefined then (n, broken, prev, false)
      else {
        val e = AuditEntry(
          r.actorId,
          r.actorName,
          r.via,
          r.action,
          r.targetType,
          r.targetId,
          r.targetName,
          r.ip,
          r.userAgent,
          r.success,
          r.detail
        )
        // 古い行を保存期間で消したあとは、最初の行の prev_hash をそのまま使う
        val expectedPrev = if first then r.prevHash else prev
        val linkOk = first || r.prevHash.map(_.toList) == prev.map(_.toList)
        val ok = linkOk && MessageDigest.isEqual(hashOf(expectedPrev, r.at, e), r.hash)
        (n + 1, if ok then None else Some(r.id), Some(r.hash), false)
      }
    }.compile.lastOrError.map(t => (t._1, t._2))

  def purge(
    before: Instant
  ): IO[Int] = tx(sql"delete from audit_log where at < $before".update.run)

  /** 最近のログイン（ダッシュボード）. */
  def countSince(
    action: String,
    since: Instant,
    success: Boolean
  ): IO[Int] =
    tx(sql"select count(*) from audit_log where action = $action and at >= $since and success = $success".query[
      Int
    ].unique)
}
