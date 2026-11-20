package sruru.db

import sbirds.db.*
import cats.effect.*
import cats.syntax.all.*
import doobie.*
import doobie.implicits.*
import doobie.postgres.implicits.*

import java.time.Instant

final class MailStore(xa: Transactor[IO]) extends TxStore(xa) {

  def enqueue(to: String, subject: String, body: String): IO[Unit] =
    tx(sql"insert into mail_outbox (to_addr, subject, body) values ($to, $subject, $body)".update.run.void)

  /** 送る時刻になったメールを1件ずつ send で送る（ほかのノードとは重ならない）. */
  def process(limit: Int)(send: OutMail => IO[OutboxResult]): IO[Int] =
    processEach(
      sql"""select id, to_addr, subject, body, attempts from mail_outbox where sent_at is null and next_at <= now() and attempts < 10
            order by id limit $limit for update skip locked""".query[OutMail].to[List]
    )(send) {
      (m, r) =>
        r match {
          case OutboxResult.Sent =>
            sql"update mail_outbox set sent_at = now(), error = null where id = ${m.id}".update.run
          case OutboxResult.Skip(e) =>
            sql"update mail_outbox set sent_at = now(), error = $e where id = ${m.id}".update.run
          case OutboxResult.Retry(e) =>
            val secs = Outbox.backoffSeconds(m.attempts)
            sql"""update mail_outbox set attempts = attempts + 1, error = $e, next_at = now() + make_interval(secs => $secs)
                where id = ${m.id}""".update.run
        }
    }

  def purge(before: Instant): IO[Int] =
    tx(sql"delete from mail_outbox where created_at < $before and sent_at is not null".update.run)
}
