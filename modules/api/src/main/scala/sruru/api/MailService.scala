package sruru.api

import sbirds.db.*
import cats.effect.*
import sruru.core.*
import sruru.db.*
import sbirds.mail.{Mail, Mailer}

import scala.concurrent.duration.*

/** メールの送信（送信待ちの表に入れ、定期処理で送る. SMTP が未設定なら標準出力に出す）. */
final class MailService(store: MailStore, mailer: Option[Mailer], cfg: ApiConfig) {
  def send(to: String, subject: String, body: String): IO[Unit] =
    mailer match {
      case Some(_) => store.enqueue(to, subject, body)
      // 本文にはワンタイムコードなどが入るので、出すのは開発用のときだけ. それも標準出力だけにする（ロガーを通すと OTLP で skorimako に送られる）
      case None if cfg.devMode => IO.println(s"[sruru] mail (SMTP 未設定のため送信しません) to=$to subject=$subject\n$body")
      case None => sbirds.observe.Log.println(s"[sruru] WARNING: SMTP が未設定のため、メールを送れません（to=$to）")
    }

  def loop: IO[Nothing] =
    Loops.every(5.seconds, 5.seconds, ErrorCode.MailWorkerFailed) {
      mailer.fold(IO.unit)(m =>
        store.process(20)(om =>
          sbirds.observe.Telemetry.span("mail.send")(m.send(Mail(
            om.to,
            om.to,
            om.subject,
            om.body
          ))).as(OutboxResult.Sent)
            .flatTap(_ => sbirds.observe.Metrics.count("sruru.mails.sent", "result" -> "sent"))
            .handleErrorWith(e =>
              sbirds.observe.Metrics.count("sruru.mails.sent", "result" -> "retry").as(OutboxResult.Retry(e.getMessage))
            )
        ).void
      )
    }
}
