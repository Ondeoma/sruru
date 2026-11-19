package sruru.federation

import cats.effect.IO

/** アクセストークンを期限まで使い回す. */
private[federation] final class TokenCache(request: IO[(String, Long)]) {
  private val ref = cats.effect.Ref.unsafe[IO, Option[(String, java.time.Instant)]](None)

  def token: IO[String] =
    for {
      now <- IO.realTimeInstant
      cur <- ref.get
      t <- cur match {
        case Some((t, exp)) if exp.isAfter(now.plusSeconds(60)) => IO.pure(t)
        case _ => request.flatMap((t, sec) => ref.set(Some(t -> now.plusSeconds(sec))).as(t))
      }
    } yield t
}
