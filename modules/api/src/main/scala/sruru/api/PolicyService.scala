package sruru.api

import cats.effect.*
import cats.syntax.all.*
import sruru.db.*
import sruru.shared.*

/** 設定（ポリシー）の控え. 5秒ごとに DB から読み直す（ほかのノードでの変更も数秒で反映される）. */
final class PolicyService(
  settings: SettingsStore,
  cache: Ref[IO, Option[(Long, PoliciesDto)]]) {
  def get: IO[PoliciesDto] =
    (cache.get, IO.monotonic).flatMapN {
      (
        c,
        now
      ) =>
        c match {
          case Some((at, p)) if now.toMillis - at < 5000 => IO.pure(p)
          case _ =>
            settings.getAs[PoliciesDto]("policies", PoliciesDto()).flatTap(p => cache.set(Some(now.toMillis -> p)))
        }
    }

  def put(
    p: PoliciesDto
  ): IO[Unit] = settings.put("policies", p) *> cache.set(None)
}

object PolicyService {
  def create(
    settings: SettingsStore
  ): IO[PolicyService] = Ref.of[IO, Option[(Long, PoliciesDto)]](None).map(new PolicyService(settings, _))
}
