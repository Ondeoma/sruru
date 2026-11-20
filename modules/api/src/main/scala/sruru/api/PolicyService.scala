package sruru.api

import cats.effect.*
import cats.syntax.all.*
import sruru.db.*
import sruru.shared.*

/** 設定（ポリシー）の控え. 5秒ごとに DB から読み直す（ほかのノードでの変更も数秒で反映される）. */
final class PolicyService(settings: SettingsStore, cache: Ref[IO, Option[(Long, PoliciesDto)]]) {

  /**
   * この要求に効くポリシー: 全体のポリシーに、アクセスしたホスト名のドメインの上書きを重ねたもの（指定した項目を置き換える）.
   * 既定のホスト名と、要求の外（定期処理）では全体のまま. ユーザーが分かっていれば、さらに Directory.policyFor でグループの上書きを重ねる.
   */
  def get: IO[PoliciesDto] = (global, Site.current).mapN((p, d) => d.fold(p)(PolicyService.forDomain(p, _)))

  /** 全体のポリシー（管理画面で編集するもの・ドメインに依らない項目を読むとき）. */
  def global: IO[PoliciesDto] =
    (cache.get, IO.monotonic).flatMapN {
      (c, now) =>
        c match {
          case Some((at, p)) if now.toMillis - at < 5000 => IO.pure(p)
          case _ =>
            settings.getAs[PoliciesDto]("policies", PoliciesDto()).flatTap(p => cache.set(Some(now.toMillis -> p)))
        }
    }

  def put(p: PoliciesDto): IO[Unit] = settings.put("policies", p.copy(domain = "")) *> cache.set(None)
}

object PolicyService {

  /** ドメインの上書きを重ねたポリシー（どのドメインのものかも入れる）. */
  def forDomain(p: PoliciesDto, d: sruru.core.Domain): PoliciesDto =
    DomainPolicy.applied(p, d.policy).copy(domain = d.host)

  def create(settings: SettingsStore): IO[PolicyService] =
    Ref.of[IO, Option[(Long, PoliciesDto)]](None).map(new PolicyService(settings, _))
}
