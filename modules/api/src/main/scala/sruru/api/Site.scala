package sruru.api

import cats.effect.*
import cats.syntax.all.*
import org.http4s.*
import org.typelevel.ci.CIString
import sruru.core.*
import sruru.db.*

/**
 * この要求のドメイン（アクセスしたホスト名）. 要求ごとに Domains.middleware が入れ、ポリシー（PolicyService.get）と
 * 公開 URL（ApiConfig.url）がこれを読む. 既定のホスト名（PUBLIC_URL）と、要求の外（定期処理）では None.
 */
object Site {
  // ファイバーごとの値の入れ物（鍵）を1つだけ作る. 中身はファイバーごとなので、要求どうしで混ざらない
  private val local: IOLocal[Option[Domain]] =
    IOLocal[Option[Domain]](None).syncStep(Int.MaxValue).unsafeRunSync().getOrElse(sys.error("IOLocal"))

  def current: IO[Option[Domain]] = local.get

  /** ドメインのホスト名（既定のホスト名なら空）. セッション・トークンに結び付ける値. */
  def host: IO[String] = local.get.map(_.fold("")(_.host))

  def set(d: Option[Domain]): IO[Unit] = local.set(d)

  /** そのドメインの要求として実行する（定期処理で、ドメインごとのポリシーを読むとき）. */
  def within[A](d: Option[Domain])(io: IO[A]): IO[A] =
    local.get.flatMap(old => local.set(d) *> io.guarantee(local.set(old)))
}

/** ドメインの一覧の控えと、要求からのドメインの判定. 5秒ごとに DB から読み直す（ほかのノードでの変更も数秒で反映される）. */
final class Domains(val store: DomainStore,
                    policies: PolicyService,
                    cfg: ApiConfig,
                    cache: Ref[IO, Option[(Long, List[Domain])]]) {

  def all: IO[List[Domain]] =
    (cache.get, IO.monotonic).flatMapN {
      (c, now) =>
        c match {
          case Some((at, ds)) if now.toMillis - at < 5000 => IO.pure(ds)
          case _ => store.all.flatTap(ds => cache.set(Some(now.toMillis -> ds)))
        }
    }

  def invalidate: IO[Unit] = cache.set(None)

  def byHost(host: String): IO[Option[Domain]] = all.map(_.find(_.host == host))

  /**
   * 要求のホスト名に当たるドメイン. 登録のないホスト名は既定のホスト名として扱う（None）.
   * ホスト名は Host ヘッダー. 信頼するプロキシからの要求なら X-Forwarded-Host を先に見る.
   */
  def resolve(req: Request[IO]): IO[Option[Domain]] =
    all.flatMap {
      case Nil => IO.pure(None)
      case ds =>
        policies.global.map { p =>
          val remote = req.remote.map(_.host.toString).getOrElse("-")
          val forwarded = Option.when(IpRules.matches(remote, p.ip.trustedProxies))(
            req.headers.get(CIString("X-Forwarded-Host")).map(_.head.value.split(',').head.trim)
          ).flatten.filter(_.nonEmpty)
          val raw = forwarded.orElse(req.headers.get(CIString("Host")).map(_.head.value)).getOrElse("").trim.toLowerCase
          // ポートまで書いて登録したものが先. なければポートを除いたホスト名で探す
          ds.find(_.host == raw).orElse(ds.find(_.host == Domains.withoutPort(raw)))
        }
    }

  /** 要求ごとに、ドメインを決めてから処理する. */
  def middleware(app: HttpApp[IO]): HttpApp[IO] =
    HttpApp[IO](req => resolve(req).flatMap(Site.set) *> app.run(req))

  /** 既定のホスト名（PUBLIC_URL のもの）か. ドメインとしては登録できない. */
  def isPrimary(host: String): Boolean = Domains.hostOf(cfg.publicUrl).contains(host)
}

object Domains {
  def create(store: DomainStore, policies: PolicyService, cfg: ApiConfig): IO[Domains] =
    Ref.of[IO, Option[(Long, List[Domain])]](None).map(new Domains(store, policies, cfg, _))

  private def withoutPort(h: String): String =
    if h.startsWith("[") then h.takeWhile(_ != ']') + "]" else h.takeWhile(_ != ':')

  /** URL のホスト名（既定のポートでなければ :port 付き. 小文字）. */
  def hostOf(url: String): Option[String] =
    scala.util.Try(new java.net.URI(url)).toOption.flatMap(u =>
      Option(u.getHost).map(h => (if u.getPort == -1 then h else s"$h:${u.getPort}").toLowerCase)
    )
}

/** この要求のホスト名の公開 URL（issuer）と、ドメイン（ホスト名. 既定なら空）. */
final case class Here(url: String, domain: String)
