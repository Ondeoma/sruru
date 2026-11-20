package sruru.api

import cats.effect.*
import cats.syntax.all.*
import io.circe.Json
import io.circe.syntax.*
import org.http4s.*
import org.http4s.circe.CirceEntityCodec.*
import sruru.core.*
import sruru.db.*
import sruru.shared.*

import java.util.UUID

/** ドメイン（sruru にアクセスするホスト名）ごとのポリシーの上書きの管理 API（システム管理者のみ）. */
final class DomainRoutes(domains: Domains,
                         dir: Directory,
                         sessions: SessionStore,
                         fedStore: FederationStore,
                         audit: AuditService,
                         val auth: SessionAuth,
                         cfg: ApiConfig)
  extends RouteSupport {

  val routes: HttpRoutes[IO] = HttpRoutes.of[IO] {
    case req @ GET -> Root / "api" / "admin" / "domains" => getAdminDomains(req)
    case req @ POST -> Root / "api" / "admin" / "domains" => postAdminDomains(req)
    case req @ PUT -> Root / "api" / "admin" / "domains" / UuidVar(id) => putAdminDomain(req, id)
    case req @ DELETE -> Root / "api" / "admin" / "domains" / UuidVar(id) => deleteAdminDomain(req, id)
  }

  private def getAdminDomains(req: Request[IO]): IO[Response[IO]] =
    admin(req)(_ =>
      (domains.store.all, Site.current).flatMapN((ds, cur) =>
        Ok(DomainsDto(cfg.publicUrl, cur.map(_.id), ds.map(dto)))
      )
    )

  private def postAdminDomains(req: Request[IO]): IO[Response[IO]] =
    admin(req)(p =>
      body[DomainReq](req) { r =>
        DomainPolicy.normalizeHost(r.host).filterOrElse(
          h => !domains.isPrimary(h),
          "既定のホスト名（PUBLIC_URL）は登録できません"
        ) match {
          case Left(e) => err(ErrorCode.InvalidInput, e)
          case Right(host) =>
            checked(req, None, r.policy) {
              pol =>
                domains.store.create(host, r.note.trim, pol).flatMap {
                  case None => err(ErrorCode.DomainHostTaken)
                  case Some(d) =>
                    domains.invalidate *>
                      audited(audit, req, p, "domain.create", target(d), Json.obj("policy" -> d.policy.asJson)) *>
                      Created(dto(d))
                }
            }
        }
      }
    )

  private def putAdminDomain(req: Request[IO], id: UUID): IO[Response[IO]] =
    admin(req)(p =>
      body[DomainReq](req) { r =>
        domains.store.find(id).flatMap {
          case None => err(ErrorCode.DomainNotFound)
          // ホスト名は変えられない（セッション・トークンがホスト名に結び付いているため. 変えるなら消して作り直す）
          case Some(old) if DomainPolicy.normalizeHost(r.host) != Right(old.host) =>
            err(ErrorCode.InvalidInput, "ホスト名は変えられません（消してから作り直してください）")
          case Some(old) =>
            checked(req, Some(old), r.policy) {
              pol =>
                domains.store.update(id, r.note.trim, pol).flatMap {
                  case None => err(ErrorCode.DomainNotFound)
                  case Some(d) =>
                    domains.invalidate *> audited(
                      audit,
                      req,
                      p,
                      "domain.update",
                      target(d),
                      Json.obj("before" -> old.policy.asJson, "after" -> d.policy.asJson)
                    ) *> Ok(dto(d))
                }
            }
        }
      }
    )

  private def deleteAdminDomain(req: Request[IO], id: UUID): IO[Response[IO]] =
    admin(req)(p =>
      Site.current.flatMap {
        case Some(cur) if cur.id == id => err(ErrorCode.DomainAdminLockout, "いま開いているホスト名のドメインは消せません")
        case _ =>
          domains.store.delete(id).flatMap {
            case None => err(ErrorCode.DomainNotFound)
            case Some(d) =>
              // そのホスト名でのログインを終わらせる（トークンの失効とバックチャネルの通知も行う）
              sessions.loginsOfDomain(d.host).flatMap(_.traverse_((lid, uid) => dir.endLogin(uid, lid))) *>
                sessions.deleteBrowsersOfDomain(d.host) *> domains.invalidate *>
                audited(audit, req, p, "domain.delete", target(d)) *> NoContent()
          }
      }
    )

  /**
   * 上書きの内容を確かめてから続ける. いま開いているホスト名のドメインについては、自分を締め出す設定
   * （管理機能を使えなくする・いまの IP アドレスを許可しない）を受け付けない.
   */
  private def checked(req: Request[IO], old: Option[Domain], policy: DomainPolicy)(
    f: DomainPolicy => IO[Response[IO]]): IO[Response[IO]] =
    (ctx(req), Site.current, fedStore.all).flatMapN {
      (c, cur, fs) =>
        val mine = old.exists(o => cur.exists(_.id == o.id))
        val unknown = policy.login.providers.toList.flatten.filterNot(s => fs.exists(_.slug == s))
        DomainPolicyCheck.validate(policy) match {
          case Left(e) => err(ErrorCode.InvalidInput, e)
          case Right(_) if unknown.nonEmpty =>
            err(ErrorCode.InvalidInput, s"外部の IdP が見つかりません: ${unknown.mkString(", ")}")
          case Right(pol) if mine && !pol.admin => err(ErrorCode.DomainAdminLockout)
          case Right(pol)
              if mine && pol.ip.exists(x => !IpRules.allowedBy(c.ip, IpPolicy(allow = x.allow, deny = x.deny))) =>
            err(ErrorCode.DomainAdminLockout, s"いまの IP アドレス（${c.ip}）が、このドメインの IP の許可に含まれていません")
          case Right(pol) => f(pol)
        }
    }

  private def dto(d: Domain): DomainDto = DomainDto(d.id, d.host, d.note, d.policy, cfg.urlOf(d.host))

  private def target(d: Domain): Option[(String, String, String)] = Some(("domain", d.id.toString, d.host))
}
