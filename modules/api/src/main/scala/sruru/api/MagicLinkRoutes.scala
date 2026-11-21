package sruru.api

import cats.effect.*
import org.http4s.*
import org.http4s.headers.`WWW-Authenticate`
import sruru.core.*
import sruru.db.*
import sruru.shared.*

import java.util.UUID

/**
 * マジックリンクの発行: 管理者（メールで送る）と、許可した OAuth クライアント（Basic 認証. URL を返すかメールで送る）.
 * 使う側（POST /api/login/magic）は LoginRoutes.
 */
final class MagicLinkRoutes(magic: MagicLinkService,
                            dir: Directory,
                            protected val apps: AppStore,
                            val auth: SessionAuth,
                            protected val cfg: ApiConfig) extends RouteSupport with OAuthEndpoint {

  val routes: HttpRoutes[IO] = HttpRoutes.of[IO] {
    case req @ POST -> Root / "api" / "magic-links" => postMagicLinks(req)
    case req @ POST -> Root / "api" / "admin" / "users" / UuidVar(id) / "magic-link" => postAdminUserMagicLink(req, id)
  }

  /** サービスから発行する（クライアントの認証は Authorization: Basic. シークレットを本文・URL に載せさせない）. */
  private def postMagicLinks(req: Request[IO]): IO[Response[IO]] =
    clientAuth(req, Map.empty).flatMap {
      case Right((app, oc)) if !oc.isPublic =>
        body[MagicLinkReq](req)(r => ctx(req).flatMap(c => okJson(magic.issueByClient(c, app, oc, r))))
          .map(_.putHeaders("Cache-Control" -> "no-store"))
      case Right(_) => err(ErrorCode.MagicLinkNotAllowed)
      case Left(_) =>
        err(ErrorCode.MagicLinkClientAuthFailed).map(_.putHeaders(`WWW-Authenticate`(Challenge("Basic", "sruru"))))
    }

  /** 管理者が発行する（登録されているアドレスへメールで送るだけ）. */
  private def postAdminUserMagicLink(req: Request[IO], id: UUID): IO[Response[IO]] =
    admin(req)(p =>
      dir.users.find(id).flatMap {
        case None => err(ErrorCode.UserNotFound)
        case Some(u) => ctx(req).flatMap(c => okJson(magic.issueByAdmin(c, p, u)))
      }
    )
}
