package sruru.api

import cats.effect.*
import cats.syntax.all.*
import org.http4s.*
import sruru.db.*

import java.util.UUID

/** /auth/resume?req=…: ログイン・同意の画面の後に、要求の種類（OIDC・SAML）ごとの続きへ戻る. */
final class ResumeRoutes(tokens: TokenStore,
                         handlers: Map[String, (Request[IO], AuthRequest) => IO[Response[IO]]],
                         gate: AuthGate)
  extends org.http4s.dsl.Http4sDsl[IO] {

  val routes: HttpRoutes[IO] = HttpRoutes.of[IO] {
    case req @ GET -> Root / "auth" / "resume" =>
      req.params.get("req").flatMap(s => scala.util.Try(UUID.fromString(s)).toOption) match {
        case None => gate.errorPage("要求が正しくありません")
        case Some(id) =>
          // 要求を受けたドメイン（ホスト名）でだけ続きを行う（ほかのホスト名のログイン・ポリシーで完了させない）
          (Time.now.flatMap(now => tokens.request(id, now)), Site.host).mapN((r, d) =>
            r.filter(_.domain == d)
          ).flatMap {
            case None => gate.errorPage("ログインの要求の有効期限が切れました。アプリケーションからやり直してください")
            case Some(r) => handlers.get(r.protocol).fold(gate.errorPage("不明な要求です"))(_(req, r))
          }
      }
  }
}
