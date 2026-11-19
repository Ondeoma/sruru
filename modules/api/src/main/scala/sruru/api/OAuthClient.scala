package sruru.api

import io.circe.Decoder
import sruru.shared.*

/**
 * OAuth（/oauth/…）で連携する兄弟のサービス（skakapo など. 環境変数 OAUTH_CLIENTS で登録する）.
 * redirectUri は完全一致で照合する. sruru は管理の基盤なので、渡せるスコープは read だけ.
 */
final case class OAuthClient(id: String,
                             secret: String,
                             redirectUri: String,
                             name: String,
                             scopes: List[String] = List(TokenScopes.Read))

object OAuthClient {

  /** OAuth で渡せるスコープ（write・admin・scim はトークンでは渡さない）. */
  val Allowed: Set[String] = Set(TokenScopes.Read)

  private given Decoder[OAuthClient] = Decoder.instance(c =>
    for {
      id <- c.get[String]("id")
      secret <- c.get[String]("secret")
      ru <- c.get[String]("redirectUri")
      name <- c.getOrElse[String]("name")(id)
      scopes <- c.getOrElse[List[String]]("scopes")(List(TokenScopes.Read))
    } yield OAuthClient(id.trim, secret, ru.trim, name.trim, scopes.distinct)
  )

  /** OAUTH_CLIENTS（JSON の配列）を読む. */
  def parse(json: String): Either[String, List[OAuthClient]] =
    io.circe.parser.decode[List[OAuthClient]](json).left.map(e =>
      s"OAUTH_CLIENTS の形式が正しくありません: ${e.getMessage}"
    ).flatMap { cs =>
      cs.find(c => c.id.isEmpty || c.redirectUri.isEmpty).map(_ => "OAUTH_CLIENTS の id・redirectUri は必須です")
        .orElse(cs.find(_.secret.length < 16).map(c => s"OAUTH_CLIENTS の ${c.id} の secret は16文字以上にしてください"))
        .orElse(cs.find(c => c.scopes.isEmpty || !c.scopes.forall(Allowed)).map(c =>
          s"OAUTH_CLIENTS の ${c.id} の scopes は read だけにしてください"
        ))
        .orElse(Option.when(cs.map(_.id).distinct.size != cs.size)("OAUTH_CLIENTS の id が重複しています"))
        .toLeft(cs)
    }
}
