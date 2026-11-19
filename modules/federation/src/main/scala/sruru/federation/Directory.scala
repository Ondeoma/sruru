package sruru.federation

import cats.effect.IO
import io.circe.Json

import java.security.{PrivateKey, PublicKey}

/** ディレクトリの利用者. attributes は部署・役職・社員番号・電話・上長のメールアドレスなど. */
final case class DirUser(externalId: String,
                         username: String,
                         email: Option[String],
                         name: String,
                         givenName: Option[String],
                         familyName: Option[String],
                         active: Boolean,
                         attributes: Json,
                         photoUrl: Option[String])

/** ディレクトリのグループ. memberUserIds は DirUser.externalId（入れ子のグループは展開済み）. */
final case class DirGroup(externalId: String,
                          name: String,
                          description: String,
                          email: Option[String],
                          memberUserIds: List[String])

final case class DirSnapshot(users: List[DirUser], groups: List[DirGroup])

/** 利用者とグループを取り込む元. */
trait DirectorySource {
  def fetch: IO[DirSnapshot]

  /** 写真（中身と Content-Type）. なければ None. */
  def photo(u: DirUser): IO[Option[(Array[Byte], String)]]
}

// ==================================================================== Google Workspace

/** サービスアカウントの鍵（JSON）. */
final case class ServiceAccount(clientEmail: String,
                                privateKeyId: String,
                                privateKey: PrivateKey,
                                publicKey: PublicKey,
                                tokenUri: String)

// ==================================================================== Microsoft Entra ID

// ==================================================================== 設定から
