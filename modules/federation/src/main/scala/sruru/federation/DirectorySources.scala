package sruru.federation

import cats.effect.IO
import cats.syntax.all.*
import io.circe.{HCursor, Json}
import org.http4s.client.Client

object DirectorySources {
  private def field(c: HCursor, k: String): Either[String, String] = Dir.str(c, k).toRight(s"設定に $k がありません")

  /** 設定の JSON から（google: {"serviceAccountJson": "...", "adminEmail": "...", "customer": "my_customer"} / entra: {"tenantId": "...", "clientId": "...", "clientSecret": "..."}）. */
  def from(kind: String, config: Json, http: Client[IO]): Either[String, DirectorySource] = {
    val c = config.hcursor
    kind.trim.toLowerCase match {
      case "google" | "google_workspace" =>
        for {
          // 文字列でも JSON のオブジェクトのままでもよい
          sa <- c.downField("serviceAccountJson").focus.flatMap(j => j.asString.orElse(j.asObject.map(_ => j.noSpaces)))
            .filter(_.trim.nonEmpty).toRight("設定に serviceAccountJson がありません")
          _ <- GoogleDirectory.parseServiceAccount(sa)
          admin <- field(c, "adminEmail")
        } yield GoogleDirectory(http, sa, admin, Dir.str(c, "customer").getOrElse("my_customer"))
      case "entra" | "azure" | "microsoft" =>
        (field(c, "tenantId"), field(c, "clientId"), field(c, "clientSecret")).mapN(EntraDirectory(http, _, _, _))
      case other => Left(s"未対応のディレクトリの種類です: $other")
    }
  }
}
