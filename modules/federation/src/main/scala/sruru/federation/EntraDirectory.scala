package sruru.federation

import cats.effect.IO
import cats.effect.syntax.all.*
import io.circe.Json
import io.circe.syntax.*
import org.http4s.*
import org.http4s.client.Client

/** Microsoft Entra ID（Microsoft Graph. クライアント資格情報）. */
final class EntraDirectory(http: Client[IO],
                           tenantId: String,
                           clientId: String,
                           clientSecret: String,
                           graphBase: String = "https://graph.microsoft.com",
                           loginBase: String = "https://login.microsoftonline.com") extends DirectorySource {
  private val tokens = TokenCache(requestToken)

  private def requestToken: IO[(String, Long)] =
    for {
      u <- HttpUtil.uri(loginBase.stripSuffix("/")).map(_ / tenantId / "oauth2" / "v2.0" / "token")
      j <- HttpUtil.json(
        http,
        Request[IO](Method.POST, u).withEntity(UrlForm(
          "grant_type" -> "client_credentials",
          "client_id" -> clientId,
          "client_secret" -> clientSecret,
          "scope" -> "https://graph.microsoft.com/.default"
        )),
        "Entra のアクセストークンの取得"
      )
      t <-
        IO.fromOption(j.hcursor.get[String]("access_token").toOption)(new FederationError("Entra の応答にアクセストークンがありません"))
    } yield (t, j.hcursor.get[Long]("expires_in").getOrElse(3600L))

  private def graph(pathAndQuery: String): IO[Uri] = HttpUtil.uri(graphBase.stripSuffix("/") + pathAndQuery)

  private def paged(token: String, what: String, start: Uri): IO[List[Json]] = {
    val get = (u: Uri) =>
      HttpUtil.json(
        http,
        HttpUtil.bearer(
          Request[IO](Method.GET, u),
          token
        ).putHeaders(Header.Raw(org.typelevel.ci.CIString("ConsistencyLevel"), "eventual")),
        what
      )
    HttpUtil.pages(start)(get)(
      Dir.list(_, "value"),
      j => Dir.str(j.hcursor, "@odata.nextLink").flatMap(s => Uri.fromString(s).toOption)
    )
  }

  def fetch: IO[DirSnapshot] =
    for {
      token <- tokens.token
      uu <- graph("/v1.0/users?$select=" + EntraDirectory.UserFields + "&$top=999")
      us <- paged(token, "Entra の利用者の取得", uu)
      users = us.flatMap(EntraDirectory.toUser)
      known = users.map(_.externalId).toSet
      gu <- graph("/v1.0/groups?$select=id,displayName,description,mail&$top=999")
      gs <- paged(token, "Entra のグループの取得", gu)
      groups <- gs.flatMap(g => Dir.str(g.hcursor, "id").map(_ -> g)).parTraverseN(Dir.Parallelism) {
        (id, g) =>
          graph(s"/v1.0/groups/${Uri.pathEncode(id)}/transitiveMembers/microsoft.graph.user?$$select=id&$$top=999")
            .flatMap(paged(token, "Entra のグループのメンバーの取得", _)).map { ms =>
              val c = g.hcursor
              DirGroup(
                id,
                Dir.str(c, "displayName").getOrElse(id),
                Dir.str(c, "description").getOrElse(""),
                Dir.str(c, "mail"),
                Dir.members(ms.flatMap(m => Dir.str(m.hcursor, "id")), known)
              )
            }
      }
    } yield DirSnapshot(users, groups)

  def photo(u: DirUser): IO[Option[(Array[Byte], String)]] =
    for {
      token <- tokens.token
      pu <- graph(s"/v1.0/users/${Uri.pathEncode(u.externalId)}/photo/$$value")
      res <- HttpUtil.run(http, HttpUtil.bearer(Request[IO](Method.GET, pu), token))
      out <-
        if res.status.code == 404 then IO.pure(None)
        else if !res.status.isSuccess then IO.raiseError(HttpUtil.failure("Entra の写真の取得", res))
        else IO.pure(Option.when(res.body.nonEmpty)(res.body -> res.contentType.getOrElse("image/jpeg")))
    } yield out
}

object EntraDirectory {
  val UserFields =
    "id,userPrincipalName,mail,displayName,givenName,surname,accountEnabled,department,jobTitle,employeeId,mobilePhone,officeLocation"

  def toUser(j: Json): Option[DirUser] = {
    val c = j.hcursor
    for {
      id <- Dir.str(c, "id")
      upn <- Dir.str(c, "userPrincipalName")
    } yield {
      def a(k: String) = Dir.str(c, k).map(_.asJson)
      DirUser(
        externalId = id,
        username = upn,
        email = Dir.str(c, "mail").orElse(Some(upn)),
        name = Dir.str(c, "displayName").getOrElse(upn),
        givenName = Dir.str(c, "givenName"),
        familyName = Dir.str(c, "surname"),
        active = c.get[Boolean]("accountEnabled").getOrElse(true),
        attributes = Dir.attrs(
          "department" -> a("department"),
          "jobTitle" -> a("jobTitle"),
          "employeeId" -> a("employeeId"),
          "phone" -> a("mobilePhone"),
          "officeLocation" -> a("officeLocation")
        ),
        photoUrl = None
      )
    }
  }
}
