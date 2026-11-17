package sruru.federation

import cats.effect.IO
import cats.effect.syntax.all.*
import cats.syntax.all.*
import io.circe.{HCursor, Json}
import io.circe.parser.parse
import io.circe.syntax.*
import org.http4s.*
import org.http4s.client.Client
import sruru.security.{Jose, SigningKey}

import java.security.interfaces.RSAPrivateCrtKey
import java.security.spec.{PKCS8EncodedKeySpec, RSAPublicKeySpec}
import java.security.{KeyFactory, PrivateKey, PublicKey}
import java.util.Base64

/** ディレクトリの利用者. attributes は部署・役職・社員番号・電話・上長のメールアドレスなど. */
final case class DirUser(
    externalId: String,
    username: String,
    email: Option[String],
    name: String,
    givenName: Option[String],
    familyName: Option[String],
    active: Boolean,
    attributes: Json,
    photoUrl: Option[String]
)

/** ディレクトリのグループ. memberUserIds は DirUser.externalId（入れ子のグループは展開済み）. */
final case class DirGroup(externalId: String, name: String, description: String, email: Option[String], memberUserIds: List[String])

final case class DirSnapshot(users: List[DirUser], groups: List[DirGroup])

/** 利用者とグループを取り込む元. */
trait DirectorySource:
  def fetch: IO[DirSnapshot]

  /** 写真（中身と Content-Type）. なければ None. */
  def photo(u: DirUser): IO[Option[(Array[Byte], String)]]

private[federation] object Dir:
  val Parallelism = 4

  def str(c: HCursor, k: String): Option[String] = c.get[String](k).toOption.filter(_.nonEmpty)

  def list(j: Json, k: String): List[Json] = j.hcursor.get[List[Json]](k).getOrElse(Nil)

  /** 属性（値のないものは除く）. */
  def attrs(kv: (String, Option[Json])*): Json = Json.fromFields(kv.collect { case (k, Some(v)) => k -> v })

  /** 所属がわかっている利用者だけ・重複なし. */
  def members(ids: List[String], known: Set[String]): List[String] = ids.filter(known.contains).distinct

// ==================================================================== Google Workspace

/** サービスアカウントの鍵（JSON）. */
final case class ServiceAccount(clientEmail: String, privateKeyId: String, privateKey: PrivateKey, publicKey: PublicKey, tokenUri: String)

object GoogleDirectory:
  val Scopes: List[String] = List(
    "https://www.googleapis.com/auth/admin.directory.user.readonly",
    "https://www.googleapis.com/auth/admin.directory.group.readonly",
    "https://www.googleapis.com/auth/admin.directory.group.member.readonly"
  )
  val DefaultTokenUri = "https://oauth2.googleapis.com/token"

  /** PKCS#8 の PEM（BEGIN PRIVATE KEY）の RSA 秘密鍵. */
  def parsePem(pem: String): Either[String, PrivateKey] =
    val body = pem.linesIterator.map(_.trim).filterNot(l => l.startsWith("-----") || l.isEmpty).mkString
    Either.catchNonFatal {
      KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Base64.getMimeDecoder.decode(body)))
    }.leftMap(_ => "秘密鍵（PKCS#8 の PEM）を読めません")

  def parseServiceAccount(json: String): Either[String, ServiceAccount] =
    for
      j <- parse(json).leftMap(_ => "サービスアカウントの JSON を読めません")
      c = j.hcursor
      email <- Dir.str(c, "client_email").toRight("サービスアカウントの JSON に client_email がありません")
      kid   <- Dir.str(c, "private_key_id").toRight("サービスアカウントの JSON に private_key_id がありません")
      pem   <- Dir.str(c, "private_key").toRight("サービスアカウントの JSON に private_key がありません")
      pk    <- parsePem(pem)
      pub <- pk match
        case k: RSAPrivateCrtKey =>
          Either.catchNonFatal(KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(k.getModulus, k.getPublicExponent)))
            .leftMap(_ => "公開鍵を作れません")
        case _ => Left("RSA の秘密鍵ではありません")
    // token_uri は Google の既定のものだけ（JSON に書かれた別の URL へ、署名した要求を送らない）
    yield ServiceAccount(email, kid, pk, pub, DefaultTokenUri)

  /** Google の web-safe base64（'*' の埋め草もある）. */
  def decodeWebSafe(s: String): Array[Byte] =
    Base64.getUrlDecoder.decode(s.trim.replace('+', '-').replace('/', '_').reverse.dropWhile(c => c == '=' || c == '*').reverse)

/** Google Workspace の Admin SDK Directory API（サービスアカウント + ドメイン全体の委任）. */
final class GoogleDirectory(
    http: Client[IO],
    serviceAccountJson: String,
    adminEmail: String,
    customer: String = "my_customer",
    adminBase: String = "https://admin.googleapis.com"
) extends DirectorySource:
  private lazy val account = GoogleDirectory.parseServiceAccount(serviceAccountJson)

  private val tokens = TokenCache(requestToken)

  /** JWT による認可（RFC 7523）. sub に管理者を入れてドメイン全体の委任を使う. */
  private def requestToken: IO[(String, Long)] =
    for
      sa  <- IO.fromEither(account.leftMap(new FederationError(_)))
      now <- IO.realTimeInstant
      claims = Json.obj(
        "iss"   -> sa.clientEmail.asJson,
        "sub"   -> adminEmail.asJson,
        "scope" -> GoogleDirectory.Scopes.mkString(" ").asJson,
        "aud"   -> sa.tokenUri.asJson,
        "iat"   -> now.getEpochSecond.asJson,
        "exp"   -> (now.getEpochSecond + 3600).asJson
      )
      jwt = Jose.sign(SigningKey(sa.privateKeyId, "RS256", sa.privateKey, sa.publicKey, None), claims)
      u <- HttpUtil.uri(sa.tokenUri)
      j <- HttpUtil.json(http, Request[IO](Method.POST, u).withEntity(
             UrlForm("grant_type" -> "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion" -> jwt)), "Google のアクセストークンの取得")
      t <- IO.fromOption(j.hcursor.get[String]("access_token").toOption)(new FederationError("Google の応答にアクセストークンがありません"))
    yield (t, j.hcursor.get[Long]("expires_in").getOrElse(3600L))

  private def base: IO[Uri] = HttpUtil.uri(adminBase.stripSuffix("/")).map(_ / "admin" / "directory" / "v1")

  private def get(token: String, what: String)(u: Uri): IO[Json] =
    HttpUtil.json(http, HttpUtil.bearer(Request[IO](Method.GET, u), token), what)

  private def paged(token: String, what: String, start: Uri, items: String): IO[List[Json]] =
    HttpUtil.pages(start)(get(token, what))(Dir.list(_, items), j => Dir.str(j.hcursor, "nextPageToken").map(t => start.withQueryParam("pageToken", t)))

  def fetch: IO[DirSnapshot] =
    for
      token <- tokens.token
      b     <- base
      us    <- paged(token, "Google の利用者の取得", (b / "users").withQueryParams(Map("customer" -> customer, "maxResults" -> "500", "projection" -> "full")), "users")
      users = us.flatMap(GoogleUsers.toUser)
      known = users.map(_.externalId).toSet
      gs <- paged(token, "Google のグループの取得", (b / "groups").withQueryParams(Map("customer" -> customer, "maxResults" -> "200")), "groups")
      groups <- gs.flatMap(g => Dir.str(g.hcursor, "id").map(_ -> g)).parTraverseN(Dir.Parallelism) { (id, g) =>
        val u = (b / "groups" / id / "members").withQueryParams(Map("maxResults" -> "200", "includeDerivedMembership" -> "true"))
        paged(token, "Google のグループのメンバーの取得", u, "members").map { ms =>
          val ids = ms.map(_.hcursor).filter(c => Dir.str(c, "type").contains("USER")).flatMap(Dir.str(_, "id"))
          val c   = g.hcursor
          DirGroup(id, Dir.str(c, "name").orElse(Dir.str(c, "email")).getOrElse(id), Dir.str(c, "description").getOrElse(""),
            Dir.str(c, "email"), Dir.members(ids, known))
        }
      }
    yield DirSnapshot(users, groups)

  def photo(u: DirUser): IO[Option[(Array[Byte], String)]] =
    if u.photoUrl.isEmpty then IO.pure(None)
    else
      for
        token <- tokens.token
        b     <- base
        res   <- HttpUtil.run(http, HttpUtil.bearer(Request[IO](Method.GET, b / "users" / u.externalId / "photos" / "thumbnail"), token))
        out <-
          if res.status.code == 404 then IO.pure(None)
          else if !res.status.isSuccess then IO.raiseError(HttpUtil.failure("Google の写真の取得", res))
          else
            HttpUtil.parseJson("Google の写真の取得", res).flatMap { j =>
              val c = j.hcursor
              Dir.str(c, "photoData") match
                case None => IO.pure(None)
                case Some(d) =>
                  IO(GoogleDirectory.decodeWebSafe(d)).adaptError(_ => new FederationError("Google の写真を読めません"))
                    .map(bytes => Some(bytes -> Dir.str(c, "mimeType").getOrElse("image/jpeg")))
            }
      yield out

/** Google の利用者の JSON を DirUser にする. */
private[federation] object GoogleUsers:
  private def pick(arr: List[Json], pred: HCursor => Boolean = _ => true): Option[HCursor] =
    val cs = arr.map(_.hcursor).filter(pred)
    cs.find(_.get[Boolean]("primary").toOption.contains(true)).orElse(cs.headOption)

  def toUser(j: Json): Option[DirUser] =
    val c = j.hcursor
    for
      id    <- Dir.str(c, "id")
      email <- Dir.str(c, "primaryEmail")
    yield
      val n   = c.downField("name")
      def ns(k: String) = n.get[String](k).toOption.filter(_.nonEmpty)
      val org = pick(Dir.list(j, "organizations"))
      def os(k: String) = org.flatMap(Dir.str(_, k)).map(_.asJson)
      val empId = pick(Dir.list(j, "externalIds"), x => Dir.str(x, "type").contains("organization")).flatMap(Dir.str(_, "value"))
      val phone = pick(Dir.list(j, "phones"), x => Dir.str(x, "type").exists(t => t == "work" || t == "mobile"))
        .orElse(pick(Dir.list(j, "phones"))).flatMap(Dir.str(_, "value"))
      val manager = pick(Dir.list(j, "relations"), x => Dir.str(x, "type").contains("manager")).flatMap(Dir.str(_, "value"))
      val gn      = ns("givenName")
      val family  = ns("familyName")
      DirUser(
        externalId = id,
        username = email,
        email = Some(email),
        name = ns("fullName").orElse((gn.toList ++ family.toList).mkString(" ").some.filter(_.nonEmpty)).getOrElse(email),
        givenName = gn,
        familyName = family,
        active = !c.get[Boolean]("suspended").getOrElse(false) && !c.get[Boolean]("archived").getOrElse(false),
        attributes = Dir.attrs(
          "department"  -> os("department"),
          "jobTitle"    -> os("title"),
          "costCenter"  -> os("costCenter"),
          "employeeId"  -> empId.map(_.asJson),
          "phone"       -> phone.map(_.asJson),
          "manager"     -> manager.map(_.asJson),
          "orgUnitPath" -> Dir.str(c, "orgUnitPath").map(_.asJson)
        ),
        photoUrl = Dir.str(c, "thumbnailPhotoUrl")
      )


// ==================================================================== Microsoft Entra ID

/** Microsoft Entra ID（Microsoft Graph. クライアント資格情報）. */
final class EntraDirectory(
    http: Client[IO],
    tenantId: String,
    clientId: String,
    clientSecret: String,
    graphBase: String = "https://graph.microsoft.com",
    loginBase: String = "https://login.microsoftonline.com"
) extends DirectorySource:
  private val tokens = TokenCache(requestToken)

  private def requestToken: IO[(String, Long)] =
    for
      u <- HttpUtil.uri(loginBase.stripSuffix("/")).map(_ / tenantId / "oauth2" / "v2.0" / "token")
      j <- HttpUtil.json(http, Request[IO](Method.POST, u).withEntity(UrlForm(
             "grant_type"    -> "client_credentials",
             "client_id"     -> clientId,
             "client_secret" -> clientSecret,
             "scope"         -> "https://graph.microsoft.com/.default"
           )), "Entra のアクセストークンの取得")
      t <- IO.fromOption(j.hcursor.get[String]("access_token").toOption)(new FederationError("Entra の応答にアクセストークンがありません"))
    yield (t, j.hcursor.get[Long]("expires_in").getOrElse(3600L))

  private def graph(pathAndQuery: String): IO[Uri] = HttpUtil.uri(graphBase.stripSuffix("/") + pathAndQuery)

  private def paged(token: String, what: String, start: Uri): IO[List[Json]] =
    val get = (u: Uri) =>
      HttpUtil.json(http, HttpUtil.bearer(Request[IO](Method.GET, u), token).putHeaders(Header.Raw(org.typelevel.ci.CIString("ConsistencyLevel"), "eventual")), what)
    HttpUtil.pages(start)(get)(Dir.list(_, "value"), j => Dir.str(j.hcursor, "@odata.nextLink").flatMap(s => Uri.fromString(s).toOption))

  def fetch: IO[DirSnapshot] =
    for
      token <- tokens.token
      uu    <- graph("/v1.0/users?$select=" + EntraDirectory.UserFields + "&$top=999")
      us    <- paged(token, "Entra の利用者の取得", uu)
      users = us.flatMap(EntraDirectory.toUser)
      known = users.map(_.externalId).toSet
      gu <- graph("/v1.0/groups?$select=id,displayName,description,mail&$top=999")
      gs <- paged(token, "Entra のグループの取得", gu)
      groups <- gs.flatMap(g => Dir.str(g.hcursor, "id").map(_ -> g)).parTraverseN(Dir.Parallelism) { (id, g) =>
        graph(s"/v1.0/groups/${Uri.pathEncode(id)}/transitiveMembers/microsoft.graph.user?$$select=id&$$top=999")
          .flatMap(paged(token, "Entra のグループのメンバーの取得", _)).map { ms =>
            val c = g.hcursor
            DirGroup(id, Dir.str(c, "displayName").getOrElse(id), Dir.str(c, "description").getOrElse(""), Dir.str(c, "mail"),
              Dir.members(ms.flatMap(m => Dir.str(m.hcursor, "id")), known))
          }
      }
    yield DirSnapshot(users, groups)

  def photo(u: DirUser): IO[Option[(Array[Byte], String)]] =
    for
      token <- tokens.token
      pu    <- graph(s"/v1.0/users/${Uri.pathEncode(u.externalId)}/photo/$$value")
      res   <- HttpUtil.run(http, HttpUtil.bearer(Request[IO](Method.GET, pu), token))
      out <-
        if res.status.code == 404 then IO.pure(None)
        else if !res.status.isSuccess then IO.raiseError(HttpUtil.failure("Entra の写真の取得", res))
        else IO.pure(Option.when(res.body.nonEmpty)(res.body -> res.contentType.getOrElse("image/jpeg")))
    yield out

object EntraDirectory:
  val UserFields =
    "id,userPrincipalName,mail,displayName,givenName,surname,accountEnabled,department,jobTitle,employeeId,mobilePhone,officeLocation"

  def toUser(j: Json): Option[DirUser] =
    val c = j.hcursor
    for
      id  <- Dir.str(c, "id")
      upn <- Dir.str(c, "userPrincipalName")
    yield
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
          "department"     -> a("department"),
          "jobTitle"       -> a("jobTitle"),
          "employeeId"     -> a("employeeId"),
          "phone"          -> a("mobilePhone"),
          "officeLocation" -> a("officeLocation")
        ),
        photoUrl = None
      )

// ==================================================================== 設定から

object DirectorySources:
  private def field(c: HCursor, k: String): Either[String, String] = Dir.str(c, k).toRight(s"設定に $k がありません")

  /** 設定の JSON から（google: {"serviceAccountJson": "...", "adminEmail": "...", "customer": "my_customer"} / entra: {"tenantId": "...", "clientId": "...", "clientSecret": "..."}）. */
  def from(kind: String, config: Json, http: Client[IO]): Either[String, DirectorySource] =
    val c = config.hcursor
    kind.trim.toLowerCase match
      case "google" | "google_workspace" =>
        for
          // 文字列でも JSON のオブジェクトのままでもよい
          sa <- c.downField("serviceAccountJson").focus.flatMap(j => j.asString.orElse(j.asObject.map(_ => j.noSpaces)))
                  .filter(_.trim.nonEmpty).toRight("設定に serviceAccountJson がありません")
          _     <- GoogleDirectory.parseServiceAccount(sa)
          admin <- field(c, "adminEmail")
        yield GoogleDirectory(http, sa, admin, Dir.str(c, "customer").getOrElse("my_customer"))
      case "entra" | "azure" | "microsoft" =>
        (field(c, "tenantId"), field(c, "clientId"), field(c, "clientSecret")).mapN(EntraDirectory(http, _, _, _))
      case other => Left(s"未対応のディレクトリの種類です: $other")
