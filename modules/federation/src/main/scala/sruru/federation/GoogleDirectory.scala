package sruru.federation

import cats.effect.IO
import cats.effect.syntax.all.*
import cats.syntax.all.*
import io.circe.Json
import io.circe.parser.parse
import io.circe.syntax.*
import org.http4s.*
import org.http4s.client.Client
import sruru.security.{Jose, SigningKey}

import java.security.interfaces.RSAPrivateCrtKey
import java.security.spec.{PKCS8EncodedKeySpec, RSAPublicKeySpec}
import java.security.{KeyFactory, PrivateKey}
import java.util.Base64

object GoogleDirectory {
  val Scopes: List[String] = List(
    "https://www.googleapis.com/auth/admin.directory.user.readonly",
    "https://www.googleapis.com/auth/admin.directory.group.readonly",
    "https://www.googleapis.com/auth/admin.directory.group.member.readonly"
  )
  val DefaultTokenUri = "https://oauth2.googleapis.com/token"

  /** PKCS#8 の PEM（BEGIN PRIVATE KEY）の RSA 秘密鍵. */
  def parsePem(
    pem: String
  ): Either[String, PrivateKey] = {
    val body = pem.linesIterator.map(_.trim).filterNot(l => l.startsWith("-----") || l.isEmpty).mkString
    Either.catchNonFatal {
      KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Base64.getMimeDecoder.decode(body)))
    }.leftMap(_ => "秘密鍵（PKCS#8 の PEM）を読めません")
  }

  def parseServiceAccount(
    json: String
  ): Either[String, ServiceAccount] =
    for {
      j <- parse(json).leftMap(_ => "サービスアカウントの JSON を読めません")
      c = j.hcursor
      email <- Dir.str(c, "client_email").toRight("サービスアカウントの JSON に client_email がありません")
      kid <- Dir.str(c, "private_key_id").toRight("サービスアカウントの JSON に private_key_id がありません")
      pem <- Dir.str(c, "private_key").toRight("サービスアカウントの JSON に private_key がありません")
      pk <- parsePem(pem)
      pub <- pk match {
        case k: RSAPrivateCrtKey =>
          Either.catchNonFatal(KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(
            k.getModulus,
            k.getPublicExponent
          )))
            .leftMap(_ => "公開鍵を作れません")
        case _ => Left("RSA の秘密鍵ではありません")
      }
    }
    // token_uri は Google の既定のものだけ（JSON に書かれた別の URL へ、署名した要求を送らない）
    yield ServiceAccount(email, kid, pk, pub, DefaultTokenUri)

  /** Google の web-safe base64（'*' の埋め草もある）. */
  def decodeWebSafe(
    s: String
  ): Array[Byte] =
    Base64.getUrlDecoder.decode(s.trim.replace('+', '-').replace('/', '_').reverse.dropWhile(c =>
      c == '=' || c == '*'
    ).reverse)
}

/** Google Workspace の Admin SDK Directory API（サービスアカウント + ドメイン全体の委任）. */
final class GoogleDirectory(
  http: Client[IO],
  serviceAccountJson: String,
  adminEmail: String,
  customer: String = "my_customer",
  adminBase: String = "https://admin.googleapis.com") extends DirectorySource {
  private lazy val account = GoogleDirectory.parseServiceAccount(serviceAccountJson)

  private val tokens = TokenCache(requestToken)

  /** JWT による認可（RFC 7523）. sub に管理者を入れてドメイン全体の委任を使う. */
  private def requestToken: IO[(String, Long)] =
    for {
      sa <- IO.fromEither(account.leftMap(new FederationError(_)))
      now <- IO.realTimeInstant
      claims = Json.obj(
        "iss" -> sa.clientEmail.asJson,
        "sub" -> adminEmail.asJson,
        "scope" -> GoogleDirectory.Scopes.mkString(" ").asJson,
        "aud" -> sa.tokenUri.asJson,
        "iat" -> now.getEpochSecond.asJson,
        "exp" -> (now.getEpochSecond + 3600).asJson
      )
      jwt = Jose.sign(SigningKey(sa.privateKeyId, "RS256", sa.privateKey, sa.publicKey, None), claims)
      u <- HttpUtil.uri(sa.tokenUri)
      j <- HttpUtil.json(
        http,
        Request[IO](Method.POST, u).withEntity(
          UrlForm("grant_type" -> "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion" -> jwt)
        ),
        "Google のアクセストークンの取得"
      )
      t <-
        IO.fromOption(j.hcursor.get[String]("access_token").toOption)(new FederationError("Google の応答にアクセストークンがありません"))
    } yield (t, j.hcursor.get[Long]("expires_in").getOrElse(3600L))

  private def base: IO[Uri] = HttpUtil.uri(adminBase.stripSuffix("/")).map(_ / "admin" / "directory" / "v1")

  private def get(
    token: String,
    what: String
  )(
    u: Uri
  ): IO[Json] =
    HttpUtil.json(http, HttpUtil.bearer(Request[IO](Method.GET, u), token), what)

  private def paged(
    token: String,
    what: String,
    start: Uri,
    items: String
  ): IO[List[Json]] =
    HttpUtil.pages(start)(get(token, what))(
      Dir.list(_, items),
      j => Dir.str(j.hcursor, "nextPageToken").map(t => start.withQueryParam("pageToken", t))
    )

  def fetch: IO[DirSnapshot] =
    for {
      token <- tokens.token
      b <- base
      us <- paged(
        token,
        "Google の利用者の取得",
        (b / "users").withQueryParams(Map("customer" -> customer, "maxResults" -> "500", "projection" -> "full")),
        "users"
      )
      users = us.flatMap(GoogleUsers.toUser)
      known = users.map(_.externalId).toSet
      gs <- paged(
        token,
        "Google のグループの取得",
        (b / "groups").withQueryParams(Map("customer" -> customer, "maxResults" -> "200")),
        "groups"
      )
      groups <- gs.flatMap(g => Dir.str(g.hcursor, "id").map(_ -> g)).parTraverseN(Dir.Parallelism) {
        (
          id,
          g
        ) =>
          val u = (b / "groups" / id / "members").withQueryParams(Map(
            "maxResults" -> "200",
            "includeDerivedMembership" -> "true"
          ))
          paged(token, "Google のグループのメンバーの取得", u, "members").map { ms =>
            val ids = ms.map(_.hcursor).filter(c => Dir.str(c, "type").contains("USER")).flatMap(Dir.str(_, "id"))
            val c = g.hcursor
            DirGroup(
              id,
              Dir.str(c, "name").orElse(Dir.str(c, "email")).getOrElse(id),
              Dir.str(c, "description").getOrElse(""),
              Dir.str(c, "email"),
              Dir.members(ids, known)
            )
          }
      }
    } yield DirSnapshot(users, groups)

  def photo(
    u: DirUser
  ): IO[Option[(Array[Byte], String)]] =
    if u.photoUrl.isEmpty then IO.pure(None)
    else
      for {
        token <- tokens.token
        b <- base
        res <- HttpUtil.run(
          http,
          HttpUtil.bearer(Request[IO](Method.GET, b / "users" / u.externalId / "photos" / "thumbnail"), token)
        )
        out <-
          if res.status.code == 404 then IO.pure(None)
          else if !res.status.isSuccess then IO.raiseError(HttpUtil.failure("Google の写真の取得", res))
          else
            HttpUtil.parseJson("Google の写真の取得", res).flatMap { j =>
              val c = j.hcursor
              Dir.str(c, "photoData") match {
                case None => IO.pure(None)
                case Some(d) =>
                  IO(GoogleDirectory.decodeWebSafe(d)).adaptError(_ => new FederationError("Google の写真を読めません"))
                    .map(bytes => Some(bytes -> Dir.str(c, "mimeType").getOrElse("image/jpeg")))
              }
            }
      } yield out
}
