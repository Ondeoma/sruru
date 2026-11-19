package sruru.federation

import cats.effect.{IO, Ref}
import io.circe.Json
import io.circe.syntax.*
import munit.CatsEffectSuite
import org.http4s.*
import org.http4s.circe.CirceEntityEncoder.*
import org.http4s.client.Client
import org.typelevel.ci.CIString
import sruru.security.{Jose, SigningKey}

import java.time.Instant
import java.util.Base64

class FederationSpec extends CatsEffectSuite {

  private def key(
    kid: String
  ): SigningKey = {
    val kp = Jose.generate("RS256")
    SigningKey(kid, "RS256", kp.getPrivate, kp.getPublic, None)
  }

  private val k1 = key("k1")
  private val now = Instant.parse("2026-01-01T00:00:00Z")
  private val iss = "https://idp.test"
  private val nonce = "n-123"

  private def ok(
    j: Json
  ): IO[Response[IO]] = IO.pure(Response[IO](Status.Ok).withEntity(j))
  private val notFound: IO[Response[IO]] = IO.pure(Response[IO](Status.NotFound).withEntity("not found"))
  private def path(
    req: Request[IO]
  ) = req.uri.path.renderString
  private def auth(
    req: Request[IO]
  ) = req.headers.get(CIString("Authorization")).map(_.head.value)

  private def claims(
    extra: (String, Json)*
  ): Json =
    Json.obj(
      "iss" -> iss.asJson,
      "aud" -> "client-1".asJson,
      "sub" -> "user-1".asJson,
      "exp" -> (now.getEpochSecond + 300).asJson,
      "iat" -> now.getEpochSecond.asJson,
      "nonce" -> nonce.asJson,
      "email" -> "taro@example.com".asJson,
      "email_verified" -> true.asJson,
      "name" -> "山田 太郎".asJson
    ).deepMerge(Json.fromFields(extra))

  private val cfg =
    UpstreamConfig(iss, "client-1", "secret-1", "https://sruru.test/cb", List("openid", "email", "profile"))

  /** 偽の IdP. jwks は呼ばれるたびに次の鍵の組を返す（最後のものを繰り返す）. */
  private def idp(
    idToken: String,
    jwks: List[List[SigningKey]] = List(List(k1)),
    discoveryIssuer: String = iss,
    prefix: String = "",
    userinfo: Option[Json] = None
  ): IO[(Client[IO], Ref[IO, List[UrlForm]], Ref[IO, Int])] =
    for {
      forms <- Ref.of[IO, List[UrlForm]](Nil)
      calls <- Ref.of[IO, Int](0)
    } yield {
      val app = HttpApp[IO] { req =>
        path(req) match {
          case p if p == prefix + "/.well-known/openid-configuration" =>
            ok(Json.obj(
              "issuer" -> discoveryIssuer.asJson,
              "authorization_endpoint" -> "https://idp.test/authorize?x=1".asJson,
              "token_endpoint" -> "https://idp.test/token".asJson,
              "jwks_uri" -> "https://idp.test/jwks".asJson,
              "userinfo_endpoint" -> "https://idp.test/userinfo".asJson
            ))
          case "/jwks" =>
            calls.getAndUpdate(_ + 1).flatMap(n => ok(Json.obj("keys" -> jwks(n.min(jwks.size - 1)).map(_.jwk).asJson)))
          case "/token" =>
            req.as[UrlForm].flatMap(f => forms.update(f :: _)) >>
              ok(Json.obj("id_token" -> idToken.asJson, "access_token" -> "at-1".asJson))
          case "/userinfo" if auth(req).contains("Bearer at-1") => userinfo.fold(notFound)(ok)
          case _ => notFound
        }
      }
      (Client.fromHttpApp(app), forms, calls)
    }

  private def run(
    idToken: String,
    c: UpstreamConfig = cfg,
    userinfo: Option[Json] = None
  ): IO[UpstreamIdentity] =
    idp(idToken, userinfo = userinfo).flatMap(
      (
        client,
        _,
        _
      ) => UpstreamOidc(client).exchange(c, "code-1", "verifier-1", nonce, now)
    )

  // ------------------------------------------------------------------ OIDC

  test("OIDC: 認可 URL") {
    idp("x").flatMap {
      (
        client,
        _,
        _
      ) =>
        UpstreamOidc(client).authorizationUri(
          cfg.copy(extraAuthParams = Presets.googleParams(Some("example.com"))),
          "st",
          nonce,
          "verifier-1"
        ).map { u =>
          val q = u.query.params
          assertEquals(q.get("x"), Some("1"))
          assertEquals(q.get("response_type"), Some("code"))
          assertEquals(q.get("scope"), Some("openid email profile"))
          assertEquals(q.get("code_challenge"), Some(sruru.security.Crypto.pkceS256("verifier-1")))
          assertEquals(q.get("code_challenge_method"), Some("S256"))
          assertEquals(q.get("hd"), Some("example.com"))
          assertEquals(q.get("nonce"), Some(nonce))
        }
    }
  }

  test("OIDC: 成功（トークンの要求は client_secret_post と PKCE）") {
    val tok = Jose.sign(
      k1,
      claims("groups" -> List("a", "b").asJson, "amr" -> List("pwd", "mfa").asJson, "hd" -> "example.com".asJson)
    )
    idp(tok).flatMap {
      (
        client,
        forms,
        _
      ) =>
        UpstreamOidc(client).exchange(cfg, "code-1", "verifier-1", nonce, now).flatMap { id =>
          assertEquals(id.subject, "user-1")
          assertEquals(id.email, Some("taro@example.com"))
          assert(id.emailVerified)
          assertEquals(id.name, Some("山田 太郎"))
          assertEquals(id.groups, List("a", "b"))
          assertEquals(id.amr, List("pwd", "mfa"))
          assertEquals(id.hostedDomain, Some("example.com"))
          forms.get.map { fs =>
            val f = fs.head
            assertEquals(f.getFirst("client_secret"), Some("secret-1"))
            assertEquals(f.getFirst("code_verifier"), Some("verifier-1"))
            assertEquals(f.getFirst("grant_type"), Some("authorization_code"))
          }
        }
    }
  }

  private def fails(
    io: IO[?],
    msg: String
  ): IO[Unit] =
    io.attempt.map {
      case Left(e) => assert(e.getMessage.contains(msg), e.getMessage)
      case Right(v) => fail(s"成功してしまった: $v")
    }

  test("OIDC: nonce 違い・aud 違い・署名違い・期限切れは失敗") {
    for {
      _ <- fails(run(Jose.sign(k1, claims("nonce" -> "other".asJson))), "nonce")
      _ <- fails(run(Jose.sign(k1, claims("aud" -> "client-2".asJson))), "aud")
      _ <- fails(run(Jose.sign(k1, claims("aud" -> List("client-1", "x").asJson))), "azp")
      _ <- fails(run(Jose.sign(key("k1"), claims())), "署名")
      _ <- fails(run(Jose.sign(k1, claims("exp" -> (now.getEpochSecond - 120).asJson))), "期限")
      _ <- fails(run(Jose.sign(k1, claims("iss" -> "https://evil.test".asJson))), "iss")
      _ <- run(Jose.sign(k1, claims("aud" -> List("client-1", "x").asJson, "azp" -> "client-1".asJson)))
      _ <- run(Jose.sign(k1, claims("exp" -> (now.getEpochSecond - 30).asJson))) // 猶予の内
    } yield ()
  }

  test("OIDC: 知らない kid なら JWKS を一度だけ取り直す") {
    val k2 = key("k2")
    idp(Jose.sign(k2, claims()), jwks = List(List(k1), List(k1, k2))).flatMap {
      (
        client,
        _,
        calls
      ) =>
        UpstreamOidc(client).exchange(cfg, "c", "v", nonce, now).flatMap(id =>
          calls.get.map(n => assertEquals((id.subject, n), ("user-1", 2)))
        )
    } >> idp(Jose.sign(key("k3"), claims())).flatMap {
      (
        client,
        _,
        calls
      ) =>
        fails(UpstreamOidc(client).exchange(cfg, "c", "v", nonce, now), "署名") >> calls.get.map(assertEquals(_, 2))
    }
  }

  test("OIDC: subjectClaim に oid") {
    for {
      id <- run(Jose.sign(k1, claims("oid" -> "oid-9".asJson)), cfg.copy(subjectClaim = "oid"))
      _ = assertEquals(id.subject, "oid-9")
      _ <- fails(run(Jose.sign(k1, claims()), cfg.copy(subjectClaim = "oid")), "oid")
    } yield ()
  }

  test("OIDC: メールアドレスがなければ userinfo で補う（sub が違えば失敗）") {
    val tok = Jose.sign(k1, claims().mapObject(_.remove("email").remove("email_verified")))
    for {
      id <- run(
        tok,
        userinfo = Some(Json.obj("sub" -> "user-1".asJson, "email" -> "u@example.com".asJson, "name" -> "別名".asJson))
      )
      _ = assertEquals(id.email, Some("u@example.com"))
      _ = assertEquals(id.name, Some("山田 太郎")) // ID トークンが優先
      _ <-
        fails(run(tok, userinfo = Some(Json.obj("sub" -> "user-2".asJson, "email" -> "u@example.com".asJson))), "sub")
    } yield ()
  }

  test("OIDC: Entra のマルチテナント（{tenantid}）") {
    val common = "https://login.microsoftonline.com/common/v2.0"
    val tmpl = "https://login.microsoftonline.com/{tenantid}/v2.0"
    val c = Presets.entra("common").config("client-1", "s", "https://sruru.test/cb")
    val good =
      claims("iss" -> "https://login.microsoftonline.com/t-1/v2.0".asJson, "tid" -> "t-1".asJson, "oid" -> "o-1".asJson)
    val bad = good.deepMerge(Json.obj("tid" -> "t-2".asJson))
    for {
      r1 <- idp(Jose.sign(k1, good), discoveryIssuer = tmpl, prefix = "/common/v2.0")
      id <- UpstreamOidc(r1._1).exchange(c, "c", "v", nonce, now)
      _ = assertEquals((id.subject, id.tenantId), ("o-1", Some("t-1")))
      r2 <- idp(Jose.sign(k1, bad), discoveryIssuer = tmpl, prefix = "/common/v2.0")
      _ <- fails(UpstreamOidc(r2._1).exchange(c, "c", "v", nonce, now), "iss")
      // シングルテナントでは {tenantid} の discovery を受け付けない
      r3 <- idp(Jose.sign(k1, good), discoveryIssuer = tmpl, prefix = "/t-1/v2.0")
      _ <- fails(
        UpstreamOidc(r3._1).exchange(Presets.entra("t-1").config("client-1", "s", "x"), "c", "v", nonce, now),
        "issuer"
      )
    } yield assertEquals(common, Presets.entra("common").issuer)
  }

  // ------------------------------------------------------------------ Google

  private val gkp = Jose.generate("RS256")
  private val pem =
    "-----BEGIN PRIVATE KEY-----\n" +
      Base64.getMimeEncoder(64, "\n".getBytes).encodeToString(gkp.getPrivate.getEncoded) +
      "\n-----END PRIVATE KEY-----\n"
  private val saJson = Json.obj(
    "type" -> "service_account".asJson,
    "client_email" -> "sync@proj.iam.gserviceaccount.com".asJson,
    "private_key_id" -> "pk-1".asJson,
    "private_key" -> pem.asJson,
    "token_uri" -> "https://oauth2.googleapis.com/token".asJson
  ).noSpaces

  private def gUser(
    id: String,
    email: String,
    extra: (String, Json)*
  ): Json =
    Json.obj(
      "id" -> id.asJson,
      "primaryEmail" -> email.asJson,
      "name" -> Json.obj("fullName" -> s"name $id".asJson, "givenName" -> "g".asJson, "familyName" -> "f".asJson)
    ).deepMerge(Json.fromFields(extra))

  test("Google: JWT の認可・利用者とメンバーのページ送り・停止中の利用者") {
    for {
      tokenCalls <- Ref.of[IO, Int](0)
      assertion <- Ref.of[IO, Option[Json]](None)
      app = HttpApp[IO] { req =>
        val q = req.uri.query.params
        if path(req) == "/token" then
          req.as[UrlForm].flatMap { f =>
            val a = f.getFirst("assertion").get
            assertEquals(f.getFirst("grant_type"), Some("urn:ietf:params:oauth:grant-type:jwt-bearer"))
            assertEquals(Jose.header(a).toOption.flatMap(_.hcursor.get[String]("kid").toOption), Some("pk-1"))
            tokenCalls.update(_ + 1) >> assertion.set(Jose.verifyWith(a, gkp.getPublic).toOption) >>
              ok(Json.obj("access_token" -> "gat".asJson, "expires_in" -> 3600.asJson))
          }
        else if !auth(req).contains("Bearer gat") then IO.pure(Response[IO](Status.Unauthorized))
        else
          path(req) match {
            case "/admin/directory/v1/users" =>
              assertEquals(q.get("customer"), Some("C123"))
              assertEquals(q.get("projection"), Some("full"))
              q.get("pageToken") match {
                case None => ok(Json.obj(
                    "users" -> List(gUser(
                      "1",
                      "a@example.com",
                      "organizations" -> Json.arr(Json.obj(
                        "department" -> "営業".asJson,
                        "title" -> "主任".asJson,
                        "primary" -> true.asJson
                      )),
                      "relations" ->
                        Json.arr(Json.obj("type" -> "manager".asJson, "value" -> "boss@example.com".asJson)),
                      "thumbnailPhotoUrl" -> "https://x/photo".asJson
                    )).asJson,
                    "nextPageToken" -> "p2".asJson
                  ))
                case Some("p2") =>
                  ok(Json.obj("users" -> List(gUser("2", "b@example.com", "suspended" -> true.asJson)).asJson))
                case _ => notFound
              }
            case "/admin/directory/v1/groups" =>
              ok(Json.obj("groups" -> Json.arr(Json.obj(
                "id" -> "g1".asJson,
                "email" -> "sales@example.com".asJson,
                "name" -> "営業部".asJson,
                "description" -> "説明".asJson
              ))))
            case "/admin/directory/v1/groups/g1/members" =>
              q.get("pageToken") match {
                case None => ok(Json.obj(
                    "members" -> Json.arr(
                      Json.obj("id" -> "1".asJson, "type" -> "USER".asJson),
                      Json.obj("id" -> "g9".asJson, "type" -> "GROUP".asJson)
                    ),
                    "nextPageToken" -> "m2".asJson
                  ))
                case Some("m2") => ok(Json.obj("members" -> Json.arr(
                    Json.obj("id" -> "2".asJson, "type" -> "USER".asJson),
                    Json.obj("id" -> "outsider".asJson, "type" -> "USER".asJson)
                  )))
                case _ => notFound
              }
            case "/admin/directory/v1/users/1/photos/thumbnail" =>
              ok(Json.obj(
                "photoData" -> Base64.getUrlEncoder.encodeToString(Array[Byte](1, 2, 3, -1)).asJson,
                "mimeType" -> "image/png".asJson
              ))
            case _ => notFound
          }
      }
      src <- IO.fromEither(DirectorySources.from(
        "google",
        Json.obj(
          "serviceAccountJson" -> saJson.asJson,
          "adminEmail" -> "admin@example.com".asJson,
          "customer" -> "C123".asJson
        ),
        Client.fromHttpApp(app)
      ).left.map(new RuntimeException(_)))
      snap <- src.fetch
      a <- assertion.get
      n <- tokenCalls.get
      pic <- src.photo(snap.users.head)
      none <- src.photo(snap.users(1))
    } yield {
      val c = a.get.hcursor
      assertEquals(c.get[String]("iss").toOption, Some("sync@proj.iam.gserviceaccount.com"))
      assertEquals(c.get[String]("sub").toOption, Some("admin@example.com"))
      assertEquals(c.get[String]("aud").toOption, Some("https://oauth2.googleapis.com/token"))
      assertEquals(c.get[String]("scope").toOption, Some(GoogleDirectory.Scopes.mkString(" ")))
      assertEquals(n, 1)
      assertEquals(
        snap.users.map(u => (u.externalId, u.username, u.active)),
        List(("1", "a@example.com", true), ("2", "b@example.com", false))
      )
      val u1 = snap.users.head.attributes.hcursor
      assertEquals(u1.get[String]("department").toOption, Some("営業"))
      assertEquals(u1.get[String]("jobTitle").toOption, Some("主任"))
      assertEquals(u1.get[String]("manager").toOption, Some("boss@example.com"))
      assertEquals(
        snap.groups.map(g => (g.externalId, g.name, g.email, g.memberUserIds)),
        List(("g1", "営業部", Some("sales@example.com"), List("1", "2")))
      )
      assertEquals(
        pic.map(
          (
            b,
            t
          ) => (b.toList, t)
        ),
        Some((List[Byte](1, 2, 3, -1), "image/png"))
      )
      assertEquals(none, None)
    }
  }

  test("Google: 設定の誤り") {
    val http = Client.fromHttpApp(HttpApp[IO](_ => notFound))
    assert(DirectorySources.from(
      "google",
      Json.obj("serviceAccountJson" -> "{}".asJson, "adminEmail" -> "a".asJson),
      http
    ).isLeft)
    assert(DirectorySources.from("google", Json.obj("serviceAccountJson" -> saJson.asJson), http).isLeft)
    assert(DirectorySources.from("ldap", Json.obj(), http).isLeft)
  }

  // ------------------------------------------------------------------ Entra

  test("Entra: トークンの要求・nextLink のページ送り・transitiveMembers・写真なし・429 の再送") {
    for {
      form <- Ref.of[IO, Option[UrlForm]](None)
      throttled <- Ref.of[IO, Boolean](false)
      seen <- Ref.of[IO, List[String]](Nil)
      app = HttpApp[IO] { req =>
        val q = req.uri.query.params
        seen.update(req.uri.renderString :: _) >>
          (path(req) match {
            case "/tid-1/oauth2/v2.0/token" =>
              req.as[UrlForm].flatMap(f => form.set(Some(f))) >>
                ok(Json.obj("access_token" -> "eat".asJson, "expires_in" -> 3599.asJson))
            case _ if !auth(req).contains("Bearer eat") => IO.pure(Response[IO](Status.Unauthorized))
            case "/v1.0/users" =>
              throttled.getAndSet(true).flatMap { done =>
                if !done then
                  IO.pure(Response[IO](Status.TooManyRequests).putHeaders(Header.Raw(CIString("Retry-After"), "0")))
                else if q.get("$skiptoken").contains("abc") then
                  ok(Json.obj("value" -> Json.arr(Json.obj(
                    "id" -> "u2".asJson,
                    "userPrincipalName" -> "b@contoso.com".asJson,
                    "accountEnabled" -> false.asJson
                  ))))
                else {
                  assertEquals(q.get("$top"), Some("999"))
                  ok(Json.obj(
                    "value" -> Json.arr(Json.obj(
                      "id" -> "u1".asJson,
                      "userPrincipalName" -> "a@contoso.com".asJson,
                      "mail" -> "a.mail@contoso.com".asJson,
                      "displayName" -> "A さん".asJson,
                      "department" -> "開発".asJson,
                      "accountEnabled" -> true.asJson
                    )),
                    "@odata.nextLink" -> "https://graph.microsoft.com/v1.0/users?$skiptoken=abc".asJson
                  ))
                }
              }
            case "/v1.0/groups" =>
              ok(Json.obj("value" -> Json.arr(Json.obj("id" -> "g1".asJson, "displayName" -> "開発部".asJson))))
            case "/v1.0/groups/g1/transitiveMembers/microsoft.graph.user" =>
              if q.contains("$skiptoken") then ok(Json.obj("value" -> Json.arr(Json.obj("id" -> "u2".asJson))))
              else
                ok(Json.obj(
                  "value" -> Json.arr(Json.obj("id" -> "u1".asJson)),
                  "@odata.nextLink" ->
                    "https://graph.microsoft.com/v1.0/groups/g1/transitiveMembers/microsoft.graph.user?$skiptoken=x".asJson
                ))
            case p if p.startsWith("/v1.0/users/u1/photo/") => notFound
            case p if p.startsWith("/v1.0/users/u2/photo/") =>
              IO.pure(Response[IO](Status.Ok).withEntity(Array[Byte](
                9,
                8,
                7
              ))(using EntityEncoder.byteArrayEncoder).withContentType(headers.`Content-Type`(MediaType.image.png)))
            case _ => notFound
          })
      }
      src <- IO.fromEither(DirectorySources.from(
        "entra",
        Json.obj(
          "tenantId" -> "tid-1".asJson,
          "clientId" -> "cid".asJson,
          "clientSecret" -> "csec".asJson
        ),
        Client.fromHttpApp(app)
      ).left.map(new RuntimeException(_)))
      snap <- src.fetch
      f <- form.get
      p1 <- src.photo(snap.users.head)
      p2 <- src.photo(snap.users(1))
      urls <- seen.get
    } yield {
      assertEquals(f.flatMap(_.getFirst("grant_type")), Some("client_credentials"))
      assertEquals(f.flatMap(_.getFirst("scope")), Some("https://graph.microsoft.com/.default"))
      assertEquals(f.flatMap(_.getFirst("client_id")), Some("cid"))
      assertEquals(f.flatMap(_.getFirst("client_secret")), Some("csec"))
      assertEquals(
        snap.users.map(u => (u.externalId, u.username, u.email, u.active)),
        List(
          ("u1", "a@contoso.com", Some("a.mail@contoso.com"), true),
          ("u2", "b@contoso.com", Some("b@contoso.com"), false)
        )
      )
      assertEquals(snap.users.head.attributes.hcursor.get[String]("department").toOption, Some("開発"))
      assertEquals(snap.groups.map(g => (g.name, g.memberUserIds)), List(("開発部", List("u1", "u2"))))
      assertEquals(p1, None)
      assertEquals(
        p2.map(
          (
            b,
            t
          ) => (b.toList, t)
        ),
        Some((List[Byte](9, 8, 7), "image/png"))
      )
      assert(urls.exists(_.contains("$select=id,userPrincipalName")), urls.mkString("\n"))
      assert(urls.exists(_.endsWith("/photo/$value")), urls.mkString("\n"))
    }
  }

  test("上流の URL は https だけ（http://localhost の issuer のときだけ localhost も）") {
    def u(
      s: String
    ) = Uri.unsafeFromString(s)
    assert(UpstreamOidc.safeEndpoint("https://idp.test", u("https://idp.test/token")))
    assert(!UpstreamOidc.safeEndpoint("https://idp.test", u("http://169.254.169.254/latest")))
    assert(UpstreamOidc.safeEndpoint("http://localhost:9000", u("http://localhost:9000/token")))
    assert(!UpstreamOidc.safeEndpoint("http://localhost:9000", u("http://10.0.0.1/token")))
    assert(!UpstreamOidc.isLocalHttp("http://localhost@169.254.169.254/"))
    assert(!UpstreamOidc.isLocalHttp("http://localhost.evil.test/"))
  }
}
