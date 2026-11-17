package sruru.api

import cats.effect.*
import io.circe.Json
import io.circe.syntax.*
import munit.CatsEffectSuite
import org.http4s.*
import org.http4s.circe.CirceEntityCodec.*
import org.http4s.ember.client.EmberClientBuilder
import org.http4s.headers.Location
import sruru.api.rp.{OidcClient, OidcConfig}

/**
 * 独立した OIDC クライアント（rp/RpOidc.scala）で、起動中の sruru にログインできることを確かめる.
 * SRURU_URL（例 http://localhost:9100）と SRURU_ADMIN_USER・SRURU_ADMIN_PASS がなければ飛ばす.
 */
class RpCompatSpec extends CatsEffectSuite:

  private given org.typelevel.log4cats.LoggerFactory[IO] = org.typelevel.log4cats.noop.NoOpFactory[IO]

  private val base = sys.env.get("SRURU_URL")
  private val user = sys.env.getOrElse("SRURU_ADMIN_USER", "admin")
  private val pass = sys.env.getOrElse("SRURU_ADMIN_PASS", "")

  test("OIDC クライアント（JWKS の署名の検証・nonce・PKCE）でログインできる") {
    base match
      case None => IO(assume(false, "SRURU_URL が未設定"))
      case Some(b) =>
        EmberClientBuilder.default[IO].build.use { http =>
          def cookies(r: Response[IO]): String = r.cookies.map(c => s"${c.name}=${c.content}").mkString("; ")
          def post(path: String, body: Json, cookie: String) =
            Request[IO](Method.POST, Uri.unsafeFromString(b + path)).withEntity(body).putHeaders("X-Sruru" -> "1", "Cookie" -> cookie)
          for
            start   <- http.run(post("/api/login/start", Json.obj(), "")).use(r => r.as[Json].map(j => (cookies(r), j.hcursor.get[String]("id").toOption.get)))
            (ck0, fid) = start
            // ログインの完了で Cookie の値が新しくなる（セッションの固定化の対策）
            ck      <- http.run(post("/api/login/password", Json.obj("flowId" -> fid.asJson, "username" -> user.asJson, "password" -> pass.asJson), ck0))
                         .use(r => IO(Option(cookies(r)).filter(_.nonEmpty).getOrElse(ck0)))
            slug     = "rp-" + java.util.UUID.randomUUID().toString.take(8)
            created <- http.expect[Json](post("/api/admin/apps", Json.obj("slug" -> slug.asJson, "name" -> "RP".asJson, "protocol" -> "oidc".asJson,
                         "oidc" -> Json.obj("clientId" -> slug.asJson, "confidential" -> true.asJson,
                           "redirectUris" -> List("http://localhost:1/auth/callback").asJson)), ck))
            secret   = created.hcursor.get[String]("clientSecret").toOption.get
            rp      <- OidcClient.create(OidcConfig(b, slug, secret, "http://localhost:1/auth/callback"), http)
            authUri <- rp.authorizationUri("st", "verifier-0123456789-0123456789-0123456789-abc", "nonce-1")
            loc     <- http.run(Request[IO](Method.GET, authUri).putHeaders("Cookie" -> ck)).use(r => IO(r.headers.get[Location].get.uri))
            code     = loc.query.params("code")
            res     <- rp.authenticate(code, "verifier-0123456789-0123456789-0123456789-abc", "nonce-1", java.time.Instant.now())
          yield
            assertEquals(res.identity.name.nonEmpty, true)
            assert(res.identity.email.isDefined)
            assertEquals(loc.query.params.get("state"), Some("st"))
        }
  }
