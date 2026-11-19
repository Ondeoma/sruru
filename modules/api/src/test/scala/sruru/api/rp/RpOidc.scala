package sruru.api.rp

// 一般的な Web アプリの OIDC クライアント（RP）の実装. sruru と組み合わせて動くことを確かめるためだけに使う.

import cats.effect.*
import cats.syntax.all.*
import io.circe.Json
import io.circe.parser.parse
import org.http4s.*
import org.http4s.circe.CirceEntityDecoder.*
import org.http4s.client.Client

import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.spec.{ECGenParameterSpec, ECParameterSpec, ECPoint, ECPublicKeySpec, RSAPublicKeySpec}
import java.security.{AlgorithmParameters, KeyFactory, PublicKey, Signature}
import java.time.Instant
import java.util.Base64

final case class OidcConfig(
  issuer: String,
  clientId: String,
  clientSecret: String,
  redirectUri: String,
  groupsClaim: String = "groups",
  scopes: List[String] = List("openid", "profile", "email"),
  /** ログインを許すグループ（空ならだれでも） */
  allowedGroups: Set[String] = Set.empty)

final case class Identity(
  sub: String,
  email: Option[String],
  name: String,
  groups: List[String],
  picture: Option[String] = None)

final case class ProviderMetadata(
  issuer: String,
  authorizationEndpoint: Uri,
  tokenEndpoint: Uri,
  jwksUri: Option[Uri],
  endSessionEndpoint: Option[Uri])

/** ID トークン（JWT）の読み取りと検証. */
object IdToken {
  private val dec = Base64.getUrlDecoder

  private def part(
    jwt: String,
    i: Int
  ): Either[String, Json] =
    jwt.split('.').lift(i).toRight("malformed id_token").flatMap { p =>
      Either.catchNonFatal(new String(dec.decode(p), StandardCharsets.UTF_8)).leftMap(_ => "invalid base64 in id_token")
        .flatMap(parse(_).leftMap(e => s"invalid json in id_token: ${e.getMessage}"))
    }

  def decodeHeader(
    jwt: String
  ): Either[String, Json] = part(jwt, 0)
  def decodeClaims(
    jwt: String
  ): Either[String, Json] = part(jwt, 1)

  def validate(
    claims: Json,
    issuer: String,
    cfg: OidcConfig,
    expectedNonce: String,
    now: Instant
  ): Either[String, Identity] = {
    val c = claims.hcursor
    for {
      iss <- c.get[String]("iss").leftMap(_ => "missing iss")
      _ <- Either.cond(iss == issuer, (), s"issuer mismatch: $iss")
      aud <- c.downField("aud").focus.toRight("missing aud").flatMap { j =>
        j.asString.map(List(_)).orElse(j.asArray.map(_.toList.flatMap(_.asString))).toRight("invalid aud")
      }
      _ <- Either.cond(aud.contains(cfg.clientId), (), "audience mismatch")
      // 複数の aud があるときは、azp が自分であること（OIDC Core 3.1.3.7）
      _ <- Either.cond(aud.size == 1 || c.get[String]("azp").toOption.contains(cfg.clientId), (), "azp mismatch")
      exp <- c.get[Long]("exp").leftMap(_ => "missing exp")
      _ <- Either.cond(Instant.ofEpochSecond(exp).plusSeconds(60).isAfter(now), (), "id_token expired")
      non <- c.get[String]("nonce").leftMap(_ => "missing nonce")
      _ <- Either.cond(Crypto.constantTimeEquals(non, expectedNonce), (), "nonce mismatch")
      sub <- c.get[String]("sub").leftMap(_ => "missing sub")
    } yield {
      val email = c.get[String]("email").toOption
      val name = c.get[String]("name").toOption.filter(_.nonEmpty)
        .orElse(c.get[String]("preferred_username").toOption)
        .orElse(email)
        .getOrElse(sub)
      val groups = c.downField(cfg.groupsClaim).as[List[String]].getOrElse(Nil)
      Identity(sub, email, name, groups, c.get[String]("picture").toOption)
    }
  }
}

/** JWS の署名の検証（RS256/384/512・ES256/384/512・HS256/384/512）. 鍵は JWKS（JSON Web Key Set）. */
object Jws {
  private val dec = Base64.getUrlDecoder

  private def bigInt(
    s: String
  ): BigInteger = new BigInteger(1, dec.decode(s))

  /** JWK の公開鍵. */
  def publicKey(
    jwk: Json
  ): Either[String, PublicKey] = {
    val c = jwk.hcursor
    c.get[String]("kty").leftMap(_ => "jwk without kty").flatMap {
      case "RSA" =>
        (c.get[String]("n"), c.get[String]("e")).tupled.leftMap(_ => "invalid RSA jwk").flatMap {
          (
            n,
            e
          ) =>
            Either.catchNonFatal(KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(
              bigInt(n),
              bigInt(e)
            ))).leftMap(_.getMessage)
        }
      case "EC" =>
        (c.get[String]("crv"), c.get[String]("x"), c.get[String]("y")).tupled.leftMap(_ => "invalid EC jwk").flatMap {
          (
            crv,
            x,
            y
          ) =>
            val name = crv match {
              case "P-256" => "secp256r1"
              case "P-384" => "secp384r1"
              case "P-521" => "secp521r1"
              case other => other
            }
            Either.catchNonFatal {
              val params = AlgorithmParameters.getInstance("EC")
              params.init(new ECGenParameterSpec(name))
              val spec = params.getParameterSpec(classOf[ECParameterSpec])
              KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(bigInt(x), bigInt(y)), spec))
            }.leftMap(_.getMessage)
        }
      case other => Left(s"unsupported jwk kty: $other")
    }
  }

  private def javaAlg(
    alg: String
  ): Option[String] = alg match {
    case "RS256" => Some("SHA256withRSA")
    case "RS384" => Some("SHA384withRSA")
    case "RS512" => Some("SHA512withRSA")
    // JWS の ECDSA の署名は r||s をそのまま並べた形（P1363）
    case "ES256" => Some("SHA256withECDSAinP1363Format")
    case "ES384" => Some("SHA384withECDSAinP1363Format")
    case "ES512" => Some("SHA512withECDSAinP1363Format")
    case _ => None
  }

  /**
   * 署名を検証する. alg が none のトークンは受け付けない.
   * HS* はクライアントシークレットを鍵にする（OIDC Core 10.1）.
   */
  def verify(
    jwt: String,
    jwks: List[Json],
    clientSecret: String
  ): Either[String, Unit] =
    jwt.split('.') match {
      case Array(h, p, s) =>
        val input = s"$h.$p".getBytes(StandardCharsets.US_ASCII)
        for {
          header <- IdToken.decodeHeader(jwt)
          alg <- header.hcursor.get[String]("alg").leftMap(_ => "id_token without alg")
          sig <- Either.catchNonFatal(dec.decode(s)).leftMap(_ => "invalid signature encoding")
          _ <- alg match {
            case "HS256" | "HS384" | "HS512" =>
              val mac = javax.crypto.Mac.getInstance("Hmac" + alg.replace("HS", "SHA"))
              mac.init(new javax.crypto.spec.SecretKeySpec(
                clientSecret.getBytes(StandardCharsets.UTF_8),
                mac.getAlgorithm
              ))
              Either.cond(
                java.security.MessageDigest.isEqual(mac.doFinal(input), sig),
                (),
                "invalid id_token signature"
              )
            case other =>
              for {
                ja <- javaAlg(other).toRight(s"unsupported id_token alg: $other")
                kid = header.hcursor.get[String]("kid").toOption
                kty = if other.startsWith("RS") then "RSA" else "EC"
                candidates = jwks.filter { k =>
                  val kc = k.hcursor
                  kc.get[String]("kty").toOption.contains(kty) &&
                  kc.get[String]("use").toOption.forall(_ == "sig") &&
                  kid.forall(id => kc.get[String]("kid").toOption.contains(id))
                }
                _ <- Either.cond(candidates.nonEmpty, (), s"no matching key in jwks (kid=${kid.getOrElse("-")})")
                ok = candidates.exists { k =>
                  publicKey(k).toOption.exists { pk =>
                    scala.util.Try {
                      val v = Signature.getInstance(ja)
                      v.initVerify(pk)
                      v.update(input)
                      v.verify(sig)
                    }.getOrElse(false)
                  }
                }
                _ <- Either.cond(ok, (), "invalid id_token signature")
              } yield ()
          }
        } yield ()
      case _ => Left("malformed id_token")
    }
}

/** ログインの結果. idToken はログアウトのとき IdP に渡す（id_token_hint）. */
final case class LoginResult(
  identity: Identity,
  idToken: String)

/** OIDC プロバイダ向けのクライアント（Authorization Code + PKCE + nonce. ID トークンは署名・iss・aud・exp・nonce を検証する）. */
final class OidcClient private (
  cfg: OidcConfig,
  http: Client[IO],
  meta: Ref[IO, Option[ProviderMetadata]],
  keys: Ref[IO, List[Json]]) {

  def config: OidcConfig = cfg

  def discover: IO[ProviderMetadata] = meta.get.flatMap {
    case Some(m) => IO.pure(m)
    case None =>
      val url = Uri.unsafeFromString(cfg.issuer.stripSuffix("/") + "/.well-known/openid-configuration")
      http.expect[Json](url).flatMap { j =>
        val c = j.hcursor
        def uri(
          name: String
        ) = c.get[String](name).toOption.flatMap(s => Uri.fromString(s).toOption)
        val res = for {
          iss <- c.get[String]("issuer").leftMap(_ => "discovery: missing issuer")
          auth <- uri("authorization_endpoint").toRight("discovery: missing authorization_endpoint")
          tok <- uri("token_endpoint").toRight("discovery: missing token_endpoint")
          _ <-
            Either.cond(iss.stripSuffix("/") == cfg.issuer.stripSuffix("/"), (), s"discovery: issuer mismatch ($iss)")
        } yield ProviderMetadata(iss, auth, tok, uri("jwks_uri"), uri("end_session_endpoint"))
        IO.fromEither(res.leftMap(new RuntimeException(_))).flatTap(m => meta.set(Some(m)))
      }
  }

  private def fetchKeys(
    m: ProviderMetadata
  ): IO[List[Json]] =
    m.jwksUri.fold(IO.pure(List.empty[Json]))(u =>
      http.expect[Json](u).map(_.hcursor.get[List[Json]]("keys").getOrElse(Nil))
    )
      .flatTap(keys.set)

  /** 署名を検証する. 鍵が見つからなければ JWKS を取り直してもう一度（IdP の鍵の入れ替え）. */
  private def verifySignature(
    m: ProviderMetadata,
    idToken: String
  ): IO[Unit] =
    keys.get.flatMap(ks => if ks.isEmpty then fetchKeys(m) else IO.pure(ks)).flatMap { ks =>
      Jws.verify(idToken, ks, cfg.clientSecret) match {
        case Right(_) => IO.unit
        case Left(_) =>
          fetchKeys(m).flatMap(ks2 =>
            IO.fromEither(Jws.verify(idToken, ks2, cfg.clientSecret).leftMap(new RuntimeException(_)))
          )
      }
    }

  def authorizationUri(
    state: String,
    verifier: String,
    nonce: String
  ): IO[Uri] =
    discover.map { m =>
      m.authorizationEndpoint.withQueryParams(
        Map(
          "response_type" -> "code",
          "client_id" -> cfg.clientId,
          "redirect_uri" -> cfg.redirectUri,
          "scope" -> cfg.scopes.mkString(" "),
          "state" -> state,
          "nonce" -> nonce,
          "code_challenge" -> Crypto.pkceChallenge(verifier),
          "code_challenge_method" -> "S256"
        )
      )
    }

  /** 認可コードを ID トークンに交換し、検証済みの Identity を返す. */
  def authenticate(
    code: String,
    verifier: String,
    nonce: String,
    now: Instant
  ): IO[LoginResult] =
    for {
      m <- discover
      req = Request[IO](Method.POST, m.tokenEndpoint).withEntity(
        UrlForm(
          "grant_type" -> "authorization_code",
          "code" -> code,
          "redirect_uri" -> cfg.redirectUri,
          "client_id" -> cfg.clientId,
          "client_secret" -> cfg.clientSecret,
          "code_verifier" -> verifier
        )
      )
      resp <- http.expect[Json](req)
      idToken <-
        IO.fromEither(resp.hcursor.get[String]("id_token").leftMap(e => new RuntimeException(s"no id_token: $e")))
      _ <- verifySignature(m, idToken)
      claims <- IO.fromEither(IdToken.decodeClaims(idToken).leftMap(new RuntimeException(_)))
      id <- IO.fromEither(IdToken.validate(claims, m.issuer, cfg, nonce, now).leftMap(new RuntimeException(_)))
      _ <- IO.raiseUnless(cfg.allowedGroups.isEmpty || id.groups.exists(cfg.allowedGroups.contains))(
        new RuntimeException("このサービスを使えるグループに所属していません")
      )
    } yield LoginResult(id, idToken)

  /** IdP からもログアウトする URL（end_session_endpoint がなければ None）. */
  def logoutUri(
    idToken: Option[String],
    postLogout: String
  ): IO[Option[Uri]] =
    discover.attempt.map(_.toOption.flatMap(_.endSessionEndpoint).map { e =>
      e.withQueryParams(Map("post_logout_redirect_uri" -> postLogout, "client_id" -> cfg.clientId) ++
        idToken.map("id_token_hint" -> _))
    })
}

object OidcClient {
  def create(
    cfg: OidcConfig,
    http: Client[IO]
  ): IO[OidcClient] =
    (Ref.of[IO, Option[ProviderMetadata]](None), Ref.of[IO, List[Json]](Nil)).mapN(new OidcClient(cfg, http, _, _))
}

private object Crypto {
  def constantTimeEquals(
    a: String,
    b: String
  ): Boolean = sruru.security.Crypto.constantTimeEquals(a, b)
  def pkceChallenge(
    v: String
  ): String = sruru.security.Crypto.pkceS256(v)
}
