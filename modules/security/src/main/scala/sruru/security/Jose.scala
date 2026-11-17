package sruru.security

import cats.syntax.all.*
import io.circe.Json
import io.circe.parser.parse
import io.circe.syntax.*
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.{JcaX509CertificateConverter, JcaX509v3CertificateBuilder}
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder

import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.*
import java.security.cert.{CertificateFactory, X509Certificate}
import java.security.interfaces.{ECPublicKey, RSAPublicKey}
import java.security.spec.*
import java.time.Instant
import java.util.{Base64, Date}

/** 署名鍵（秘密鍵は PKCS#8 の DER を base64 にして保存する）. */
final case class SigningKey(kid: String, alg: String, privateKey: PrivateKey, publicKey: PublicKey, cert: Option[X509Certificate]):
  def jwk: Json = Jose.publicJwk(kid, alg, publicKey)

object Jose:
  private val enc = Crypto.b64url
  private val dec = Crypto.b64urlDec

  private def b64(b: BigInteger): String =
    val raw = b.toByteArray
    enc.encodeToString(if raw.length > 1 && raw(0) == 0 then raw.drop(1) else raw)

  private def big(s: String): BigInteger = new BigInteger(1, dec.decode(s))

  // ------------------------------------------------------------------ 鍵

  def generate(alg: String): KeyPair = alg match
    case "ES256" =>
      val g = KeyPairGenerator.getInstance("EC")
      g.initialize(new ECGenParameterSpec("secp256r1"))
      g.generateKeyPair()
    case _ =>
      val g = KeyPairGenerator.getInstance("RSA")
      g.initialize(2048)
      g.generateKeyPair()

  def newKid(): String = Crypto.randomToken(12)

  def publicJwk(kid: String, alg: String, pk: PublicKey): Json = pk match
    case r: RSAPublicKey =>
      Json.obj("kty" -> "RSA".asJson, "kid" -> kid.asJson, "use" -> "sig".asJson, "alg" -> alg.asJson,
        "n" -> b64(r.getModulus).asJson, "e" -> b64(r.getPublicExponent).asJson)
    case e: ECPublicKey =>
      def coord(b: BigInteger) =
        val raw = b.toByteArray.dropWhile(_ == 0)
        enc.encodeToString(Array.fill[Byte](32 - raw.length)(0) ++ raw)
      Json.obj("kty" -> "EC".asJson, "kid" -> kid.asJson, "use" -> "sig".asJson, "alg" -> alg.asJson, "crv" -> "P-256".asJson,
        "x" -> coord(e.getW.getAffineX).asJson, "y" -> coord(e.getW.getAffineY).asJson)
    case _ => Json.obj()

  def publicKey(jwk: Json): Either[String, PublicKey] =
    val c = jwk.hcursor
    c.get[String]("kty").leftMap(_ => "jwk without kty").flatMap {
      case "RSA" =>
        (c.get[String]("n"), c.get[String]("e")).tupled.leftMap(_ => "invalid RSA jwk").flatMap { (n, e) =>
          Either.catchNonFatal(KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(big(n), big(e)))).leftMap(_.getMessage)
        }
      case "EC" =>
        (c.get[String]("crv"), c.get[String]("x"), c.get[String]("y")).tupled.leftMap(_ => "invalid EC jwk").flatMap { (crv, x, y) =>
          val name = crv match
            case "P-256" => "secp256r1"
            case "P-384" => "secp384r1"
            case "P-521" => "secp521r1"
            case other   => other
          Either.catchNonFatal {
            val params = AlgorithmParameters.getInstance("EC")
            params.init(new ECGenParameterSpec(name))
            val spec = params.getParameterSpec(classOf[ECParameterSpec])
            KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(big(x), big(y)), spec))
          }.leftMap(_.getMessage)
        }
      case other => Left(s"unsupported jwk kty: $other")
    }

  def encodePrivate(k: PrivateKey): String = Base64.getEncoder.encodeToString(k.getEncoded)

  def decodePrivate(alg: String, s: String): PrivateKey =
    KeyFactory.getInstance(if alg.startsWith("ES") then "EC" else "RSA").generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder.decode(s)))

  /** SAML のメタデータに載せる自己署名証明書（10年）. */
  def selfSignedCert(kp: KeyPair, cn: String): X509Certificate =
    val now   = Instant.now()
    val name  = new X500Name(s"CN=$cn")
    val alg   = if kp.getPrivate.getAlgorithm == "EC" then "SHA256withECDSA" else "SHA256withRSA"
    val b     = new JcaX509v3CertificateBuilder(name, new BigInteger(64, new SecureRandom()), Date.from(now.minusSeconds(3600)),
      Date.from(now.plusSeconds(3650L * 86400)), name, kp.getPublic)
    new JcaX509CertificateConverter().getCertificate(b.build(new JcaContentSignerBuilder(alg).build(kp.getPrivate)))

  def certPem(c: X509Certificate): String =
    "-----BEGIN CERTIFICATE-----\n" + Base64.getMimeEncoder(64, "\n".getBytes).encodeToString(c.getEncoded) + "\n-----END CERTIFICATE-----\n"

  /** PEM（複数可）の証明書. */
  def parseCerts(pem: String): Either[String, List[X509Certificate]] =
    Either.catchNonFatal {
      val cf = CertificateFactory.getInstance("X.509")
      import scala.jdk.CollectionConverters.*
      cf.generateCertificates(new java.io.ByteArrayInputStream(pem.trim.getBytes(StandardCharsets.US_ASCII))).asScala.toList
        .collect { case c: X509Certificate => c }
    }.leftMap(e => s"証明書を読めません: ${e.getMessage}").flatMap(l => if l.isEmpty then Left("証明書がありません") else Right(l))

  /** 証明書の本体（BEGIN/END を除いた base64。SAML のメタデータ用）. */
  def certBase64(c: X509Certificate): String = Base64.getEncoder.encodeToString(c.getEncoded)

  // ------------------------------------------------------------------ JWS

  def javaAlg(alg: String): Option[String] = alg match
    case "RS256" => Some("SHA256withRSA")
    case "RS384" => Some("SHA384withRSA")
    case "RS512" => Some("SHA512withRSA")
    // JWS の ECDSA の署名は r||s をそのまま並べた形（P1363）
    case "ES256" => Some("SHA256withECDSAinP1363Format")
    case "ES384" => Some("SHA384withECDSAinP1363Format")
    case "ES512" => Some("SHA512withECDSAinP1363Format")
    case _       => None

  /** JWT に署名する（typ は既定で JWT. アクセストークンは at+jwt）. */
  def sign(key: SigningKey, claims: Json, typ: String = "JWT"): String =
    val header = Json.obj("alg" -> key.alg.asJson, "kid" -> key.kid.asJson, "typ" -> typ.asJson)
    val input  = enc.encodeToString(header.noSpaces.getBytes(StandardCharsets.UTF_8)) + "." +
      enc.encodeToString(claims.dropNullValues.noSpaces.getBytes(StandardCharsets.UTF_8))
    val s = Signature.getInstance(javaAlg(key.alg).get)
    s.initSign(key.privateKey)
    s.update(input.getBytes(StandardCharsets.US_ASCII))
    input + "." + enc.encodeToString(s.sign())

  private def part(jwt: String, i: Int): Either[String, Json] =
    jwt.split('.').lift(i).toRight("malformed jwt").flatMap { p =>
      Either.catchNonFatal(new String(dec.decode(p), StandardCharsets.UTF_8)).leftMap(_ => "invalid base64 in jwt")
        .flatMap(parse(_).leftMap(e => s"invalid json in jwt: ${e.getMessage}"))
    }

  def header(jwt: String): Either[String, Json] = part(jwt, 0)
  def claims(jwt: String): Either[String, Json] = part(jwt, 1)

  /** 署名を検証して中身を返す（none・HS* は受け付けない）. */
  def verify(jwt: String, keys: List[Json]): Either[String, Json] =
    jwt.split('.') match
      case Array(h, p, s) =>
        val input = s"$h.$p".getBytes(StandardCharsets.US_ASCII)
        for
          hd  <- header(jwt)
          alg <- hd.hcursor.get[String]("alg").leftMap(_ => "jwt without alg")
          ja  <- javaAlg(alg).toRight(s"unsupported alg: $alg")
          sig <- Either.catchNonFatal(dec.decode(s)).leftMap(_ => "invalid signature encoding")
          kid = hd.hcursor.get[String]("kid").toOption
          kty = if alg.startsWith("RS") then "RSA" else "EC"
          candidates = keys.filter { k =>
            val kc = k.hcursor
            kc.get[String]("kty").toOption.contains(kty) && kc.get[String]("use").toOption.forall(_ == "sig") &&
            kid.forall(id => kc.get[String]("kid").toOption.forall(_ == id))
          }
          _ <- Either.cond(candidates.nonEmpty, (), s"no matching key (kid=${kid.getOrElse("-")})")
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
          _ <- Either.cond(ok, (), "invalid signature")
          c <- claims(jwt)
        yield c
      case _ => Left("malformed jwt")

  /** 公開鍵で検証する（SAML の SP の証明書・外部の鍵）. */
  def verifyWith(jwt: String, pk: PublicKey): Either[String, Json] =
    val alg = if pk.getAlgorithm == "EC" then "ES256" else "RS256"
    verify(jwt, List(publicJwk("x", alg, pk).mapObject(_.remove("kid"))))
