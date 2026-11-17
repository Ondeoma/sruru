package sruru.security

import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters

import java.nio.charset.StandardCharsets
import java.security.{MessageDigest, SecureRandom}
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.{GCMParameterSpec, SecretKeySpec}

/** 乱数のトークン・ハッシュ・比較. */
object Crypto:
  private val rnd = new SecureRandom()
  val b64url    = Base64.getUrlEncoder.withoutPadding()
  val b64urlDec = Base64.getUrlDecoder

  def randomBytes(n: Int): Array[Byte] =
    val a = new Array[Byte](n)
    rnd.nextBytes(a)
    a

  def randomToken(bytes: Int = 32): String = b64url.encodeToString(randomBytes(bytes))

  /** 数字だけのコード（メールのワンタイムコード）. */
  def randomDigits(n: Int): String = (1 to n).map(_ => ('0' + rnd.nextInt(10)).toChar).mkString

  /** 紛らわしい文字を除いた英数字（回復コード）. */
  def randomCode(n: Int): String =
    val alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
    (1 to n).map(_ => alphabet(rnd.nextInt(alphabet.length))).mkString

  def sha256(s: String): Array[Byte]      = sha256(s.getBytes(StandardCharsets.UTF_8))
  def sha256(b: Array[Byte]): Array[Byte] = MessageDigest.getInstance("SHA-256").digest(b)

  def hex(b: Array[Byte]): String = b.map(x => f"${x & 0xff}%02x").mkString

  def pkceS256(verifier: String): String = b64url.encodeToString(sha256(verifier))

  def constantTimeEquals(a: String, b: String): Boolean =
    MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8))

  def constantTimeEquals(a: Array[Byte], b: Array[Byte]): Boolean = MessageDigest.isEqual(a, b)

/** パスワードのハッシュ（Argon2id。PHC 形式の文字列で保存する）. */
object Passwords:
  private val enc = Base64.getEncoder.withoutPadding()
  private val dec = Base64.getDecoder
  private val D   = "$"

  // OWASP の推奨（m=19MiB, t=2, p=1）
  val Memory      = 19456
  val Iterations  = 2
  val Parallelism = 1

  private def derive(pw: String, salt: Array[Byte], m: Int, t: Int, p: Int, len: Int): Array[Byte] =
    val params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
      .withVersion(Argon2Parameters.ARGON2_VERSION_13).withMemoryAsKB(m).withIterations(t).withParallelism(p).withSalt(salt).build()
    val gen = new Argon2BytesGenerator()
    gen.init(params)
    val out = new Array[Byte](len)
    gen.generateBytes(pw.getBytes(StandardCharsets.UTF_8), out)
    out

  def hash(pw: String): String =
    val salt = Crypto.randomBytes(16)
    val h    = derive(pw, salt, Memory, Iterations, Parallelism, 32)
    List("", "argon2id", "v=19", s"m=$Memory,t=$Iterations,p=$Parallelism", enc.encodeToString(salt), enc.encodeToString(h)).mkString(D)

  def verify(pw: String, stored: String): Boolean =
    stored.split('$').toList match
      case "" :: "argon2id" :: "v=19" :: params :: salt :: h :: Nil =>
        val kv = params.split(',').flatMap(_.split('=') match { case Array(k, v) => v.toIntOption.map(k -> _); case _ => None }).toMap
        (kv.get("m"), kv.get("t"), kv.get("p")) match
          case (Some(m), Some(t), Some(p)) =>
            scala.util.Try {
              val expected = dec.decode(h)
              Crypto.constantTimeEquals(derive(pw, dec.decode(salt), m, t, p, expected.length), expected)
            }.getOrElse(false)
          case _ => false
      case _ => false

  /** 存在しないユーザーでも同じくらい時間をかける（ユーザーの有無を応答時間で知られないため）. */
  lazy val dummy: String = hash(Crypto.randomToken())

/** API トークン: sruru_ で始まるランダム値. DB にはハッシュだけを保存し、画面には先頭だけ出す. */
object ApiTokens:
  val Prefix = "sruru_"
  def generate(): (String, String) =
    val t = Prefix + Crypto.randomToken(30)
    (t, t.take(Prefix.length + 6))
  def looksLike(s: String): Boolean = s.startsWith(Prefix)

/** 秘密の値（署名鍵・外部 IdP のシークレット・TOTP の鍵）の暗号化. APP_SECRET から鍵を作る（AES-256-GCM）. */
final class SecretBox(secret: String):
  private val key = new SecretKeySpec(Crypto.sha256("sruru-secret-box:" + secret), "AES")

  /** "v1:" + base64(iv + 暗号文) */
  def encrypt(plain: String): String =
    val iv = Crypto.randomBytes(12)
    val c  = Cipher.getInstance("AES/GCM/NoPadding")
    c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv))
    "v1:" + Base64.getEncoder.encodeToString(iv ++ c.doFinal(plain.getBytes(StandardCharsets.UTF_8)))

  def decrypt(enc: String): Option[String] =
    scala.util.Try {
      val raw = Base64.getDecoder.decode(enc.stripPrefix("v1:"))
      val c   = Cipher.getInstance("AES/GCM/NoPadding")
      c.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, raw.take(12)))
      new String(c.doFinal(raw.drop(12)), StandardCharsets.UTF_8)
    }.toOption
