package sruru.security

import java.nio.charset.StandardCharsets
import java.security.{MessageDigest, SecureRandom}
import java.util.Base64

/** 乱数のトークン・ハッシュ・比較. */
object Crypto {
  private val rnd = new SecureRandom()
  val b64url = Base64.getUrlEncoder.withoutPadding()
  val b64urlDec = Base64.getUrlDecoder

  def randomBytes(n: Int): Array[Byte] = {
    val a = new Array[Byte](n)
    rnd.nextBytes(a)
    a
  }

  def randomToken(bytes: Int = 32): String = b64url.encodeToString(randomBytes(bytes))

  /** 数字だけのコード（メールのワンタイムコード）. */
  def randomDigits(n: Int): String = (1 to n).map(_ => ('0' + rnd.nextInt(10)).toChar).mkString

  /** 紛らわしい文字を除いた英数字（回復コード）. */
  def randomCode(n: Int): String = {
    val alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
    (1 to n).map(_ => alphabet(rnd.nextInt(alphabet.length))).mkString
  }

  def sha256(s: String): Array[Byte] = sha256(s.getBytes(StandardCharsets.UTF_8))
  def sha256(b: Array[Byte]): Array[Byte] = MessageDigest.getInstance("SHA-256").digest(b)

  def hex(b: Array[Byte]): String = b.map(x => f"${x & 0xff}%02x").mkString

  def pkceS256(verifier: String): String = b64url.encodeToString(sha256(verifier))

  def constantTimeEquals(a: String, b: String): Boolean =
    MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8))

  def constantTimeEquals(a: Array[Byte], b: Array[Byte]): Boolean = MessageDigest.isEqual(a, b)
}

/** API トークン: sruru_ で始まるランダム値. DB にはハッシュだけを保存し、画面には先頭だけ出す. */
object ApiTokens {
  val Prefix = "sruru_"
  def generate(): (String, String) = {
    val t = Prefix + Crypto.randomToken(30)
    (t, t.take(Prefix.length + 6))
  }
  def looksLike(s: String): Boolean = s.startsWith(Prefix)
}
