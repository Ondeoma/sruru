package sruru.security

import java.net.URLEncoder
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** TOTP（RFC 6238。SHA-1・6桁・30秒. 一般的な認証アプリと互換）. */
object Totp {
  val Digits = 6
  val Period = 30L

  private val Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

  def base32(b: Array[Byte]): String = {
    val sb = new StringBuilder
    var buffer = 0
    var bits = 0
    b.foreach { x =>
      buffer = (buffer << 8) | (x & 0xff)
      bits += 8
      while bits >= 5 do {
        sb += Alphabet((buffer >> (bits - 5)) & 31)
        bits -= 5
      }
    }
    if bits > 0 then sb += Alphabet((buffer << (5 - bits)) & 31)
    sb.toString
  }

  def base32Decode(s: String): Array[Byte] = {
    val clean = s.toUpperCase.filter(Alphabet.contains(_))
    val out = new java.io.ByteArrayOutputStream()
    var buffer = 0
    var bits = 0
    clean.foreach { c =>
      buffer = (buffer << 5) | Alphabet.indexOf(c)
      bits += 5
      if bits >= 8 then {
        out.write((buffer >> (bits - 8)) & 0xff)
        bits -= 8
      }
    }
    out.toByteArray
  }

  def newSecret(): String = base32(Crypto.randomBytes(20))

  def code(secret: String, step: Long): String = {
    val mac = Mac.getInstance("HmacSHA1")
    mac.init(new SecretKeySpec(base32Decode(secret), "HmacSHA1"))
    val h = mac.doFinal(ByteBuffer.allocate(8).putLong(step).array())
    val o = h(h.length - 1) & 0xf
    val bin = ((h(o) & 0x7f) << 24) | ((h(o + 1) & 0xff) << 16) | ((h(o + 2) & 0xff) << 8) | (h(o + 3) & 0xff)
    val n = bin % 1000000
    f"$n%06d"
  }

  def step(epochSeconds: Long): Long = epochSeconds / Period

  /**
   * コードを確かめる（前後1ステップのずれを許す）. 合っていればそのステップ.
   * lastUsed 以下のステップは受け付けない（同じコードの使い回しを防ぐ）.
   */
  def verify(secret: String, input: String, epochSeconds: Long, lastUsed: Long): Option[Long] = {
    val c = input.filter(_.isDigit)
    if c.length != Digits then None
    else {
      val now = step(epochSeconds)
      List(now, now - 1, now + 1).find(s => s > lastUsed && Crypto.constantTimeEquals(code(secret, s), c))
    }
  }

  def uri(issuer: String, account: String, secret: String): String = {
    def e(s: String) = URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20")
    s"otpauth://totp/${e(issuer)}:${e(account)}?secret=$secret&issuer=${e(issuer)}&algorithm=SHA1&digits=$Digits&period=$Period"
  }
}
