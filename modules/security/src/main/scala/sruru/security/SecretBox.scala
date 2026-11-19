package sruru.security

import java.nio.charset.StandardCharsets
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.{GCMParameterSpec, SecretKeySpec}

/** 秘密の値（署名鍵・外部 IdP のシークレット・TOTP の鍵）の暗号化. APP_SECRET から鍵を作る（AES-256-GCM）. */
final class SecretBox(
  secret: String) {
  private val key = new SecretKeySpec(Crypto.sha256("sruru-secret-box:" + secret), "AES")

  /** "v1:" + base64(iv + 暗号文) */
  def encrypt(
    plain: String
  ): String = {
    val iv = Crypto.randomBytes(12)
    val c = Cipher.getInstance("AES/GCM/NoPadding")
    c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv))
    "v1:" + Base64.getEncoder.encodeToString(iv ++ c.doFinal(plain.getBytes(StandardCharsets.UTF_8)))
  }

  def decrypt(
    enc: String
  ): Option[String] =
    scala.util.Try {
      val raw = Base64.getDecoder.decode(enc.stripPrefix("v1:"))
      val c = Cipher.getInstance("AES/GCM/NoPadding")
      c.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, raw.take(12)))
      new String(c.doFinal(raw.drop(12)), StandardCharsets.UTF_8)
    }.toOption
}
