package sruru.security

import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters

import java.nio.charset.StandardCharsets
import java.util.Base64

/** パスワードのハッシュ（Argon2id。PHC 形式の文字列で保存する）. */
object Passwords {
  private val enc = Base64.getEncoder.withoutPadding()
  private val dec = Base64.getDecoder
  private val D = "$"

  // OWASP の推奨（m=19MiB, t=2, p=1）
  val Memory = 19456
  val Iterations = 2
  val Parallelism = 1

  private def derive(
    pw: String,
    salt: Array[Byte],
    m: Int,
    t: Int,
    p: Int,
    len: Int
  ): Array[Byte] = {
    val params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
      .withVersion(
        Argon2Parameters.ARGON2_VERSION_13
      ).withMemoryAsKB(m).withIterations(t).withParallelism(p).withSalt(salt).build()
    val gen = new Argon2BytesGenerator()
    gen.init(params)
    val out = new Array[Byte](len)
    gen.generateBytes(pw.getBytes(StandardCharsets.UTF_8), out)
    out
  }

  def hash(
    pw: String
  ): String = {
    val salt = Crypto.randomBytes(16)
    val h = derive(pw, salt, Memory, Iterations, Parallelism, 32)
    List(
      "",
      "argon2id",
      "v=19",
      s"m=$Memory,t=$Iterations,p=$Parallelism",
      enc.encodeToString(salt),
      enc.encodeToString(h)
    ).mkString(D)
  }

  def verify(
    pw: String,
    stored: String
  ): Boolean =
    stored.split('$').toList match {
      case "" :: "argon2id" :: "v=19" :: params :: salt :: h :: Nil =>
        val kv = params.split(',').flatMap(_.split('=') match {
          case Array(k, v) => v.toIntOption.map(k -> _); case _ => None
        }).toMap
        (kv.get("m"), kv.get("t"), kv.get("p")) match {
          case (Some(m), Some(t), Some(p)) =>
            scala.util.Try {
              val expected = dec.decode(h)
              Crypto.constantTimeEquals(derive(pw, dec.decode(salt), m, t, p, expected.length), expected)
            }.getOrElse(false)
          case _ => false
        }
      case _ => false
    }

  /** 存在しないユーザーでも同じくらい時間をかける（ユーザーの有無を応答時間で知られないため）. */
  lazy val dummy: String = hash(Crypto.randomToken())
}
