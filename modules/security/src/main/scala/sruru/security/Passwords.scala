package sruru.security

import org.bouncycastle.crypto.generators.{Argon2BytesGenerator, OpenBSDBCrypt}
import org.bouncycastle.crypto.params.Argon2Parameters

import java.nio.charset.StandardCharsets
import java.util.Base64

/**
 * パスワードのハッシュ（Argon2id。PHC 形式の文字列で保存する）.
 * ほかのシステムから移したユーザーの bcrypt（jBCrypt の `$2a$` など）も照合できる. 新しく保存するのは常に Argon2id.
 */
object Passwords {
  private val enc = Base64.getEncoder.withoutPadding()
  private val dec = Base64.getDecoder
  private val D = "$"

  // OWASP の推奨（m=19MiB, t=2, p=1）
  val Memory = 19456
  val Iterations = 2
  val Parallelism = 1

  private def derive(pw: String, salt: Array[Byte], m: Int, t: Int, p: Int, len: Int): Array[Byte] = {
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

  def hash(pw: String): String = {
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

  /** bcrypt のハッシュ（`$2a$`・`$2b$`・`$2y$`、コスト 2 桁、塩と値で 53 文字）. */
  private val BcryptForm = """^\$2[aby]\$(\d\d)\$[./A-Za-z0-9]{53}$""".r

  /** bcrypt のハッシュとして正しい形か（コストは 4〜31）. */
  def isBcrypt(stored: String): Boolean = stored match {
    case BcryptForm(cost) => cost.toInt >= 4 && cost.toInt <= 31
    case _ => false
  }

  /** Argon2id の PHC 形式として読めるか. */
  def isArgon2id(stored: String): Boolean = argon2Params(stored).isDefined

  /** 取り込みで受け付けるハッシュの形（bcrypt か Argon2id）. */
  def acceptable(stored: String): Boolean = isBcrypt(stored) || isArgon2id(stored)

  /** Argon2id の今の既定で作り直すべきか（bcrypt・パラメータの違う Argon2id）. */
  def needsRehash(stored: String): Boolean =
    !argon2Params(stored).exists((m, t, p, _, _) => m == Memory && t == Iterations && p == Parallelism)

  private def argon2Params(stored: String): Option[(Int, Int, Int, String, String)] =
    stored.split('$').toList match {
      case "" :: "argon2id" :: "v=19" :: params :: salt :: h :: Nil =>
        val kv = params.split(',').flatMap(_.split('=') match {
          case Array(k, v) => v.toIntOption.map(k -> _); case _ => None
        }).toMap
        (kv.get("m"), kv.get("t"), kv.get("p")) match {
          case (Some(m), Some(t), Some(p)) if salt.nonEmpty && h.nonEmpty => Some((m, t, p, salt, h))
          case _ => None
        }
      case _ => None
    }

  /** bcrypt の照合. jBCrypt と同じく、UTF-8 で 72 バイトを超える部分は使わない. */
  private def verifyBcrypt(pw: String, stored: String): Boolean =
    scala.util.Try(OpenBSDBCrypt.checkPassword(stored, pw.getBytes(StandardCharsets.UTF_8).take(72))).getOrElse(false)

  def verify(pw: String, stored: String): Boolean =
    if isBcrypt(stored) then verifyBcrypt(pw, stored)
    else verifyArgon2(pw, stored)

  private def verifyArgon2(pw: String, stored: String): Boolean =
    argon2Params(stored).exists { (m, t, p, salt, h) =>
      scala.util.Try {
        val expected = dec.decode(h)
        Crypto.constantTimeEquals(derive(pw, dec.decode(salt), m, t, p, expected.length), expected)
      }.getOrElse(false)
    }

  /** 存在しないユーザーでも同じくらい時間をかける（ユーザーの有無を応答時間で知られないため）. */
  lazy val dummy: String = hash(Crypto.randomToken())
}
