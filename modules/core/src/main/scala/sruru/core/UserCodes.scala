package sruru.core

import java.security.SecureRandom

/**
 * デバイスフロー（RFC 8628）で利用者が手で打ち込むコード. 母音と紛らわしい文字を除いた 20 文字から 8 文字
 * （RFC 8628 6.1 の例と同じ文字. 20^8 ≒ 2.6×10^10 通り. 母音がないので、意味のある単語にもならない）.
 */
object UserCodes {
  val Alphabet = "BCDFGHJKLMNPQRSTVWXZ"
  val Length = 8

  def generate(rnd: SecureRandom): String =
    List.fill(Length)(Alphabet.charAt(rnd.nextInt(Alphabet.length))).mkString

  /** 画面・応答に出す形（BCDF-GHJK）. */
  def format(code: String): String = code.take(Length / 2) + "-" + code.drop(Length / 2)

  /** 入力をそろえる（大文字小文字・ハイフン・空白の違いを吸収する）. コードの形でなければ None. */
  def normalize(input: String): Option[String] = {
    val s = input.filterNot(c => c.isWhitespace || "-‐‑‒–—―ー－_".contains(c)).map {
      // 全角の英字は半角にする
      case c if c >= 'Ａ' && c <= 'Ｚ' => (c - 'Ａ' + 'A').toChar
      case c if c >= 'ａ' && c <= 'ｚ' => (c - 'ａ' + 'A').toChar
      case c => c.toUpper
    }
    Option.when(s.length == Length && s.forall(Alphabet.contains(_)))(s)
  }
}
