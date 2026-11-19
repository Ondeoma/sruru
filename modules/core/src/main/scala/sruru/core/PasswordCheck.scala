package sruru.core

import sruru.shared.PasswordPolicy

/** パスワードがポリシーを満たすかの確認（履歴の確認はハッシュが要るので呼び出し側で行う）. */
object PasswordCheck {

  /** よく使われるパスワード（resources/common-passwords.txt。小文字で比べる）. */
  lazy val common: Set[String] =
    Option(getClass.getResourceAsStream("/common-passwords.txt")).fold(Set.empty[String]) { in =>
      try scala.io.Source.fromInputStream(in, "UTF-8").getLines().map(_.trim.toLowerCase).filter(_.nonEmpty).toSet
      finally in.close()
    }

  private def classes(
    pw: String
  ): Int =
    List(
      pw.exists(_.isUpper),
      pw.exists(_.isLower),
      pw.exists(_.isDigit),
      pw.exists(c => !c.isLetterOrDigit)
    ).count(identity)

  /** 満たしていない条件の説明（空なら OK）. userInfo はユーザー名・メールの @ の前・名前. */
  def violations(
    pw: String,
    p: PasswordPolicy,
    userInfo: List[String] = Nil
  ): List[String] = {
    val cps = pw.codePointCount(0, pw.length)
    List(
      Option.when(cps < p.minLength)(s"${p.minLength}文字以上にしてください"),
      Option.when(cps > p.maxLength)(s"${p.maxLength}文字以下にしてください"),
      Option.when(p.requireUpper && !pw.exists(_.isUpper))("英大文字を含めてください"),
      Option.when(p.requireLower && !pw.exists(_.isLower))("英小文字を含めてください"),
      Option.when(p.requireDigit && !pw.exists(_.isDigit))("数字を含めてください"),
      Option.when(p.requireSymbol && !pw.exists(c => !c.isLetterOrDigit))("記号を含めてください"),
      Option.when(classes(pw) < p.minClasses)(s"英大文字・英小文字・数字・記号のうち${p.minClasses}種類以上を使ってください"),
      Option.when(p.disallowUserInfo &&
        userInfo.map(_.trim.toLowerCase).filter(_.length >= 3).exists(pw.toLowerCase.contains))(
        "ユーザー名・メールアドレス・名前を含めないでください"
      ),
      Option.when(p.disallowCommon && common.contains(pw.toLowerCase))("よく使われるパスワードは使えません")
    ).flatten
  }

  /** ポリシーの説明（画面に出す）. */
  def describe(
    p: PasswordPolicy
  ): List[String] =
    List(
      Some(s"${p.minLength}文字以上"),
      Option.when(p.minClasses > 1)(s"英大文字・英小文字・数字・記号のうち${p.minClasses}種類以上"),
      Option.when(p.requireUpper)("英大文字を含む"),
      Option.when(p.requireLower)("英小文字を含む"),
      Option.when(p.requireDigit)("数字を含む"),
      Option.when(p.requireSymbol)("記号を含む"),
      Option.when(p.disallowUserInfo)("ユーザー名・メールアドレスを含まない"),
      Option.when(p.historyCount > 0)(s"直近${p.historyCount}回のパスワードと違う")
    ).flatten
}
