package sruru.shared

import io.circe.*
import io.circe.derivation.{Configuration, ConfiguredCodec}

// グループごとのポリシーの上書き。None の項目は全体のポリシーのまま。
// セキュリティの項目は、全体と所属するすべてのグループのうち「より厳しい方」にまとめる（優先度は関係しない）。
// 表示の項目（サービス名・ロゴ）は、上書きしているグループのうち優先度の最も高いものを使う。

/** パスワードの条件の上書き. 真偽値は「必須にする」ときだけ Some(true). */
final case class PasswordOverride(
  minLength: Option[Int] = None,
  requireUpper: Option[Boolean] = None,
  requireLower: Option[Boolean] = None,
  requireDigit: Option[Boolean] = None,
  requireSymbol: Option[Boolean] = None,
  minClasses: Option[Int] = None,
  historyCount: Option[Int] = None,
  /** 有効期限（日。0 は無期限なので、上書きでは1以上） */
  maxAgeDays: Option[Int] = None,
  disallowUserInfo: Option[Boolean] = None,
  disallowCommon: Option[Boolean] = None) derives ConfiguredCodec

/** アカウントのロックの上書き（IP ごとの制限はユーザーに依らないので全体のまま）. */
final case class LockoutOverride(
  enabled: Option[Boolean] = None,
  maxFailures: Option[Int] = None,
  /** ロックする時間（分。0 は管理者が解除するまで = 最も厳しい） */
  lockMinutes: Option[Int] = None) derives ConfiguredCodec

/** 多要素認証の上書き. */
final case class MfaOverride(
  /** off | optional | required（required が最も厳しい） */
  mode: Option[String] = None,
  /** false で、その方法を使わせない */
  allowTotp: Option[Boolean] = None,
  allowEmail: Option[Boolean] = None,
  emailCodeMinutes: Option[Int] = None) derives ConfiguredCodec

/** セッションの上書き. */
final case class SessionOverride(
  lifetimeHours: Option[Int] = None,
  /** 操作がなければ切れるまでの時間（分。上書きでは1以上） */
  idleMinutes: Option[Int] = None,
  maxAccounts: Option[Int] = None) derives ConfiguredCodec

/** IP アドレスの制限の上書き. allow はこれにも含まれること（全体の allow と両方）、deny は全体に加える. */
final case class IpOverride(allow: List[String] = Nil, deny: List[String] = Nil) derives ConfiguredCodec

/** 表示の上書き（優先度の最も高いグループのものを使う）. */
final case class BrandingOverride(
  title: Option[String] = None,
  /** ロゴの ID（/brand-logos/{id}） */
  logo: Option[String] = None) derives ConfiguredCodec

/** グループのポリシーの上書き一式. */
final case class GroupPolicy(password: PasswordOverride = PasswordOverride(),
                             lockout: LockoutOverride = LockoutOverride(),
                             mfa: MfaOverride = MfaOverride(),
                             session: SessionOverride = SessionOverride(),
                             ip: IpOverride = IpOverride(),
                             branding: BrandingOverride = BrandingOverride()) derives ConfiguredCodec {
  def isEmpty: Boolean = this == GroupPolicy()
}

object GroupPolicy {

  private val MfaRank = Map("off" -> 0, "optional" -> 1, "required" -> 2)

  // 「より厳しい方」
  private def larger(a: Int, b: Option[Int]): Int = b.fold(a)(math.max(a, _))
  private def smaller(a: Int, b: Option[Int]): Int = b.fold(a)(math.min(a, _))
  private def or(a: Boolean, b: Option[Boolean]): Boolean = a || b.contains(true)
  private def and(a: Boolean, b: Option[Boolean]): Boolean = a && !b.contains(false)

  /** 0 を「制限なし」とする値（有効期限・無操作の時間）: 0 でない小さい方. */
  private def limit(a: Int, b: Option[Int]): Int = b.filter(_ > 0).fold(a)(x => if a <= 0 then x else math.min(a, x))

  /** ロックの時間: 0（管理者が解除するまで）が最も厳しく、ほかは長い方. */
  private def lockTime(a: Int, b: Option[Int]): Int = b.fold(a)(x => if a == 0 || x == 0 then 0 else math.max(a, x))

  /** 1つのグループの上書きを重ねる（厳しい方へ. 表示の項目はここでは扱わない）. */
  private def stricter(p: PoliciesDto, g: GroupPolicy): PoliciesDto = {
    val pw = g.password
    val lo = g.lockout
    val mf = g.mfa
    val se = g.session
    p.copy(
      password = p.password.copy(
        minLength = larger(p.password.minLength, pw.minLength),
        requireUpper = or(p.password.requireUpper, pw.requireUpper),
        requireLower = or(p.password.requireLower, pw.requireLower),
        requireDigit = or(p.password.requireDigit, pw.requireDigit),
        requireSymbol = or(p.password.requireSymbol, pw.requireSymbol),
        minClasses = larger(p.password.minClasses, pw.minClasses),
        historyCount = larger(p.password.historyCount, pw.historyCount),
        maxAgeDays = limit(p.password.maxAgeDays, pw.maxAgeDays),
        disallowUserInfo = or(p.password.disallowUserInfo, pw.disallowUserInfo),
        disallowCommon = or(p.password.disallowCommon, pw.disallowCommon)
      ),
      lockout = p.lockout.copy(
        enabled = or(p.lockout.enabled, lo.enabled),
        maxFailures = smaller(p.lockout.maxFailures, lo.maxFailures),
        lockMinutes = lockTime(p.lockout.lockMinutes, lo.lockMinutes)
      ),
      mfa = p.mfa.copy(
        mode = mf.mode.filter(m => MfaRank.getOrElse(m, -1) > MfaRank.getOrElse(p.mfa.mode, 0)).getOrElse(p.mfa.mode),
        allowTotp = and(p.mfa.allowTotp, mf.allowTotp),
        allowEmail = and(p.mfa.allowEmail, mf.allowEmail),
        emailCodeMinutes = smaller(p.mfa.emailCodeMinutes, mf.emailCodeMinutes)
      ),
      session = p.session.copy(
        lifetimeHours = smaller(p.session.lifetimeHours, se.lifetimeHours),
        idleMinutes = limit(p.session.idleMinutes, se.idleMinutes),
        maxAccounts = smaller(p.session.maxAccounts, se.maxAccounts)
      ),
      ip = p.ip.copy(
        allowAlso = p.ip.allowAlso ++ Option(g.ip.allow).filter(_.nonEmpty).toList,
        deny = (p.ip.deny ++ g.ip.deny).distinct
      )
    )
  }

  /**
   * ユーザーに効くポリシー. groups は所属するグループの (優先度, 名前, 上書き)（親グループを含む）.
   * セキュリティの項目は全体とすべてのグループの厳しい方. 表示の項目は、優先度の高い（同じなら名前の順で先の）グループのもの.
   */
  def effective(global: PoliciesDto, groups: List[(Int, String, GroupPolicy)]): PoliciesDto = {
    val merged = groups.foldLeft(global)((p, g) => stricter(p, g._3))
    // どちらの方法も使えなくなったら、認証アプリは残す（2つ目の要素を求めるのに登録できる方法がなくならないように）
    val mfa = if !merged.mfa.allowTotp && !merged.mfa.allowEmail then merged.mfa.copy(allowTotp = true) else merged.mfa
    val ordered = groups.sortBy(g => (-g._1, g._2)).map(_._3.branding)
    def pick[A](f: BrandingOverride => Option[A]): Option[A] = ordered.flatMap(f).headOption
    merged.copy(
      mfa = mfa,
      branding = merged.branding.copy(
        title = pick(_.title).getOrElse(merged.branding.title),
        logo = pick(_.logo).orElse(merged.branding.logo)
      )
    )
  }

  /** 上書きの値を確かめる. */
  def validate(g: GroupPolicy): Either[String, GroupPolicy] =
    check(g.password, g.lockout, g.mfa, g.session, g.branding.title, zeroMeansNoLimit = false)
      .toLeft(g.copy(branding = g.branding.copy(title = g.branding.title.map(_.trim))))

  /**
   * 上書きの値の確認（グループとドメインで共通）. 最初の誤りを返す.
   * zeroMeansNoLimit: 有効期限・無操作の時間に 0（無期限・切れない）を許すか（置き換えるドメインの上書きでは許す）.
   */
  def check(pw: PasswordOverride,
            lo: LockoutOverride,
            mf: MfaOverride,
            se: SessionOverride,
            title: Option[String],
            zeroMeansNoLimit: Boolean): Option[String] = {
    val min = if zeroMeansNoLimit then 0 else 1
    List(
      pw.minLength.filter(_ < 4).map(_ => "パスワードの最小の長さは4以上にしてください"),
      pw.minClasses.filter(x => x < 1 || x > 4).map(_ => "文字の種類の数は1〜4にしてください"),
      pw.historyCount.filter(_ < 0).map(_ => "再利用を禁じる回数は0以上にしてください"),
      pw.maxAgeDays.filter(_ < min).map(_ => s"パスワードの有効期限は${min}日以上にしてください"),
      lo.maxFailures.filter(_ < 1).map(_ => "ロックするまでの回数は1以上にしてください"),
      lo.lockMinutes.filter(_ < 0).map(_ => "ロックする時間は0以上にしてください"),
      mf.mode.filterNot(MfaRank.contains).map(_ => "多要素認証のモードは off・optional・required です"),
      mf.emailCodeMinutes.filter(_ < 1).map(_ => "メールのコードの有効期間は1分以上にしてください"),
      se.lifetimeHours.filter(_ < 1).map(_ => "ログインの有効期間は1時間以上にしてください"),
      se.idleMinutes.filter(_ < min).map(_ => s"無操作で切れるまでの時間は${min}分以上にしてください"),
      se.maxAccounts.filter(_ < 1).map(_ => "同時にログインできるアカウントの数は1以上にしてください"),
      title.filter(_.trim.isEmpty).map(_ => "サービス名を入力してください")
    ).flatten.headOption
  }
}
