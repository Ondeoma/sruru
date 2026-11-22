package sruru.shared

import io.circe.*
import io.circe.derivation.ConfiguredCodec

// ドメイン（sruru にアクセスするホスト名）ごとのポリシーの上書き。None の項目は全体のポリシーのまま。
// グループの上書き（より厳しい方）と違い、指定した項目は全体の値を「置き換える」（緩めることもできる）。
// 重ねる順は 全体 → ドメイン（置き換え）→ グループ（厳しい方）。

/** 表示と自己登録の上書き. */
final case class DomainBranding(
  title: Option[String] = None,
  /** ロゴの ID（/brand-logos/{id}） */
  logo: Option[String] = None,
  /** ログインの画面の案内（Some("") で案内を出さない） */
  loginMessage: Option[String] = None,
  selfRegistration: Option[Boolean] = None) derives ConfiguredCodec

/** ログインの方法の上書き. */
final case class DomainLogin(
  /** クライアント証明書でのログイン */
  cert: Option[Boolean] = None,
  /** 使える外部の IdP（slug）. None なら有効なものすべて、Some(Nil) なら使わせない */
  providers: Option[List[String]] = None) derives ConfiguredCodec

/** ドメインのポリシーの上書き一式. */
final case class DomainPolicy(
  password: PasswordOverride = PasswordOverride(),
  lockout: LockoutOverride = LockoutOverride(),
  mfa: MfaOverride = MfaOverride(),
  session: SessionOverride = SessionOverride(),
  /** IP アドレスの許可・拒否. Some なら全体の allow・deny を置き換える（空のリストで「制限なし」にもできる） */
  ip: Option[IpOverride] = None,
  branding: DomainBranding = DomainBranding(),
  login: DomainLogin = DomainLogin(),
  /** このホスト名で管理画面・管理 API を使えるか */
  admin: Boolean = true) derives ConfiguredCodec

object DomainPolicy {

  /** 全体のポリシーに、ドメインの上書きを重ねる（指定した項目を置き換える）. */
  def applied(p: PoliciesDto, d: DomainPolicy): PoliciesDto = {
    val pw = d.password
    val lo = d.lockout
    val mf = d.mfa
    val se = d.session
    val mfa = p.mfa.copy(
      mode = mf.mode.getOrElse(p.mfa.mode),
      allowTotp = mf.allowTotp.getOrElse(p.mfa.allowTotp),
      allowEmail = mf.allowEmail.getOrElse(p.mfa.allowEmail),
      emailCodeMinutes = mf.emailCodeMinutes.getOrElse(p.mfa.emailCodeMinutes)
    )
    p.copy(
      password = p.password.copy(
        minLength = pw.minLength.getOrElse(p.password.minLength),
        requireUpper = pw.requireUpper.getOrElse(p.password.requireUpper),
        requireLower = pw.requireLower.getOrElse(p.password.requireLower),
        requireDigit = pw.requireDigit.getOrElse(p.password.requireDigit),
        requireSymbol = pw.requireSymbol.getOrElse(p.password.requireSymbol),
        minClasses = pw.minClasses.getOrElse(p.password.minClasses),
        historyCount = pw.historyCount.getOrElse(p.password.historyCount),
        maxAgeDays = pw.maxAgeDays.getOrElse(p.password.maxAgeDays),
        disallowUserInfo = pw.disallowUserInfo.getOrElse(p.password.disallowUserInfo),
        disallowCommon = pw.disallowCommon.getOrElse(p.password.disallowCommon)
      ),
      lockout = p.lockout.copy(
        enabled = lo.enabled.getOrElse(p.lockout.enabled),
        maxFailures = lo.maxFailures.getOrElse(p.lockout.maxFailures),
        lockMinutes = lo.lockMinutes.getOrElse(p.lockout.lockMinutes)
      ),
      // どちらの方法も使えなくなったら、認証アプリは残す（グループの上書きと同じ決まり）
      mfa = if !mfa.allowTotp && !mfa.allowEmail then mfa.copy(allowTotp = true) else mfa,
      session = p.session.copy(
        lifetimeHours = se.lifetimeHours.getOrElse(p.session.lifetimeHours),
        idleMinutes = se.idleMinutes.getOrElse(p.session.idleMinutes),
        maxAccounts = se.maxAccounts.getOrElse(p.session.maxAccounts)
      ),
      ip = d.ip.fold(p.ip)(x => p.ip.copy(allow = x.allow, deny = x.deny)),
      cert = p.cert.copy(enabled = d.login.cert.getOrElse(p.cert.enabled)),
      branding = p.branding.copy(
        title = d.branding.title.getOrElse(p.branding.title),
        logo = d.branding.logo.orElse(p.branding.logo),
        loginMessage = d.branding.loginMessage.getOrElse(p.branding.loginMessage),
        selfRegistration = d.branding.selfRegistration.getOrElse(p.branding.selfRegistration)
      )
    )
  }

  /** 上書きの値を確かめる（置き換えなので、0 = 無期限・切れない も指定できる）. */
  def validate(d: DomainPolicy): Either[String, DomainPolicy] =
    GroupPolicy.check(d.password, d.lockout, d.mfa, d.session, d.branding.title, zeroMeansNoLimit = true).toLeft(
      d.copy(
        branding =
          d.branding.copy(title = d.branding.title.map(_.trim), loginMessage = d.branding.loginMessage.map(_.trim)),
        login = d.login.copy(providers = d.login.providers.map(_.map(_.trim).filter(_.nonEmpty).distinct))
      )
    )

  /** ホスト名の形（host か host:port. 小文字にそろえる）. スキーム・パスは付けない. */
  def normalizeHost(s: String): Either[String, String] = {
    val h = s.trim.toLowerCase
    val ok = h.nonEmpty && h.length <= 255 && h.matches("""[a-z0-9]([a-z0-9.\-]*[a-z0-9])?(:[0-9]{1,5})?""")
    Either.cond(ok, h, "ホスト名は auth.example.com（必要なら :ポート）の形で入力してください")
  }
}
