package sruru.shared

import io.circe.*
import io.circe.derivation.{Configuration, ConfiguredCodec}

// 管理画面で変えるポリシー（settings の表に JSON で保存する）。足りないキーは既定値になる。

given Configuration = Configuration.default.withDefaults

/** パスワードの条件. */
final case class PasswordPolicy(
  minLength: Int = 10,
  maxLength: Int = 256,
  requireUpper: Boolean = false,
  requireLower: Boolean = false,
  requireDigit: Boolean = false,
  requireSymbol: Boolean = false,
  /** 文字の種類（大文字・小文字・数字・記号）のうち最低いくつを使うか */
  minClasses: Int = 2,
  /** 直近いくつのパスワードの再利用を禁じるか（0 なら制限なし） */
  historyCount: Int = 5,
  /** 有効期限（日。0 なら無期限） */
  maxAgeDays: Int = 0,
  /** ユーザー名・メールアドレス・名前を含むパスワードを禁じる */
  disallowUserInfo: Boolean = true,
  /** よく使われるパスワードを禁じる */
  disallowCommon: Boolean = true) derives ConfiguredCodec

/** アカウントのロック. */
final case class LockoutPolicy(
  enabled: Boolean = true,
  /** 連続で失敗したらロックする回数 */
  maxFailures: Int = 5,
  /** ロックする時間（分。0 なら管理者が解除するまで） */
  lockMinutes: Int = 15,
  /** 同じ IP アドレスからの失敗の上限（窓の中で）。超えたら一時的にログインを受け付けない */
  ipMaxFailures: Int = 30,
  ipWindowMinutes: Int = 15) derives ConfiguredCodec

/** 多要素認証. */
final case class MfaPolicy(
  /** off | optional | required */
  mode: String = "optional",
  /** このグループのメンバーには必須にする（mode が optional のとき） */
  requiredGroups: List[String] = Nil,
  /** 管理者には必須にする */
  requiredForAdmins: Boolean = false,
  allowTotp: Boolean = true,
  allowEmail: Boolean = true,
  /** メールのコードの有効期間（分） */
  emailCodeMinutes: Int = 10) derives ConfiguredCodec

/** セッション. */
final case class SessionPolicy(
  /** ログインの有効期間（時間） */
  lifetimeHours: Int = 24 * 14,
  /** 操作がなければ切れるまでの時間（分。0 なら切れない） */
  idleMinutes: Int = 0,
  /** 1つのブラウザで同時にログインできるアカウントの数 */
  maxAccounts: Int = 5) derives ConfiguredCodec

/** IP アドレスの制限. CIDR（192.168.0.0/16・2001:db8::/32）か単独のアドレス. */
final case class IpPolicy(
  /** 空でなければ、ここに含まれるアドレスからだけログインできる */
  allow: List[String] = Nil,
  /** ここに含まれるアドレスからはログインできない */
  deny: List[String] = Nil,
  /** 空でなければ、管理画面・管理 API はここからだけ使える */
  adminAllow: List[String] = Nil,
  /** X-Forwarded-For を信頼するプロキシ（ロードバランサー）のアドレス */
  trustedProxies: List[String] = List("127.0.0.1/32", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"),
  /** グループの上書きの allow（それぞれにも含まれること）. ユーザーに効くポリシーを計算したときだけ入る（全体の設定には保存しない） */
  allowAlso: List[List[String]] = Nil) derives ConfiguredCodec

/** クライアント証明書によるログイン. */
final case class CertAuthPolicy(
  enabled: Boolean = false,
  /** 証明書を渡すリバースプロキシのヘッダー（PEM。URL エンコードされていてもよい） */
  header: String = "X-SSL-Client-Cert",
  /** registered（登録済みの証明書）| email（SAN のメールアドレス）| upn（SAN の UPN）| cn（サブジェクトの CN = ユーザー名） */
  mapping: String = "registered",
  /** 証明書でのログインを多要素とみなす（パスワードと組み合わせない場合も） */
  countsAsMfa: Boolean = true) derives ConfiguredCodec

/** 画面の表示. */
final case class Branding(
  title: String = "sruru",
  loginMessage: String = "",
  /** 利用者が自分でアカウントを作れる */
  selfRegistration: Boolean = false,
  /** 自分のアイコンがないとき Gravatar の画像を使う */
  gravatar: Boolean = false,
  /** ロゴの ID（/brand-logos/{id}）. なければ既定のロゴ */
  logo: Option[String] = None) derives ConfiguredCodec

object Branding {

  /** ロゴの URL（なければ既定のロゴ）. */
  def logoUrl(
    logo: Option[String]
  ): String = logo.fold("/logo.svg")(id => s"/brand-logos/$id")
}

/** 監査ログ. */
final case class AuditPolicy(
  /** 保存期間（日。0 なら消さない） */
  retentionDays: Int = 365) derives ConfiguredCodec

/** ポリシー一式（管理画面の「ポリシー」）. */
final case class PoliciesDto(
  password: PasswordPolicy = PasswordPolicy(),
  lockout: LockoutPolicy = LockoutPolicy(),
  mfa: MfaPolicy = MfaPolicy(),
  session: SessionPolicy = SessionPolicy(),
  ip: IpPolicy = IpPolicy(),
  cert: CertAuthPolicy = CertAuthPolicy(),
  branding: Branding = Branding(),
  audit: AuditPolicy = AuditPolicy()) derives ConfiguredCodec
