package sruru.shared

import io.circe.*
import io.circe.derivation.ConfiguredCodec

import java.util.UUID

// バックエンド(JVM)と画面(Scala.js)の両方で使う API の型。日時は Timestamp（JVM では Instant）。
// 足りないキーは既定値になる（Policies.scala の given Configuration）。

final case class ErrorDto(error: String) derives ConfiguredCodec

/** API トークンのスコープ. */
object TokenScopes {
  val Read  = "read"
  val Write = "write"
  val Admin = "admin"
  val Scim  = "scim"
  val all: List[String] = List(Read, Write, Admin, Scim)
  def label(s: String): String = s match {
    case Read  => "参照（read）"
    case Write => "変更（write）"
    case Admin => "管理（admin・管理者のみ）"
    case Scim  => "SCIM（プロビジョニング・管理者のみ）"
    case other => other
  }
}

/** 属性の種類. */
object AttrKinds {
  val all: List[(String, String)] = List("string" -> "文字列", "number" -> "数値", "boolean" -> "真偽値", "date" -> "日付", "list" -> "リスト")
}

// ------------------------------------------------------------------ 画面の設定・ログイン

final case class ProviderBriefDto(slug: String, name: String, kind: String) derives ConfiguredCodec

final case class ClientConfigDto(
    title: String,
    version: String,
    /** ロゴの URL（使用中のアカウントのグループの上書きを反映） */
    logoUrl: String = "/logo.svg",
    loginMessage: String = "",
    selfRegistration: Boolean = false,
    providers: List[ProviderBriefDto] = Nil,
    certEnabled: Boolean = false,
    passwordRules: List[String] = Nil,
    setupRequired: Boolean = false,
    mailEnabled: Boolean = false
) derives ConfiguredCodec

final case class AppBriefDto(id: UUID, slug: String, name: String, iconUrl: Option[String], launchUrl: Option[String] = None,
    description: String = "", protocol: String = "oidc") derives ConfiguredCodec

/** ポータルのアプリの並び順（ドラッグで並べ替えたもの）. */
final case class AppOrderReq(appIds: List[UUID]) derives ConfiguredCodec

final case class ScopeDto(name: String, description: String) derives ConfiguredCodec

/** 認可の要求（ログイン・同意・アカウントの選択の画面に出す）. */
final case class AuthRequestDto(id: UUID, app: AppBriefDto, scopes: List[ScopeDto] = Nil, prompt: List[String] = Nil,
    loginHint: Option[String] = None) derives ConfiguredCodec

final case class FlowUserDto(username: String, name: String, avatarUrl: Option[String]) derives ConfiguredCodec

final case class TotpSetupDto(id: UUID, secret: String, uri: String) derives ConfiguredCodec

/**
 * ログインの途中の状態. stage:
 * identify（ユーザー名とパスワード）| mfa（2つ目の要素）| enroll_mfa（認証アプリの登録が必要）| show_recovery（回復コードの表示）|
 * change_password（パスワードの変更が必要）| done（redirect へ移る）
 */
final case class FlowDto(
    id: UUID,
    stage: String,
    user: Option[FlowUserDto] = None,
    mfaMethods: List[String] = Nil,
    emailHint: Option[String] = None,
    emailSent: Boolean = false,
    totpSetup: Option[TotpSetupDto] = None,
    recoveryCodes: List[String] = Nil,
    passwordRules: List[String] = Nil,
    redirect: Option[String] = None,
    request: Option[AuthRequestDto] = None,
    message: Option[String] = None
) derives ConfiguredCodec

final case class LoginStartReq(requestId: Option[UUID] = None, returnTo: Option[String] = None, add: Boolean = false, stepUp: Boolean = false)
    derives ConfiguredCodec
final case class PasswordLoginReq(flowId: UUID, username: String, password: String) derives ConfiguredCodec
final case class MfaReq(flowId: UUID, method: String, code: String) derives ConfiguredCodec
final case class FlowReq(flowId: UUID) derives ConfiguredCodec
final case class FlowTotpVerifyReq(flowId: UUID, deviceId: UUID, code: String) derives ConfiguredCodec
final case class FlowPasswordReq(flowId: UUID, password: String) derives ConfiguredCodec
final case class ForgotReq(username: String) derives ConfiguredCodec
final case class ResetReq(token: String, password: String) derives ConfiguredCodec
final case class RegisterReq(flowId: UUID, username: String, email: String, name: String, password: String) derives ConfiguredCodec
final case class SetupReq(token: String, username: String, name: String, email: String, password: String) derives ConfiguredCodec
final case class SwitchReq(userId: UUID) derives ConfiguredCodec
final case class AccountLogoutReq(userId: Option[UUID] = None) derives ConfiguredCodec
final case class ConsentReq(requestId: UUID, approve: Boolean) derives ConfiguredCodec
final case class RedirectDto(redirect: String) derives ConfiguredCodec

/** このブラウザでログインしているアカウント. */
final case class AccountDto(userId: UUID, username: String, name: String, avatarUrl: Option[String], active: Boolean, authTime: Timestamp)
    derives ConfiguredCodec

// ------------------------------------------------------------------ 自分

final case class TotpDto(id: UUID, name: String, createdAt: Timestamp) derives ConfiguredCodec
final case class MfaStatusDto(totp: List[TotpDto] = Nil, recoveryRemaining: Int = 0, emailAvailable: Boolean = false, required: Boolean = false)
    derives ConfiguredCodec

final case class AttributeDefDto(key: String, label: String, kind: String = "string", description: String = "", userEditable: Boolean = false,
    required: Boolean = false, scimPath: Option[String] = None, sort: Int = 0) derives ConfiguredCodec

final case class MeDto(
    id: UUID,
    username: String,
    name: String,
    email: Option[String],
    emailVerified: Boolean,
    givenName: Option[String],
    familyName: Option[String],
    avatarUrl: Option[String],
    hasOwnAvatar: Boolean,
    isAdmin: Boolean,
    groups: List[String],
    attributes: Json,
    attributeDefs: List[AttributeDefDto],
    mfa: MfaStatusDto,
    passwordSet: Boolean,
    source: String,
    locale: Option[String] = None,
    zoneinfo: Option[String] = None,
    phoneNumber: Option[String] = None,
    passwordRules: List[String] = Nil
) derives ConfiguredCodec

final case class MeUpdateReq(name: String, givenName: Option[String] = None, familyName: Option[String] = None, email: Option[String] = None,
    attributes: Json = Json.obj(), locale: Option[String] = None, zoneinfo: Option[String] = None, phoneNumber: Option[String] = None)
    derives ConfiguredCodec

final case class PasswordChangeReq(current: String, next: String) derives ConfiguredCodec
final case class TotpVerifyReq(id: UUID, code: String, name: String = "認証アプリ") derives ConfiguredCodec
final case class RecoveryCodesDto(codes: List[String]) derives ConfiguredCodec

final case class LoginSessionDto(id: UUID, ip: Option[String], userAgent: Option[String], createdAt: Timestamp, lastSeenAt: Timestamp,
    amr: List[String], current: Boolean) derives ConfiguredCodec

final case class ApiTokenDto(id: UUID, name: String, prefix: String, scopes: List[String], expiresAt: Option[Timestamp],
    lastUsedAt: Option[Timestamp], createdAt: Timestamp, owner: Option[UserBrief] = None) derives ConfiguredCodec
final case class TokenReq(name: String, scopes: List[String], days: Option[Int] = None, userId: Option[UUID] = None) derives ConfiguredCodec
final case class CreatedTokenDto(token: String, info: ApiTokenDto) derives ConfiguredCodec

final case class UserCertDto(id: UUID, fingerprint: String, subject: String, issuer: String, notAfter: Timestamp, createdAt: Timestamp)
    derives ConfiguredCodec
final case class CertReq(pem: String) derives ConfiguredCodec

final case class ConsentDto(app: AppBriefDto, scopes: List[String], createdAt: Timestamp) derives ConfiguredCodec

// ------------------------------------------------------------------ 管理: ユーザー・グループ

final case class UserBrief(id: UUID, username: String, name: String, avatarUrl: Option[String] = None) derives ConfiguredCodec
final case class GroupBrief(id: UUID, name: String) derives ConfiguredCodec

final case class UserDto(
    id: UUID,
    username: String,
    name: String,
    email: Option[String] = None,
    emailVerified: Boolean = false,
    givenName: Option[String] = None,
    familyName: Option[String] = None,
    avatarUrl: Option[String] = None,
    isAdmin: Boolean = false,
    effectiveAdmin: Boolean = false,
    isService: Boolean = false,
    disabled: Boolean = false,
    locked: Boolean = false,
    lockedUntil: Option[Timestamp] = None,
    failedAttempts: Int = 0,
    attributes: Json = Json.obj(),
    source: String = "local",
    externalId: Option[String] = None,
    groups: List[GroupBrief] = Nil,
    directGroups: List[UUID] = Nil,
    mfaEnabled: Boolean = false,
    passwordSet: Boolean = false,
    mustChangePassword: Boolean = false,
    locale: Option[String] = None,
    zoneinfo: Option[String] = None,
    phoneNumber: Option[String] = None,
    createdAt: Option[Timestamp] = None,
    updatedAt: Option[Timestamp] = None,
    lastLoginAt: Option[Timestamp] = None
) derives ConfiguredCodec

final case class UserListDto(users: List[UserDto], total: Int) derives ConfiguredCodec

final case class UserReq(
    username: String,
    name: String,
    email: Option[String] = None,
    emailVerified: Boolean = false,
    givenName: Option[String] = None,
    familyName: Option[String] = None,
    isAdmin: Boolean = false,
    isService: Boolean = false,
    disabled: Boolean = false,
    mustChangePassword: Boolean = false,
    attributes: Json = Json.obj(),
    password: Option[String] = None,
    groupIds: Option[List[UUID]] = None,
    locale: Option[String] = None,
    zoneinfo: Option[String] = None,
    phoneNumber: Option[String] = None
) derives ConfiguredCodec

final case class SetPasswordReq(password: Option[String] = None, mustChange: Boolean = true, sendResetMail: Boolean = false) derives ConfiguredCodec
final case class GeneratedPasswordDto(password: Option[String]) derives ConfiguredCodec

final case class UserDetailDto(user: UserDto, sessions: List[LoginSessionDto], tokens: List[ApiTokenDto], certs: List[UserCertDto],
    identities: List[IdentityDto], consents: List[ConsentDto]) derives ConfiguredCodec
final case class IdentityDto(providerId: UUID, providerName: String, subject: String, email: Option[String], lastLoginAt: Option[Timestamp])
    derives ConfiguredCodec

final case class GroupDto(
    id: UUID,
    name: String,
    description: String = "",
    parentIds: List[UUID] = Nil,
    attributes: Json = Json.obj(),
    isAdmin: Boolean = false,
    rule: Option[Json] = None,
    source: String = "local",
    externalId: Option[String] = None,
    memberCount: Int = 0,
    createdAt: Option[Timestamp] = None,
    /** 優先度（大きいほど優先. 表示の上書きが重なったときに使う） */
    priority: Int = 0,
    /** ポリシーの上書き */
    policy: GroupPolicy = GroupPolicy()
) derives ConfiguredCodec

final case class GroupReq(name: String, description: String = "", parentIds: List[UUID] = Nil, attributes: Json = Json.obj(),
    isAdmin: Boolean = false, rule: Option[Json] = None, priority: Int = 0, policy: GroupPolicy = GroupPolicy()) derives ConfiguredCodec

final case class GroupMembersDto(direct: List[UserBrief], dynamic: List[UserBrief], effective: Int) derives ConfiguredCodec
final case class MembersReq(userIds: List[UUID]) derives ConfiguredCodec

// ------------------------------------------------------------------ 管理: アプリケーション

final case class MappingDto(name: String, expression: String, scope: Option[String] = None, friendlyName: Option[String] = None,
    multi: Boolean = false) derives ConfiguredCodec

final case class OidcDto(
    clientId: String = "",
    confidential: Boolean = true,
    redirectUris: List[String] = Nil,
    postLogoutRedirectUris: List[String] = Nil,
    grantTypes: List[String] = List("authorization_code", "refresh_token"),
    scopes: List[String] = List("openid", "profile", "email", "groups", "offline_access"),
    consent: String = "implicit",
    subMode: String = "id",
    signingAlg: String = "RS256",
    accessTokenTtl: Int = 3600,
    idTokenTtl: Int = 3600,
    refreshTokenTtl: Int = 2592000,
    includeGroups: Boolean = true,
    backchannelLogoutUri: Option[String] = None
) derives ConfiguredCodec

final case class SamlDto(
    entityId: String = "",
    acsUrl: String = "",
    acsBinding: String = "post",
    sloUrl: Option[String] = None,
    nameIdFormat: String = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    nameIdExpr: String = "{{user.email}}",
    signResponse: Boolean = true,
    signAssertion: Boolean = true,
    spCertificate: Option[String] = None,
    wantSignedRequests: Boolean = false,
    sessionTtl: Int = 28800
) derives ConfiguredCodec

final case class AppDto(
    id: UUID,
    slug: String,
    name: String,
    description: String = "",
    protocol: String = "oidc",
    enabled: Boolean = true,
    launchUrl: Option[String] = None,
    showInPortal: Boolean = true,
    iconUrl: Option[String] = None,
    requireMfa: Boolean = false,
    ipAllow: List[String] = Nil,
    restrictAccess: Boolean = false,
    accessGroups: List[UUID] = Nil,
    mappings: List[MappingDto] = Nil,
    oidc: Option[OidcDto] = None,
    saml: Option[SamlDto] = None,
    createdAt: Option[Timestamp] = None
) derives ConfiguredCodec

final case class AppReq(
    slug: String,
    name: String,
    description: String = "",
    protocol: String = "oidc",
    enabled: Boolean = true,
    launchUrl: Option[String] = None,
    showInPortal: Boolean = true,
    requireMfa: Boolean = false,
    ipAllow: List[String] = Nil,
    restrictAccess: Boolean = false,
    accessGroups: List[UUID] = Nil,
    mappings: List[MappingDto] = Nil,
    oidc: Option[OidcDto] = None,
    saml: Option[SamlDto] = None
) derives ConfiguredCodec

final case class AppCreatedDto(app: AppDto, clientSecret: Option[String] = None) derives ConfiguredCodec
final case class SecretDto(clientSecret: Option[String]) derives ConfiguredCodec
final case class PreviewReq(userId: UUID) derives ConfiguredCodec

/** この IdP の接続情報（アプリの登録の画面に出す）. */
final case class IdpInfoDto(
    issuer: String,
    discovery: String,
    jwksUri: String,
    authorizationEndpoint: String,
    tokenEndpoint: String,
    userinfoEndpoint: String,
    endSessionEndpoint: String,
    samlEntityId: String,
    samlMetadata: String,
    samlSsoUrl: String,
    samlSloUrl: String,
    samlCertificate: String,
    scimBase: String,
    mcpUrl: String
) derives ConfiguredCodec

// ------------------------------------------------------------------ 管理: 外部 IdP・証明書・鍵・監査ログ

final case class FederationDto(
    id: UUID,
    slug: String,
    kind: String,
    name: String,
    enabled: Boolean = true,
    issuer: String = "",
    clientId: String = "",
    hasSecret: Boolean = false,
    scopes: String = "openid profile email",
    subjectClaim: String = "sub",
    jit: Boolean = true,
    linkByEmail: Boolean = false,
    allowedDomains: List[String] = Nil,
    defaultGroups: List[UUID] = Nil,
    trustMfa: Boolean = false,
    syncEnabled: Boolean = false,
    syncConfig: Json = Json.obj(),
    syncIntervalMin: Int = 60,
    lastSyncAt: Option[Timestamp] = None,
    lastSyncResult: Option[String] = None,
    callbackUrl: String = ""
) derives ConfiguredCodec

final case class FederationReq(
    slug: String,
    kind: String,
    name: String,
    enabled: Boolean = true,
    issuer: String = "",
    clientId: String = "",
    clientSecret: Option[String] = None,
    scopes: String = "openid profile email",
    subjectClaim: String = "sub",
    jit: Boolean = true,
    linkByEmail: Boolean = false,
    allowedDomains: List[String] = Nil,
    defaultGroups: List[UUID] = Nil,
    trustMfa: Boolean = false,
    syncEnabled: Boolean = false,
    syncConfig: Option[Json] = None,
    syncIntervalMin: Int = 60
) derives ConfiguredCodec

final case class CertAuthorityDto(id: UUID, name: String, subject: String, notAfter: Option[Timestamp], enabled: Boolean, createdAt: Timestamp)
    derives ConfiguredCodec
final case class CertAuthorityReq(name: String, pem: String) derives ConfiguredCodec

final case class KeyDto(kid: String, alg: String, active: Boolean, createdAt: Timestamp, retiredAt: Option[Timestamp]) derives ConfiguredCodec

final case class AuditDto(
    id: Long,
    at: Timestamp,
    actorId: Option[UUID],
    actorName: Option[String],
    via: String,
    action: String,
    targetType: Option[String],
    targetId: Option[String],
    targetName: Option[String],
    ip: Option[String],
    userAgent: Option[String],
    success: Boolean,
    detail: Json
) derives ConfiguredCodec

final case class AuditListDto(items: List[AuditDto], total: Int) derives ConfiguredCodec
final case class AuditVerifyDto(checked: Long, brokenAt: Option[Long]) derives ConfiguredCodec

final case class DashboardDto(
    users: Int,
    disabledUsers: Int,
    lockedUsers: Int,
    groups: Int,
    apps: Int,
    loginsToday: Int,
    failuresToday: Int,
    mfaUsers: Int,
    recentFailures: List[AuditDto] = Nil
) derives ConfiguredCodec

final case class SyncResultDto(message: String) derives ConfiguredCodec
