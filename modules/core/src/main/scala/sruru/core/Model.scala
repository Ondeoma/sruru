package sruru.core

import io.circe.Json
import io.circe.syntax.*

import java.time.Instant
import java.util.UUID

final case class User(
  id: UUID,
  username: String,
  email: Option[String],
  emailVerified: Boolean,
  name: String,
  givenName: Option[String],
  familyName: Option[String],
  passwordHash: Option[String],
  passwordChangedAt: Option[Instant],
  mustChangePassword: Boolean,
  isAdmin: Boolean,
  isService: Boolean,
  disabled: Boolean,
  lockedUntil: Option[Instant],
  failedAttempts: Int,
  attributes: Json,
  avatarUpdatedAt: Option[Instant],
  pictureUrl: Option[String],
  source: String,
  externalId: Option[String],
  locale: Option[String],
  zoneinfo: Option[String],
  phoneNumber: Option[String],
  createdAt: Instant,
  updatedAt: Instant,
  lastLoginAt: Option[Instant]) {
  def locked(
    now: Instant
  ): Boolean = lockedUntil.exists(_.isAfter(now))
  def hasAvatar: Boolean = avatarUpdatedAt.isDefined
}

final case class Group(
  id: UUID,
  name: String,
  description: String,
  /** 親グループ（複数. 子のメンバーは、すべての親のメンバーでもある） */
  parentIds: List[UUID],
  attributes: Json,
  isAdmin: Boolean,
  rule: Option[GroupRule],
  source: String,
  externalId: Option[String],
  createdAt: Instant,
  updatedAt: Instant,
  /** 優先度（大きいほど優先. 表示の上書きが重なったとき） */
  priority: Int = 0,
  /** ポリシーの上書き（なければ全体のまま） */
  policy: Option[sruru.shared.GroupPolicy] = None)

/** ユーザーの所属（直接・動的・親グループを含めた最終的な所属）. */
final case class Membership(
  groups: List[Group]) {
  def names: List[String] = groups.map(_.name).distinct.sorted
  def ids: Set[UUID] = groups.map(_.id).toSet
  def isAdmin: Boolean = groups.exists(_.isAdmin)
}

object Membership {

  /** 直接の所属から、親グループをたどって所属をすべて求める（循環は止める）. */
  def expand(
    direct: List[UUID],
    all: Map[UUID, Group]
  ): Membership = {
    @annotation.tailrec
    def go(
      todo: List[UUID],
      seen: Set[UUID]
    ): Set[UUID] = todo match {
      case Nil => seen
      case h :: t if seen(h) => go(t, seen)
      case h :: t => go(all.get(h).toList.flatMap(_.parentIds) ::: t, seen + h)
    }
    Membership(go(direct, Set.empty).toList.flatMap(all.get).sortBy(_.name))
  }
}

final case class AttributeDef(
  key: String,
  label: String,
  kind: String,
  description: String,
  userEditable: Boolean,
  required: Boolean,
  scimPath: Option[String],
  sort: Int)

final case class Application(
  id: UUID,
  slug: String,
  name: String,
  description: String,
  protocol: String,
  enabled: Boolean,
  launchUrl: Option[String],
  showInPortal: Boolean,
  iconUpdatedAt: Option[Instant],
  requireMfa: Boolean,
  ipAllow: List[String],
  restrictAccess: Boolean,
  createdAt: Instant,
  updatedAt: Instant)

final case class OidcClientConfig(
  appId: UUID,
  clientId: String,
  secretHash: Option[Array[Byte]],
  redirectUris: List[String],
  postLogoutRedirectUris: List[String],
  grantTypes: List[String],
  scopes: List[String],
  consent: String,
  subMode: String,
  signingAlg: String,
  accessTokenTtl: Int,
  idTokenTtl: Int,
  refreshTokenTtl: Int,
  includeGroups: Boolean,
  backchannelLogoutUri: Option[String],
  /** sbirds のサービス向けに、アプリケーションの表示名（sbirds_apps・sbirds_app）を ID トークンに入れる */
  includeAppNames: Boolean = false) {
  def isPublic: Boolean = secretHash.isEmpty
}

final case class SamlConfig(
  appId: UUID,
  entityId: String,
  acsUrl: String,
  acsBinding: String,
  sloUrl: Option[String],
  nameIdFormat: String,
  nameIdExpr: String,
  signResponse: Boolean,
  signAssertion: Boolean,
  spCertificate: Option[String],
  wantSignedRequests: Boolean,
  sessionTtl: Int)

final case class AttrMapping(
  id: UUID,
  appId: UUID,
  name: String,
  expression: String,
  scope: Option[String],
  friendlyName: Option[String],
  multi: Boolean,
  sort: Int)

/** 認証の方法（RFC 8176 の amr）. */
object Amr {
  val Pwd = "pwd"
  val Otp = "otp"
  val Mfa = "mfa"
  val Email = "email"
  val Swk = "swk" // クライアント証明書
  val Fed = "fed" // 外部の IdP
  def isMulti(
    amr: List[String]
  ): Boolean = amr.contains(Mfa)
}

/** 式・条件で使う値（{{user.…}}）. */
object Context {
  def user(
    u: User,
    m: Membership,
    picture: Option[String]
  ): Json =
    Json.obj(
      "id" -> u.id.toString.asJson,
      "username" -> u.username.asJson,
      "email" -> u.email.asJson,
      "email_verified" -> u.emailVerified.asJson,
      "name" -> u.name.asJson,
      "given_name" -> u.givenName.asJson,
      "family_name" -> u.familyName.asJson,
      "picture" -> picture.asJson,
      "locale" -> u.locale.asJson,
      "zoneinfo" -> u.zoneinfo.asJson,
      "phone_number" -> u.phoneNumber.asJson,
      "is_admin" -> (u.isAdmin || m.isAdmin).asJson,
      "source" -> u.source.asJson,
      "external_id" -> u.externalId.asJson,
      "groups" -> m.names.asJson,
      "group_ids" -> m.groups.map(_.id.toString).asJson,
      "attributes" -> u.attributes
    )

  def of(
    user: Json,
    app: Option[Application]
  ): Json =
    Json.obj(
      "user" -> user,
      "app" -> app.fold(Json.Null)(a =>
        Json.obj("slug" -> a.slug.asJson, "name" -> a.name.asJson, "id" -> a.id.toString.asJson)
      )
    )
}
