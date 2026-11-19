package sruru.db

import sbirds.shared.AppError

import cats.effect.*
import cats.syntax.all.*
import doobie.*
import doobie.implicits.*
import doobie.postgres.implicits.*
import sruru.core.*

import java.time.Instant
import java.util.UUID

/** アプリケーション（OIDC・OAuth2・SAML）・クレームの対応・利用できるグループ・同意. */
final class AppStore(xa: Transactor[IO]) extends TxStore(xa) {

  private val appCols =
    fr"""a.id, a.slug, a.name, a.description, a.protocol, a.enabled, a.launch_url, a.show_in_portal, a.icon_updated_at,
    a.require_mfa, a.ip_allow, a.restrict_access, a.created_at, a.updated_at"""
  private def selectApp(where: Fragment): Query0[Application] =
    (fr"select" ++ appCols ++ fr"from applications a" ++ where).query[Application]

  def all: IO[List[Application]] = tx(selectApp(fr"order by lower(a.name), a.slug").to[List])
  def find(id: UUID): IO[Option[Application]] = tx(selectApp(fr"where a.id = $id").option)

  /** 利用者が並べ替えたポータルの順（なければ空）. */
  def appOrder(userId: UUID): IO[List[UUID]] =
    tx(sql"select app_ids from user_app_order where user_id = $userId".query[List[UUID]].option.map(_.getOrElse(Nil)))

  def setAppOrder(userId: UUID, appIds: List[UUID]): IO[Unit] = tx(
    sql"""insert into user_app_order (user_id, app_ids) values ($userId, ${appIds.toArray})
          on conflict (user_id) do update set app_ids = excluded.app_ids, updated_at = now()""".update.run.void
  )

  def clearAppOrder(userId: UUID): IO[Unit] =
    tx(sql"delete from user_app_order where user_id = $userId".update.run.void)
  def bySlug(slug: String): IO[Option[Application]] = tx(selectApp(fr"where a.slug = $slug").option)

  def create(a: Application,
             oidc: Option[OidcClientConfig],
             saml: Option[SamlConfig]): IO[Either[AppError, Application]] = tx(
    sql"select exists(select 1 from applications where slug = ${a.slug})".query[Boolean].unique.flatMap {
      case true => fail(AppError(ErrorCode.AppSlugTaken, s"スラッグ「${a.slug}」は使われています"))
      case false =>
        sql"""insert into applications (id, slug, name, description, protocol, enabled, launch_url, show_in_portal, require_mfa, ip_allow, restrict_access)
              values (${a.id}, ${a.slug}, ${a.name}, ${a.description}, ${a.protocol}, ${a.enabled}, ${a.launchUrl}, ${a.showInPortal},
                ${a.requireMfa}, ${a.ipAllow.toArray}, ${a.restrictAccess})""".update.run *>
          oidc.traverse_(insertOidc) *> saml.traverse_(insertSaml) *>
          selectApp(fr"where a.id = ${a.id}").unique.map(Right(_))
    }
  )

  def save(a: Application): IO[Either[AppError, Application]] = tx(
    sql"select exists(select 1 from applications where slug = ${a.slug} and id <> ${a.id})".query[
      Boolean
    ].unique.flatMap {
      case true => fail(AppError(ErrorCode.AppSlugTaken, s"スラッグ「${a.slug}」は使われています"))
      case false =>
        sql"""update applications set slug = ${a.slug}, name = ${a.name}, description = ${a.description}, enabled = ${a.enabled},
                launch_url = ${a.launchUrl}, show_in_portal = ${a.showInPortal}, require_mfa = ${a.requireMfa}, ip_allow = ${a.ipAllow.toArray},
                restrict_access = ${a.restrictAccess}, updated_at = now() where id = ${a.id}""".update.run *>
          selectApp(fr"where a.id = ${a.id}").option.map(_.toRight(AppError(ErrorCode.AppNotFound)))
    }
  )

  def delete(id: UUID): IO[Boolean] = tx(sql"delete from applications where id = $id".update.run.map(_ > 0))

  // ------------------------------------------------------------------ OIDC

  private val oidcCols =
    fr"""o.app_id, o.client_id, o.secret_hash, o.redirect_uris, o.post_logout_redirect_uris, o.grant_types, o.scopes,
    o.consent, o.sub_mode, o.signing_alg, o.access_token_ttl, o.id_token_ttl, o.refresh_token_ttl, o.include_groups, o.backchannel_logout_uri, o.include_app_names"""

  private def insertOidc(o: OidcClientConfig): ConnectionIO[Int] =
    sql"""insert into oidc_clients (app_id, client_id, secret_hash, redirect_uris, post_logout_redirect_uris, grant_types, scopes, consent,
            sub_mode, signing_alg, access_token_ttl, id_token_ttl, refresh_token_ttl, include_groups, backchannel_logout_uri, include_app_names)
          values (${o.appId}, ${o.clientId}, ${o.secretHash}, ${o.redirectUris.toArray}, ${o.postLogoutRedirectUris.toArray}, ${o.grantTypes.toArray},
            ${o.scopes.toArray}, ${o.consent}, ${o.subMode}, ${o.signingAlg}, ${o.accessTokenTtl}, ${o.idTokenTtl}, ${o.refreshTokenTtl},
            ${o.includeGroups}, ${o.backchannelLogoutUri}, ${o.includeAppNames})""".update.run

  def oidc(appId: UUID): IO[Option[OidcClientConfig]] =
    tx((fr"select" ++ oidcCols ++ fr"from oidc_clients o where o.app_id = $appId").query[OidcClientConfig].option)

  def allOidc: IO[List[OidcClientConfig]] =
    tx((fr"select" ++ oidcCols ++ fr"from oidc_clients o").query[OidcClientConfig].to[List])

  def byClientId(clientId: String): IO[Option[(Application, OidcClientConfig)]] = tx((fr"select" ++ appCols ++ fr"," ++
    oidcCols ++ fr"from applications a join oidc_clients o on o.app_id = a.id where o.client_id = $clientId").query[(
    Application,
    OidcClientConfig
  )].option)

  def saveOidc(o: OidcClientConfig): IO[Either[AppError, Unit]] = tx(
    sql"select exists(select 1 from oidc_clients where client_id = ${o.clientId} and app_id <> ${o.appId})".query[
      Boolean
    ].unique.flatMap {
      case true => fail(AppError(ErrorCode.ClientIdTaken, s"クライアント ID「${o.clientId}」は使われています"))
      case false =>
        sql"""update oidc_clients set client_id = ${o.clientId}, redirect_uris = ${o.redirectUris.toArray},
                post_logout_redirect_uris = ${o.postLogoutRedirectUris.toArray}, grant_types = ${o.grantTypes.toArray}, scopes = ${o.scopes.toArray},
                consent = ${o.consent}, sub_mode = ${o.subMode}, signing_alg = ${o.signingAlg}, access_token_ttl = ${o.accessTokenTtl},
                id_token_ttl = ${o.idTokenTtl}, refresh_token_ttl = ${o.refreshTokenTtl}, include_groups = ${o.includeGroups},
                backchannel_logout_uri = ${o.backchannelLogoutUri}, include_app_names = ${o.includeAppNames}
              where app_id = ${o.appId}""".update.run.as(Right(()))
    }
  )

  /** クライアントシークレットを変える（None なら公開クライアント）. */
  def setSecret(appId: UUID, hash: Option[Array[Byte]]): IO[Unit] =
    tx(sql"update oidc_clients set secret_hash = $hash where app_id = $appId".update.run.void)

  // ------------------------------------------------------------------ SAML

  private val samlCols =
    fr"""s.app_id, s.entity_id, s.acs_url, s.acs_binding, s.slo_url, s.name_id_format, s.name_id_expr, s.sign_response,
    s.sign_assertion, s.sp_certificate, s.want_signed_requests, s.session_ttl"""

  private def insertSaml(s: SamlConfig): ConnectionIO[Int] =
    sql"""insert into saml_providers (app_id, entity_id, acs_url, acs_binding, slo_url, name_id_format, name_id_expr, sign_response,
            sign_assertion, sp_certificate, want_signed_requests, session_ttl)
          values (${s.appId}, ${s.entityId}, ${s.acsUrl}, ${s.acsBinding}, ${s.sloUrl}, ${s.nameIdFormat}, ${s.nameIdExpr}, ${s.signResponse},
            ${s.signAssertion}, ${s.spCertificate}, ${s.wantSignedRequests}, ${s.sessionTtl})""".update.run

  def saml(appId: UUID): IO[Option[SamlConfig]] =
    tx((fr"select" ++ samlCols ++ fr"from saml_providers s where s.app_id = $appId").query[SamlConfig].option)

  def byEntityId(entityId: String): IO[Option[(Application, SamlConfig)]] = tx((fr"select" ++ appCols ++ fr"," ++
    samlCols ++ fr"from applications a join saml_providers s on s.app_id = a.id where s.entity_id = $entityId").query[(
    Application,
    SamlConfig
  )].option)

  def saveSaml(s: SamlConfig): IO[Either[AppError, Unit]] = tx(
    sql"select exists(select 1 from saml_providers where entity_id = ${s.entityId} and app_id <> ${s.appId})".query[
      Boolean
    ].unique.flatMap {
      case true => fail(AppError(ErrorCode.EntityIdTaken, s"エンティティ ID「${s.entityId}」は使われています"))
      case false =>
        sql"""update saml_providers set entity_id = ${s.entityId}, acs_url = ${s.acsUrl}, acs_binding = ${s.acsBinding}, slo_url = ${s.sloUrl},
                name_id_format = ${s.nameIdFormat}, name_id_expr = ${s.nameIdExpr}, sign_response = ${s.signResponse},
                sign_assertion = ${s.signAssertion}, sp_certificate = ${s.spCertificate}, want_signed_requests = ${s.wantSignedRequests},
                session_ttl = ${s.sessionTtl}
              where app_id = ${s.appId}""".update.run.as(Right(()))
    }
  )

  // ------------------------------------------------------------------ 対応・グループ・アイコン

  def mappings(appId: UUID): IO[List[AttrMapping]] = tx(
    sql"select id, app_id, name, expression, scope, friendly_name, multi, sort from attribute_mappings where app_id = $appId order by sort, name".query[
      AttrMapping
    ].to[List]
  )

  def setMappings(appId: UUID, ms: List[AttrMapping]): IO[Unit] = tx(
    sql"delete from attribute_mappings where app_id = $appId".update.run *>
      ms.zipWithIndex.traverse_ {
        (m, i) =>
          sql"""insert into attribute_mappings (id, app_id, name, expression, scope, friendly_name, multi, sort)
              values (${UUID.randomUUID()}, $appId, ${m.name}, ${m.expression}, ${m.scope}, ${m.friendlyName}, ${m.multi}, $i)""".update.run
      }
  )

  def accessGroups(appId: UUID): IO[List[UUID]] =
    tx(sql"select group_id from application_groups where app_id = $appId".query[UUID].to[List])

  def allAccessGroups: IO[Map[UUID, List[UUID]]] =
    tx(sql"select app_id, group_id from application_groups".query[(UUID, UUID)].to[List].map(_.groupMap(_._1)(_._2)))

  def setAccessGroups(appId: UUID, ids: List[UUID]): IO[Unit] =
    tx(sql"delete from application_groups where app_id = $appId".update.run *> ids.distinct.traverse_(g =>
      sql"insert into application_groups (app_id, group_id) values ($appId, $g)".update.run
    ))

  // ------------------------------------------------------------------ グループごとの表示名・ロゴ

  /** 上書きの一覧（グループの ID・グループの名前・表示名・ロゴの ID）. */
  def groupNames(appId: UUID): IO[List[(UUID, String, Option[String], Option[String])]] = tx(
    sql"""select n.group_id, g.name, n.name, n.logo from application_group_names n join groups g on g.id = n.group_id
          where n.app_id = $appId order by g.priority desc, lower(g.name)"""
      .query[(UUID, String, Option[String], Option[String])].to[List]
  )

  /** 上書きを置き換える（グループ・表示名・ロゴの ID）. */
  def setGroupNames(appId: UUID, items: List[(UUID, Option[String], Option[String])]): IO[Unit] =
    tx(sql"delete from application_group_names where app_id = $appId".update.run *>
      items.distinctBy(_._1).traverse_((g, n, l) =>
        sql"insert into application_group_names (app_id, group_id, name, logo) values ($appId, $g, $n, $l)".update.run
      ))

  /** 所属するグループ（groupIds）で決まるアプリケーションの表示名（上書きがあるものだけ. 優先度の大きいグループのもの）. */
  def displayNames(groupIds: Set[UUID]): IO[Map[UUID, String]] =
    if (groupIds.isEmpty) IO.pure(Map.empty)
    else
      tx(
        sql"""select distinct on (n.app_id) n.app_id, n.name from application_group_names n join groups g on g.id = n.group_id
              where n.group_id = any(${groupIds.toArray}) and coalesce(n.name, '') <> ''
              order by n.app_id, g.priority desc, lower(g.name)"""
          .query[(UUID, String)].to[List].map(_.toMap)
      )

  /** 所属するグループで決まるアプリケーションのロゴ（上書きがあるものだけ. brand_logos の ID）. */
  def displayLogos(groupIds: Set[UUID]): IO[Map[UUID, String]] =
    if (groupIds.isEmpty) IO.pure(Map.empty)
    else
      tx(
        sql"""select distinct on (n.app_id) n.app_id, n.logo from application_group_names n join groups g on g.id = n.group_id
              where n.group_id = any(${groupIds.toArray}) and n.logo is not null
              order by n.app_id, g.priority desc, lower(g.name)"""
          .query[(UUID, String)].to[List].map(_.toMap)
      )

  def icon(appId: UUID): IO[Option[(Array[Byte], String)]] =
    tx(sql"select icon, icon_type from applications where id = $appId and icon is not null".query[(
      Array[Byte],
      String
    )].option)

  def setIcon(appId: UUID, data: Option[(Array[Byte], String)]): IO[Unit] = tx(
    sql"""update applications set icon = ${data.map(_._1)}, icon_type = ${data.map(_._2)}, icon_updated_at = ${data.map(
        _ => Instant.now()
      )}
          where id = $appId""".update.run.void
  )

  // ------------------------------------------------------------------ 同意

  def consent(userId: UUID, appId: UUID): IO[Option[List[String]]] =
    tx(sql"select scopes from consents where user_id = $userId and app_id = $appId".query[List[String]].option)

  def putConsent(userId: UUID, appId: UUID, scopes: List[String]): IO[Unit] = tx(
    sql"""insert into consents (user_id, app_id, scopes) values ($userId, $appId, ${scopes.distinct.toArray})
          on conflict (user_id, app_id) do update set scopes = excluded.scopes, created_at = now()""".update.run.void
  )

  def consents(userId: UUID): IO[List[(UUID, List[String], Instant)]] =
    tx(sql"select app_id, scopes, created_at from consents where user_id = $userId".query[(
      UUID,
      List[String],
      Instant
    )].to[List])

  def deleteConsent(userId: UUID, appId: UUID): IO[Boolean] =
    tx(sql"delete from consents where user_id = $userId and app_id = $appId".update.run.map(_ > 0))
}
