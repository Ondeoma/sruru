package sruru.db

import sbirds.db.*
import sruru.core.ErrorCode

import sbirds.shared.AppError

import cats.effect.*
import cats.syntax.all.*
import doobie.*
import doobie.implicits.*
import doobie.postgres.implicits.*

import java.util.UUID

/** 外部の IdP と、外部のアカウントとの結び付き. */
final class FederationStore(xa: Transactor[IO]) extends TxStore(xa) {

  private val cols =
    fr"""id, slug, kind, name, enabled, issuer, client_id, client_secret_enc, scopes, subject_claim, jit, link_by_email,
    allowed_domains, default_groups, trust_mfa, sync_enabled, sync_config_enc, sync_interval_min, last_sync_at, last_sync_result, created_at"""

  def all: IO[List[FederationProvider]] =
    tx((fr"select" ++ cols ++ fr"from federation_providers order by name").query[FederationProvider].to[List])
  def find(id: UUID): IO[Option[FederationProvider]] =
    tx((fr"select" ++ cols ++ fr"from federation_providers where id = $id").query[FederationProvider].option)
  def bySlug(slug: String): IO[Option[FederationProvider]] =
    tx((fr"select" ++ cols ++ fr"from federation_providers where slug = $slug").query[FederationProvider].option)

  def create(p: FederationProvider): IO[Either[AppError, FederationProvider]] = tx(
    sql"select exists(select 1 from federation_providers where slug = ${p.slug})".query[Boolean].unique.flatMap {
      case true => fail(AppError(ErrorCode.ProviderSlugTaken, s"スラッグ「${p.slug}」は使われています"))
      case false =>
        sql"""insert into federation_providers (id, slug, kind, name, enabled, issuer, client_id, client_secret_enc, scopes, subject_claim, jit,
                link_by_email, allowed_domains, default_groups, trust_mfa, sync_enabled, sync_config_enc, sync_interval_min)
              values (${p.id}, ${p.slug}, ${p.kind}, ${p.name}, ${p.enabled}, ${p.issuer}, ${p.clientId}, ${p.clientSecretEnc}, ${p.scopes},
                ${p.subjectClaim}, ${p.jit}, ${p.linkByEmail}, ${p.allowedDomains.toArray}, ${p.defaultGroups.toArray}, ${p.trustMfa},
                ${p.syncEnabled}, ${p.syncConfigEnc}, ${p.syncIntervalMin})""".update.run.as(Right(p))
    }
  )

  def save(p: FederationProvider): IO[Either[AppError, Unit]] = tx(
    sql"select exists(select 1 from federation_providers where slug = ${p.slug} and id <> ${p.id})".query[
      Boolean
    ].unique.flatMap {
      case true => fail(AppError(ErrorCode.ProviderSlugTaken, s"スラッグ「${p.slug}」は使われています"))
      case false =>
        sql"""update federation_providers set slug = ${p.slug}, name = ${p.name}, enabled = ${p.enabled}, issuer = ${p.issuer},
                client_id = ${p.clientId}, client_secret_enc = ${p.clientSecretEnc}, scopes = ${p.scopes}, subject_claim = ${p.subjectClaim},
                jit = ${p.jit}, link_by_email = ${p.linkByEmail}, allowed_domains = ${p.allowedDomains.toArray},
                default_groups = ${p.defaultGroups.toArray}, trust_mfa = ${p.trustMfa}, sync_enabled = ${p.syncEnabled},
                sync_config_enc = ${p.syncConfigEnc}, sync_interval_min = ${p.syncIntervalMin}
              where id = ${p.id}""".update.run.as(Right(()))
    }
  )

  def delete(id: UUID): IO[Boolean] = tx(sql"delete from federation_providers where id = $id".update.run.map(_ > 0))

  def recordSync(id: UUID, result: String): IO[Unit] =
    tx(
      sql"update federation_providers set last_sync_at = now(), last_sync_result = $result where id = $id".update.run.void
    )

  def identity(providerId: UUID, subject: String): IO[Option[FederatedIdentity]] = tx(
    sql"""select provider_id, subject, user_id, email, created_at, last_login_at from federated_identities
          where provider_id = $providerId and subject = $subject""".query[FederatedIdentity].option
  )

  def identitiesOf(userId: UUID): IO[List[FederatedIdentity]] =
    tx(sql"select provider_id, subject, user_id, email, created_at, last_login_at from federated_identities where user_id = $userId".query[
      FederatedIdentity
    ].to[List])

  def link(providerId: UUID, subject: String, userId: UUID, email: Option[String]): IO[Unit] = tx(
    sql"""insert into federated_identities (provider_id, subject, user_id, email, last_login_at) values ($providerId, $subject, $userId, $email, now())
          on conflict (provider_id, subject) do update set user_id = excluded.user_id, email = excluded.email, last_login_at = now()""".update.run.void
  )
}
