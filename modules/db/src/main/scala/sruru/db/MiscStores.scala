package sruru.db

import cats.effect.*
import cats.syntax.all.*
import doobie.*
import doobie.implicits.*
import doobie.postgres.implicits.*
import io.circe.{Decoder, Encoder, Json}
import io.circe.syntax.*

import java.time.Instant
import java.util.UUID

/** 設定（キーごとの JSON）. */
final class SettingsStore(xa: Transactor[IO]) extends TxStore(xa):
  import Codecs.given

  def get(key: String): IO[Option[Json]] = tx(sql"select value from settings where key = $key".query[Json].option)

  def getAs[A: Decoder](key: String, default: => A): IO[A] = get(key).map(_.flatMap(_.as[A].toOption).getOrElse(default))

  def put[A: Encoder](key: String, value: A): IO[Unit] = tx(
    sql"""insert into settings (key, value) values ($key, ${value.asJson}) on conflict (key) do update set value = excluded.value, updated_at = now()"""
      .update.run.void
  )

  def delete(key: String): IO[Unit] = tx(sql"delete from settings where key = $key".update.run.void)

  // ------------------------------------------------------------------ ロゴ

  def addLogo(data: Array[Byte], contentType: String): IO[UUID] =
    val id = UUID.randomUUID()
    tx(sql"insert into brand_logos (id, data, content_type) values ($id, $data, $contentType)".update.run).as(id)

  def logo(id: UUID): IO[Option[(Array[Byte], String)]] =
    tx(sql"select data, content_type from brand_logos where id = $id".query[(Array[Byte], String)].option)

  /** 使われていないロゴを消す（before より前に作ったもの. 作ったばかりで保存前のものは残す）. */
  def purgeLogos(inUse: Set[UUID], before: Instant): IO[Int] =
    tx(sql"delete from brand_logos where created_at < $before and not (id = any(${inUse.toArray}))".update.run)

  /** まだなければ入れる. 入れたら true（複数ノードで1回だけの初期化）. */
  def putIfAbsent(key: String, value: Json): IO[Boolean] =
    tx(sql"insert into settings (key, value) values ($key, $value) on conflict do nothing".update.run.map(_ > 0))

final case class FederationProvider(
    id: UUID,
    slug: String,
    kind: String,
    name: String,
    enabled: Boolean,
    issuer: String,
    clientId: String,
    clientSecretEnc: String,
    scopes: String,
    subjectClaim: String,
    jit: Boolean,
    linkByEmail: Boolean,
    allowedDomains: List[String],
    defaultGroups: List[UUID],
    trustMfa: Boolean,
    syncEnabled: Boolean,
    syncConfigEnc: Option[String],
    syncIntervalMin: Int,
    lastSyncAt: Option[Instant],
    lastSyncResult: Option[String],
    createdAt: Instant
)

final case class FederatedIdentity(providerId: UUID, subject: String, userId: UUID, email: Option[String], createdAt: Instant, lastLoginAt: Option[Instant])

/** 外部の IdP と、外部のアカウントとの結び付き. */
final class FederationStore(xa: Transactor[IO]) extends TxStore(xa):

  private val cols = fr"""id, slug, kind, name, enabled, issuer, client_id, client_secret_enc, scopes, subject_claim, jit, link_by_email,
    allowed_domains, default_groups, trust_mfa, sync_enabled, sync_config_enc, sync_interval_min, last_sync_at, last_sync_result, created_at"""

  def all: IO[List[FederationProvider]] = tx((fr"select" ++ cols ++ fr"from federation_providers order by name").query[FederationProvider].to[List])
  def find(id: UUID): IO[Option[FederationProvider]] = tx((fr"select" ++ cols ++ fr"from federation_providers where id = $id").query[FederationProvider].option)
  def bySlug(slug: String): IO[Option[FederationProvider]] =
    tx((fr"select" ++ cols ++ fr"from federation_providers where slug = $slug").query[FederationProvider].option)

  def create(p: FederationProvider): IO[Either[StoreError, FederationProvider]] = tx(
    sql"select exists(select 1 from federation_providers where slug = ${p.slug})".query[Boolean].unique.flatMap {
      case true => fail(StoreError.Conflict(s"スラッグ「${p.slug}」は使われています"))
      case false =>
        sql"""insert into federation_providers (id, slug, kind, name, enabled, issuer, client_id, client_secret_enc, scopes, subject_claim, jit,
                link_by_email, allowed_domains, default_groups, trust_mfa, sync_enabled, sync_config_enc, sync_interval_min)
              values (${p.id}, ${p.slug}, ${p.kind}, ${p.name}, ${p.enabled}, ${p.issuer}, ${p.clientId}, ${p.clientSecretEnc}, ${p.scopes},
                ${p.subjectClaim}, ${p.jit}, ${p.linkByEmail}, ${p.allowedDomains.toArray}, ${p.defaultGroups.toArray}, ${p.trustMfa},
                ${p.syncEnabled}, ${p.syncConfigEnc}, ${p.syncIntervalMin})""".update.run.as(Right(p))
    }
  )

  def save(p: FederationProvider): IO[Either[StoreError, Unit]] = tx(
    sql"select exists(select 1 from federation_providers where slug = ${p.slug} and id <> ${p.id})".query[Boolean].unique.flatMap {
      case true => fail(StoreError.Conflict(s"スラッグ「${p.slug}」は使われています"))
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
    tx(sql"update federation_providers set last_sync_at = now(), last_sync_result = $result where id = $id".update.run.void)

  def identity(providerId: UUID, subject: String): IO[Option[FederatedIdentity]] = tx(
    sql"""select provider_id, subject, user_id, email, created_at, last_login_at from federated_identities
          where provider_id = $providerId and subject = $subject""".query[FederatedIdentity].option
  )

  def identitiesOf(userId: UUID): IO[List[FederatedIdentity]] = tx(
    sql"select provider_id, subject, user_id, email, created_at, last_login_at from federated_identities where user_id = $userId"
      .query[FederatedIdentity].to[List]
  )

  def link(providerId: UUID, subject: String, userId: UUID, email: Option[String]): IO[Unit] = tx(
    sql"""insert into federated_identities (provider_id, subject, user_id, email, last_login_at) values ($providerId, $subject, $userId, $email, now())
          on conflict (provider_id, subject) do update set user_id = excluded.user_id, email = excluded.email, last_login_at = now()""".update.run.void
  )


/** 送信待ちのメール. */
final case class OutMail(id: Long, to: String, subject: String, body: String, attempts: Int)

final class MailStore(xa: Transactor[IO]) extends TxStore(xa):

  def enqueue(to: String, subject: String, body: String): IO[Unit] =
    tx(sql"insert into mail_outbox (to_addr, subject, body) values ($to, $subject, $body)".update.run.void)

  /** 送る時刻になったメールを1件ずつ send で送る（ほかのノードとは重ならない）. */
  def process(limit: Int)(send: OutMail => IO[OutboxResult]): IO[Int] =
    processEach(
      sql"""select id, to_addr, subject, body, attempts from mail_outbox where sent_at is null and next_at <= now() and attempts < 10
            order by id limit $limit for update skip locked""".query[OutMail].to[List]
    )(send) { (m, r) =>
      r match
        case OutboxResult.Sent    => sql"update mail_outbox set sent_at = now(), error = null where id = ${m.id}".update.run
        case OutboxResult.Skip(e) => sql"update mail_outbox set sent_at = now(), error = $e where id = ${m.id}".update.run
        case OutboxResult.Retry(e) =>
          val secs = Outbox.backoffSeconds(m.attempts)
          sql"""update mail_outbox set attempts = attempts + 1, error = $e, next_at = now() + make_interval(secs => $secs)
                where id = ${m.id}""".update.run
    }

  def purge(before: Instant): IO[Int] = tx(sql"delete from mail_outbox where created_at < $before and sent_at is not null".update.run)
