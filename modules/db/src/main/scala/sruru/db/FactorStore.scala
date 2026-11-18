package sruru.db

import cats.effect.*
import cats.syntax.all.*
import doobie.*
import doobie.implicits.*
import doobie.postgres.implicits.*

import java.time.Instant
import java.util.UUID

final case class TotpDevice(id: UUID, userId: UUID, name: String, secretEnc: String, confirmed: Boolean, lastUsedStep: Long, createdAt: Instant)
final case class EmailToken(id: UUID, userId: UUID, purpose: String, tokenHash: Array[Byte], attempts: Int, expiresAt: Instant)
/** API トークン. oauthClient は OAuth の連携で発行したもの（OAUTH_CLIENTS の id）. */
final case class ApiToken(id: UUID, userId: UUID, name: String, prefix: String, scopes: List[String], expiresAt: Option[Instant],
    lastUsedAt: Option[Instant], createdAt: Instant, oauthClient: Option[String] = None)
final case class UserCert(id: UUID, userId: UUID, fingerprint: String, subject: String, issuer: String, notAfter: Instant, createdAt: Instant)
final case class CertAuthority(id: UUID, name: String, pem: String, enabled: Boolean, createdAt: Instant)

/** 多要素認証・メールのコード・API トークン・証明書・ログインの試行の制限. */
final class FactorStore(xa: Transactor[IO]) extends TxStore(xa):

  // ------------------------------------------------------------------ TOTP

  private val totpCols = fr"id, user_id, name, secret_enc, confirmed, last_used_step, created_at"

  def totps(userId: UUID): IO[List[TotpDevice]] =
    tx((fr"select" ++ totpCols ++ fr"from mfa_totp where user_id = $userId order by created_at").query[TotpDevice].to[List])

  def totp(id: UUID): IO[Option[TotpDevice]] = tx((fr"select" ++ totpCols ++ fr"from mfa_totp where id = $id").query[TotpDevice].option)

  def addTotp(userId: UUID, name: String, secretEnc: String): IO[TotpDevice] =
    val d = TotpDevice(UUID.randomUUID(), userId, name, secretEnc, false, 0, Instant.now())
    tx(sql"insert into mfa_totp (id, user_id, name, secret_enc) values (${d.id}, $userId, $name, $secretEnc)".update.run).as(d)

  def confirmTotp(id: UUID, step: Long): IO[Unit] =
    tx(sql"update mfa_totp set confirmed = true, last_used_step = $step where id = $id".update.run.void)

  /** 使ったステップを記録する（前より新しいときだけ. 同時に2回使われても1回だけ成功する）. */
  def useTotp(id: UUID, step: Long): IO[Boolean] =
    tx(sql"update mfa_totp set last_used_step = $step where id = $id and last_used_step < $step".update.run.map(_ > 0))

  /** 認証アプリを登録しているユーザー（ids を指定すればその中だけ）. */
  def usersWithTotp(ids: Option[List[UUID]] = None): IO[Set[UUID]] = tx(
    (fr"select distinct user_id from mfa_totp where confirmed" ++ ids.fold(Fragment.empty)(xs => fr"and user_id = any(${xs.toArray})"))
      .query[UUID].to[List].map(_.toSet)
  )

  def deleteTotp(userId: UUID, id: UUID): IO[Boolean] = tx(sql"delete from mfa_totp where id = $id and user_id = $userId".update.run.map(_ > 0))

  def deleteUnconfirmedTotps(userId: UUID): IO[Unit] = tx(sql"delete from mfa_totp where user_id = $userId and not confirmed".update.run.void)

  /** 多要素認証をすべて外す（管理者がリセットする）. */
  def resetMfa(userId: UUID): IO[Unit] = tx(
    sql"delete from mfa_totp where user_id = $userId".update.run *> sql"delete from mfa_recovery_codes where user_id = $userId".update.run.void
  )

  // ------------------------------------------------------------------ 回復コード

  def setRecoveryCodes(userId: UUID, hashes: List[Array[Byte]]): IO[Unit] = tx(
    sql"delete from mfa_recovery_codes where user_id = $userId".update.run *>
      hashes.traverse_(h => sql"insert into mfa_recovery_codes (user_id, code_hash) values ($userId, $h)".update.run)
  )

  def useRecoveryCode(userId: UUID, hash: Array[Byte]): IO[Boolean] = tx(
    sql"update mfa_recovery_codes set used_at = now() where user_id = $userId and code_hash = $hash and used_at is null".update.run.map(_ > 0)
  )

  def recoveryRemaining(userId: UUID): IO[Int] =
    tx(sql"select count(*) from mfa_recovery_codes where user_id = $userId and used_at is null".query[Int].unique)

  // ------------------------------------------------------------------ メールのコード・リンク

  /** 同じ目的の古いものは消して新しく作る. */
  def createEmailToken(userId: UUID, purpose: String, hash: Array[Byte], expiresAt: Instant): IO[UUID] =
    val id = UUID.randomUUID()
    tx(sql"delete from email_tokens where user_id = $userId and purpose = $purpose".update.run *>
      sql"insert into email_tokens (id, user_id, purpose, token_hash, expires_at) values ($id, $userId, $purpose, $hash, $expiresAt)".update.run).as(id)

  def emailToken(userId: UUID, purpose: String, now: Instant): IO[Option[EmailToken]] = tx(
    sql"""select id, user_id, purpose, token_hash, attempts, expires_at from email_tokens
          where user_id = $userId and purpose = $purpose and consumed_at is null and expires_at > $now""".query[EmailToken].option
  )

  def emailTokenByHash(purpose: String, hash: Array[Byte], now: Instant): IO[Option[EmailToken]] = tx(
    sql"""select id, user_id, purpose, token_hash, attempts, expires_at from email_tokens
          where purpose = $purpose and token_hash = $hash and consumed_at is null and expires_at > $now""".query[EmailToken].option
  )

  /** 試行を1回数える. 上限に達していれば false（確認と加算を1つの SQL で行う）. */
  def emailTokenAttempt(id: UUID, max: Int): IO[Boolean] =
    tx(sql"update email_tokens set attempts = attempts + 1 where id = $id and attempts < $max".update.run.map(_ > 0))

  def consumeEmailToken(id: UUID): IO[Boolean] =
    tx(sql"update email_tokens set consumed_at = now() where id = $id and consumed_at is null".update.run.map(_ > 0))

  // ------------------------------------------------------------------ API トークン

  private val tokenCols = FactorStore.tokenCols

  def createToken(userId: UUID, name: String, prefix: String, hash: Array[Byte], scopes: List[String], expiresAt: Option[Instant]): IO[ApiToken] =
    tx(FactorStore.insertToken(userId, name, prefix, hash, scopes, expiresAt))

  def tokens(userId: UUID): IO[List[ApiToken]] =
    tx((fr"select" ++ tokenCols ++ fr"from api_tokens where user_id = $userId order by created_at desc").query[ApiToken].to[List])

  def allTokens: IO[List[ApiToken]] = tx((fr"select" ++ tokenCols ++ fr"from api_tokens order by created_at desc").query[ApiToken].to[List])

  /** 有効なトークン（使った日時も記録する）. */
  def findToken(hash: Array[Byte], now: Instant): IO[Option[ApiToken]] = tx(
    (fr"update api_tokens set last_used_at = $now where token_hash = $hash and (expires_at is null or expires_at > $now) returning" ++ tokenCols)
      .query[ApiToken].option
  )

  def deleteToken(id: UUID, userId: Option[UUID]): IO[Boolean] = tx(
    (fr"delete from api_tokens where id = $id" ++ userId.fold(Fragment.empty)(u => fr"and user_id = $u")).update.run.map(_ > 0)
  )

  // ------------------------------------------------------------------ クライアント証明書

  def userCerts(userId: UUID): IO[List[UserCert]] = tx(
    sql"select id, user_id, fingerprint, subject, issuer, not_after, created_at from user_certificates where user_id = $userId order by created_at"
      .query[UserCert].to[List]
  )

  def certByFingerprint(fp: String): IO[Option[UserCert]] = tx(
    sql"select id, user_id, fingerprint, subject, issuer, not_after, created_at from user_certificates where fingerprint = $fp".query[UserCert].option
  )

  def addUserCert(userId: UUID, fp: String, subject: String, issuer: String, notAfter: Instant): IO[Either[StoreError, UserCert]] =
    val c = UserCert(UUID.randomUUID(), userId, fp, subject, issuer, notAfter, Instant.now())
    tx(sql"select exists(select 1 from user_certificates where fingerprint = $fp)".query[Boolean].unique.flatMap {
      case true  => fail(StoreError.Conflict("この証明書はすでに登録されています"))
      case false =>
        sql"""insert into user_certificates (id, user_id, fingerprint, subject, issuer, not_after)
              values (${c.id}, $userId, $fp, $subject, $issuer, $notAfter)""".update.run.as(Right(c))
    })

  def deleteUserCert(id: UUID, userId: Option[UUID]): IO[Boolean] = tx(
    (fr"delete from user_certificates where id = $id" ++ userId.fold(Fragment.empty)(u => fr"and user_id = $u")).update.run.map(_ > 0)
  )

  def authorities: IO[List[CertAuthority]] =
    tx(sql"select id, name, pem, enabled, created_at from cert_authorities order by created_at".query[CertAuthority].to[List])

  def addAuthority(name: String, pem: String): IO[CertAuthority] =
    val c = CertAuthority(UUID.randomUUID(), name, pem, true, Instant.now())
    tx(sql"insert into cert_authorities (id, name, pem) values (${c.id}, $name, $pem)".update.run).as(c)

  def deleteAuthority(id: UUID): IO[Boolean] = tx(sql"delete from cert_authorities where id = $id".update.run.map(_ > 0))

  // ------------------------------------------------------------------ IP アドレスごとの失敗の回数

  /** 失敗を数える（窓が過ぎていれば数え直す）. 窓の中の失敗の回数. */
  def throttleFail(key: String, windowStart: Instant): IO[Int] = tx(
    sql"""insert into login_throttle (key, failures, window_start) values ($key, 1, now())
          on conflict (key) do update set
            failures = case when login_throttle.window_start < $windowStart then 1 else login_throttle.failures + 1 end,
            window_start = case when login_throttle.window_start < $windowStart then now() else login_throttle.window_start end
          returning failures""".query[Int].unique
  )

  def throttleCount(key: String, windowStart: Instant): IO[Int] =
    tx(sql"select failures from login_throttle where key = $key and window_start >= $windowStart".query[Int].option.map(_.getOrElse(0)))

  def purgeThrottle(before: Instant): IO[Int] = tx(sql"delete from login_throttle where window_start < $before".update.run)

  def purgeEmailTokens(now: Instant): IO[Int] = tx(sql"delete from email_tokens where expires_at < $now".update.run)

object FactorStore:
  /** API トークンの列（OAuth の連携で発行したものは、そのクライアントも）. */
  private[db] val tokenCols =
    fr"id, user_id, name, prefix, scopes, expires_at, last_used_at, created_at, (select g.client_id from oauth_grants g where g.token_id = api_tokens.id)"

  /** API トークンを作る（OAuth の連携と同じトランザクションで作れるように ConnectionIO で）. */
  private[db] def insertToken(userId: UUID, name: String, prefix: String, hash: Array[Byte], scopes: List[String],
      expiresAt: Option[Instant]): ConnectionIO[ApiToken] =
    val t = ApiToken(UUID.randomUUID(), userId, name, prefix, scopes, expiresAt, None, Instant.now())
    sql"""insert into api_tokens (id, user_id, name, prefix, token_hash, scopes, expires_at)
          values (${t.id}, $userId, $name, $prefix, $hash, ${scopes.toArray}, $expiresAt)""".update.run.as(t)
