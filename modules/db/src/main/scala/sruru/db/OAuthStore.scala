package sruru.db

import cats.effect.*
import cats.syntax.all.*
import doobie.*
import doobie.implicits.*
import doobie.postgres.implicits.*

import java.time.Instant
import java.util.UUID

/** 認可コードに結び付けた内容. */
final case class OAuthCode(clientId: String, userId: UUID, redirectUri: String, codeChallenge: String, scopes: List[String])

/** 連携（利用者 × クライアント）. lastUsedAt は今のアクセストークンを最後に使った日時. */
final case class OAuthGrant(id: UUID, userId: UUID, clientId: String, scopes: List[String], tokenId: UUID, createdAt: Instant,
    lastUsedAt: Option[Instant], expiresAt: Instant)

/** 発行するアクセストークン（API トークン）. */
final case class NewApiToken(name: String, prefix: String, hash: Array[Byte], scopes: List[String], expiresAt: Instant)

/** リフレッシュの結果. */
enum RefreshResult:
  case Ok(grant: OAuthGrant, token: ApiToken)
  /** 見つからない・期限切れ・別のクライアント. */
  case Invalid
  /** 使用済みのリフレッシュトークン（盗まれた可能性があるので連携ごと消した）. */
  case Reused

/** 兄弟のサービスへの OAuth の連携（認可コード・連携・リフレッシュトークン）. */
final class OAuthStore(xa: Transactor[IO]) extends TxStore(xa):

  private val grantCols =
    fr"g.id, g.user_id, g.client_id, g.scopes, g.token_id, g.created_at, (select t.last_used_at from api_tokens t where t.id = g.token_id), g.expires_at"

  // ------------------------------------------------------------------ 認可コード

  /** 認可コードを保存する（ついでに期限切れのコードと連携を消す）. */
  def createCode(hash: Array[Byte], c: OAuthCode, expiresAt: Instant): IO[Unit] = tx(
    sql"delete from oauth_codes where expires_at < now()".update.run *>
      sql"delete from api_tokens where id in (select token_id from oauth_grants where expires_at < now())".update.run *>
      sql"""insert into oauth_codes (code_hash, client_id, user_id, redirect_uri, code_challenge, scopes, expires_at)
            values ($hash, ${c.clientId}, ${c.userId}, ${c.redirectUri}, ${c.codeChallenge}, ${c.scopes.toArray}, $expiresAt)""".update.run
  ).void

  /** 認可コードを使う（1回だけ. 期限切れなら None）. */
  def consumeCode(hash: Array[Byte], now: Instant): IO[Option[OAuthCode]] = tx(
    sql"""delete from oauth_codes where code_hash = $hash returning client_id, user_id, redirect_uri, code_challenge, scopes, expires_at"""
      .query[(String, UUID, String, String, List[String], Instant)].option
  ).map(_.collect { case (c, u, r, ch, s, exp) if exp.isAfter(now) => OAuthCode(c, u, r, ch, s) })

  // ------------------------------------------------------------------ 連携

  /** 連携を作る（同じ利用者・クライアントの前の連携は、そのアクセストークンごと置き換える）. */
  def replaceGrant(userId: UUID, clientId: String, scopes: List[String], token: NewApiToken, refreshHash: Array[Byte],
      expiresAt: Instant): IO[ApiToken] = tx(
    for
      _ <- sql"delete from api_tokens where id in (select token_id from oauth_grants where user_id = $userId and client_id = $clientId)".update.run
      t <- FactorStore.insertToken(userId, token.name, token.prefix, token.hash, token.scopes, Some(token.expiresAt))
      _ <- sql"""insert into oauth_grants (id, user_id, client_id, scopes, refresh_hash, token_id, expires_at)
                 values (${UUID.randomUUID()}, $userId, $clientId, ${scopes.toArray}, $refreshHash, ${t.id}, $expiresAt)""".update.run
    yield t.copy(oauthClient = Some(clientId))
  )

  /**
   * リフレッシュトークンで、アクセストークンとリフレッシュトークンを新しくする（前のものは使えなくなる）.
   * 1つ前のリフレッシュトークンが使われたら、盗まれた可能性があるので連携ごと消す.
   */
  def refresh(hash: Array[Byte], clientId: String, newRefresh: Array[Byte], token: NewApiToken, expiresAt: Instant,
      now: Instant): IO[RefreshResult] = tx(
    (fr"select" ++ grantCols ++ fr"from oauth_grants g where g.refresh_hash = $hash for update").query[OAuthGrant].option.flatMap {
      case Some(g) if g.clientId == clientId && g.expiresAt.isAfter(now) =>
        for
          t <- FactorStore.insertToken(g.userId, token.name, token.prefix, token.hash, g.scopes, Some(token.expiresAt))
          _ <- sql"""update oauth_grants set token_id = ${t.id}, refresh_hash = $newRefresh, prev_refresh_hash = $hash, refreshed_at = $now,
                     expires_at = $expiresAt where id = ${g.id}""".update.run
          _ <- sql"delete from api_tokens where id = ${g.tokenId}".update.run
        yield RefreshResult.Ok(g.copy(tokenId = t.id, expiresAt = expiresAt), t.copy(oauthClient = Some(clientId)))
      case Some(_) => RefreshResult.Invalid.pure[ConnectionIO]
      case None =>
        sql"delete from api_tokens where id in (select token_id from oauth_grants where prev_refresh_hash = $hash and client_id = $clientId)"
          .update.run.map(n => if n > 0 then RefreshResult.Reused else RefreshResult.Invalid)
    }
  )

  def grantsOf(userId: UUID): IO[List[OAuthGrant]] =
    tx((fr"select" ++ grantCols ++ fr"from oauth_grants g where g.user_id = $userId order by g.created_at").query[OAuthGrant].to[List])

  /** 連携をやめる（アクセストークンを消すと連携も消える）. */
  def revoke(userId: UUID, clientId: String): IO[Boolean] =
    tx(sql"delete from api_tokens where id in (select token_id from oauth_grants where user_id = $userId and client_id = $clientId)".update.run.map(_ > 0))

  /** クライアントからの失効（RFC 7009. アクセストークン・リフレッシュトークンのどちらでも、その連携ごと）. */
  def revokeByToken(hash: Array[Byte], clientId: String): IO[Unit] = tx(
    sql"""delete from api_tokens where id in (select g.token_id from oauth_grants g where g.client_id = $clientId
          and (g.refresh_hash = $hash or g.token_id = (select t.id from api_tokens t where t.token_hash = $hash)))""".update.run.void
  )
