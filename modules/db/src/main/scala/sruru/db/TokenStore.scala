package sruru.db

import sbirds.db.*
import cats.effect.*
import cats.syntax.all.*
import doobie.*
import doobie.implicits.*
import doobie.postgres.implicits.*
import io.circe.Json

import java.time.Instant
import java.util.UUID

final case class AuthRequest(id: UUID,
                             appId: UUID,
                             protocol: String,
                             params: Json,
                             createdAt: Instant,
                             expiresAt: Instant)

final case class AuthCode(appId: UUID,
                          userId: UUID,
                          loginId: Option[UUID],
                          redirectUri: String,
                          scopes: List[String],
                          nonce: Option[String],
                          codeChallenge: Option[String],
                          challengeMethod: Option[String],
                          authTime: Instant,
                          amr: List[String],
                          expiresAt: Instant,
                          usedAt: Option[Instant])

final case class RefreshToken(id: UUID,
                              family: UUID,
                              appId: UUID,
                              userId: UUID,
                              loginId: Option[UUID],
                              scopes: List[String],
                              authTime: Instant,
                              amr: List[String],
                              createdAt: Instant,
                              expiresAt: Instant,
                              usedAt: Option[Instant],
                              revokedAt: Option[Instant])

final case class AccessTokenRow(jti: UUID,
                                appId: Option[UUID],
                                userId: Option[UUID],
                                loginId: Option[UUID],
                                scopes: List[String],
                                expiresAt: Instant,
                                revokedAt: Option[Instant])

final case class StoredKey(kid: String,
                           alg: String,
                           privateEnc: String,
                           publicJwk: Json,
                           certPem: Option[String],
                           active: Boolean,
                           createdAt: Instant,
                           retiredAt: Option[Instant])

/** 認可の要求・認可コード・リフレッシュトークン・アクセストークン・署名鍵. */
final class TokenStore(xa: Transactor[IO]) extends TxStore(xa) {
  import Codecs.given

  // ------------------------------------------------------------------ 認可の要求

  def createRequest(appId: UUID, protocol: String, params: Json, expiresAt: Instant): IO[AuthRequest] = {
    val r = AuthRequest(UUID.randomUUID(), appId, protocol, params, Instant.now(), expiresAt)
    tx(
      sql"insert into auth_requests (id, app_id, protocol, params, expires_at) values (${r.id}, $appId, $protocol, $params, $expiresAt)".update.run
    ).as(r)
  }

  def request(id: UUID, now: Instant): IO[Option[AuthRequest]] =
    tx(sql"select id, app_id, protocol, params, created_at, expires_at from auth_requests where id = $id and expires_at > $now".query[
      AuthRequest
    ].option)

  def updateRequest(id: UUID, params: Json): IO[Unit] =
    tx(sql"update auth_requests set params = $params where id = $id".update.run.void)

  def deleteRequest(id: UUID): IO[Unit] = tx(sql"delete from auth_requests where id = $id".update.run.void)

  // ------------------------------------------------------------------ 認可コード

  def createCode(hash: Array[Byte], c: AuthCode): IO[Unit] = tx(
    sql"""insert into auth_codes (code_hash, app_id, user_id, login_id, redirect_uri, scopes, nonce, code_challenge, challenge_method,
            auth_time, amr, expires_at)
          values ($hash, ${c.appId}, ${c.userId}, ${c.loginId}, ${c.redirectUri}, ${c.scopes.toArray}, ${c.nonce}, ${c.codeChallenge},
            ${c.challengeMethod}, ${c.authTime}, ${c.amr.toArray}, ${c.expiresAt})""".update.run.void
  )

  /**
   * 認可コードを使う（appId のクライアントのものだけ）. 1回目は Right(コード). 2回目以降は Left(コード)（RFC 6749 4.1.2: 発行したトークンを失効させるため）.
   * 期限切れ・存在しなければ None.
   */
  def useCode(hash: Array[Byte], appId: UUID, now: Instant): IO[Option[Either[AuthCode, AuthCode]]] = tx(
    // 他のクライアントが提示したコードは「ない」ものとして扱う（使用済みにも、再利用の失効の引き金にもさせない）
    sql"""select app_id, user_id, login_id, redirect_uri, scopes, nonce, code_challenge, challenge_method, auth_time, amr, expires_at, used_at
          from auth_codes where code_hash = $hash and app_id = $appId for update""".query[AuthCode].option.flatMap {
      case None => none[Either[AuthCode, AuthCode]].pure[ConnectionIO]
      // 使用済みなら期限が過ぎていても再利用として扱う（行は1日残る. 期限の後の再利用でも発行したトークンを失効させる）
      case Some(c) if c.usedAt.isDefined => Some(Left(c)).pure[ConnectionIO]
      case Some(c) if !c.expiresAt.isAfter(now) => none[Either[AuthCode, AuthCode]].pure[ConnectionIO]
      case Some(c) => sql"update auth_codes set used_at = $now where code_hash = $hash".update.run.as(Some(Right(c)))
    }
  )

  // ------------------------------------------------------------------ リフレッシュトークン

  private val rtCols =
    fr"id, family, app_id, user_id, login_id, scopes, auth_time, amr, created_at, expires_at, used_at, revoked_at"

  def createRefresh(hash: Array[Byte],
                    family: UUID,
                    appId: UUID,
                    userId: UUID,
                    loginId: Option[UUID],
                    scopes: List[String],
                    authTime: Instant,
                    amr: List[String],
                    expiresAt: Instant): IO[UUID] = {
    val id = UUID.randomUUID()
    tx(
      sql"""insert into refresh_tokens (id, token_hash, family, app_id, user_id, login_id, scopes, auth_time, amr, expires_at)
             values ($id, $hash, $family, $appId, $userId, $loginId, ${scopes.toArray}, $authTime, ${amr.toArray}, $expiresAt)""".update.run
    ).as(id)
  }

  def refresh(hash: Array[Byte]): IO[Option[RefreshToken]] =
    tx((fr"select" ++ rtCols ++ fr"from refresh_tokens where token_hash = $hash").query[RefreshToken].option)

  /** 使った印を付ける（同時に使われたら1回だけ成功する）. */
  def markRefreshUsed(id: UUID, now: Instant): IO[Boolean] =
    tx(
      sql"update refresh_tokens set used_at = $now where id = $id and used_at is null and revoked_at is null".update.run.map(
        _ > 0
      )
    )

  def revokeFamily(family: UUID): IO[Unit] =
    tx(sql"update refresh_tokens set revoked_at = now() where family = $family and revoked_at is null".update.run.void)

  /** 系列ごと失効させ、同じログイン・アプリで出したアクセストークンも失効させる（再利用の検出・RFC 7009 の失効）. */
  def revokeFamilyWithAccess(t: RefreshToken): IO[Unit] = tx(
    sql"update refresh_tokens set revoked_at = now() where family = ${t.family} and revoked_at is null".update.run *>
      sql"""update access_tokens set revoked_at = now() where app_id = ${t.appId} and user_id = ${t.userId}
            and login_id is not distinct from ${t.loginId} and revoked_at is null""".update.run.void
  )

  /** ユーザーのトークンをすべて失効させる（app を指定すればそのアプリの分だけ）. */
  def revokeUser(userId: UUID, appId: Option[UUID] = None): IO[Unit] =
    tx((fr"update refresh_tokens set revoked_at = now() where user_id = $userId and revoked_at is null" ++
      appId.fold(Fragment.empty)(a => fr"and app_id = $a")).update.run *>
      (fr"update access_tokens set revoked_at = now() where user_id = $userId and revoked_at is null" ++
        appId.fold(Fragment.empty)(a => fr"and app_id = $a")).update.run.void)

  /** ユーザーのトークンを失効させる（except のログインに結び付いたものは残す. offline_access も失効させる）. パスワードの変更など. */
  def revokeUserExcept(userId: UUID, except: Option[UUID]): IO[Unit] = tx(
    sql"""update refresh_tokens set revoked_at = now() where user_id = $userId and revoked_at is null
          and login_id is distinct from $except""".update.run *>
      sql"""update access_tokens set revoked_at = now() where user_id = $userId and revoked_at is null
            and login_id is distinct from $except""".update.run.void
  )

  /** ログインに結び付いたトークンを失効させる（ログアウト）. offline_access のリフレッシュトークンは残す. */
  def revokeLogin(loginId: UUID): IO[Unit] = tx(
    sql"""update refresh_tokens set revoked_at = now() where login_id = $loginId and revoked_at is null
          and not ('offline_access' = any(scopes))""".update.run *>
      sql"update access_tokens set revoked_at = now() where login_id = $loginId and revoked_at is null".update.run.void
  )

  /**
   * 認可コードの再利用のとき: そのコードから発行したリフレッシュトークンの系列（回したあとの分も、offline_access も）と、
   * 同じアプリ・ユーザーのアクセストークン（ログインに結び付いたもの・offline の分）を失効させる.
   */
  def revokeCodeFamily(c: AuthCode, family: UUID): IO[Unit] = tx(
    sql"update refresh_tokens set revoked_at = now() where family = $family and revoked_at is null".update.run *>
      sql"""update access_tokens set revoked_at = now() where app_id = ${c.appId} and user_id = ${c.userId}
            and (login_id is not distinct from ${c.loginId} or login_id is null) and revoked_at is null""".update.run.void
  )

  /** トークンを出したことのあるアプリ（バックチャネルのログアウトの送り先）. loginId を指定すればそのログインの分だけ. */
  def appsWithTokens(userId: UUID, loginId: Option[UUID]): IO[Set[UUID]] = {
    val byLogin = loginId.fold(Fragment.empty)(l => fr"and login_id = $l")
    tx(((fr"select app_id from refresh_tokens where user_id = $userId" ++ byLogin) ++ fr"union" ++
      (fr"select app_id from access_tokens where app_id is not null and user_id = $userId" ++ byLogin)).query[
      UUID
    ].to[List].map(_.toSet))
  }

  /** ユーザーが許可しているアプリ（有効なリフレッシュトークン）. */
  def grantsOf(userId: UUID, now: Instant): IO[List[(UUID, List[String], Instant)]] = tx(
    sql"""select app_id, scopes, max(created_at) from refresh_tokens where user_id = $userId and revoked_at is null and used_at is null
          and expires_at > $now group by app_id, scopes""".query[(UUID, List[String], Instant)].to[List]
  )

  // ------------------------------------------------------------------ アクセストークン

  def recordAccess(t: AccessTokenRow): IO[Unit] = tx(
    sql"""insert into access_tokens (jti, app_id, user_id, login_id, scopes, expires_at)
          values (${t.jti}, ${t.appId}, ${t.userId}, ${t.loginId}, ${t.scopes.toArray}, ${t.expiresAt})""".update.run.void
  )

  def access(jti: UUID): IO[Option[AccessTokenRow]] =
    tx(sql"select jti, app_id, user_id, login_id, scopes, expires_at, revoked_at from access_tokens where jti = $jti".query[
      AccessTokenRow
    ].option)

  def revokeAccess(jti: UUID): IO[Unit] =
    tx(sql"update access_tokens set revoked_at = now() where jti = $jti".update.run.void)

  def purge(now: Instant): IO[Int] = tx(
    for {
      a <- sql"delete from auth_requests where expires_at < $now".update.run
      b <- sql"delete from auth_codes where expires_at < $now - interval '1 day'".update.run
      c <- sql"delete from refresh_tokens where expires_at < $now".update.run
      d <- sql"delete from access_tokens where expires_at < $now".update.run
    } yield a + b + c + d
  )

  // ------------------------------------------------------------------ 署名鍵

  private val keyCols = fr"kid, alg, private_enc, public_jwk, cert_pem, active, created_at, retired_at"

  def keys: IO[List[StoredKey]] =
    tx((fr"select" ++ keyCols ++ fr"from signing_keys order by created_at desc").query[StoredKey].to[List])

  /** 鍵を追加して、その alg の使用中の鍵にする. */
  def addKey(k: StoredKey): IO[Unit] = tx(addKeyC(k))

  /** 鍵を退役させる（JWKS から外れ、以後その鍵で署名したトークンは検証できない）. 使用中の鍵は退役できない. */
  def retireKey(kid: String): IO[Boolean] =
    tx(
      sql"update signing_keys set retired_at = now() where kid = $kid and not active and retired_at is null".update.run.map(
        _ > 0
      )
    )

  /** 複数のノードが同時に起動しても鍵を1つだけ作るためのロック（トランザクションの間）. */
  def withKeyLock[A](action: ConnectionIO[A]): IO[A] =
    tx(sql"select pg_advisory_xact_lock(7213001)".query[Unit].unique *> action)

  def keysC: ConnectionIO[List[StoredKey]] = (fr"select" ++ keyCols ++ fr"from signing_keys").query[StoredKey].to[List]

  def addKeyC(k: StoredKey): ConnectionIO[Unit] =
    sql"update signing_keys set active = false where alg = ${k.alg} and active".update.run *>
      sql"""insert into signing_keys (kid, alg, private_enc, public_jwk, cert_pem, active)
            values (${k.kid}, ${k.alg}, ${k.privateEnc}, ${k.publicJwk}, ${k.certPem}, true)""".update.run.void
}
