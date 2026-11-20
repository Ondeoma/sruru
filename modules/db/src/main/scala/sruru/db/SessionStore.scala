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

final case class BrowserSession(id: UUID, activeUser: Option[UUID], expiresAt: Instant)

/** 1つのブラウザでログインしているアカウント. */
final case class Login(id: UUID,
                       browserSessionId: UUID,
                       userId: UUID,
                       authTime: Instant,
                       amr: List[String],
                       ip: Option[String],
                       userAgent: Option[String],
                       createdAt: Instant,
                       lastSeenAt: Instant,
                       expiresAt: Instant)

/** ログインの途中の状態. */
final case class LoginFlow(id: UUID,
                           browserSessionId: UUID,
                           userId: Option[UUID],
                           stage: String,
                           amr: List[String],
                           authRequestId: Option[UUID],
                           returnTo: Option[String],
                           data: Json,
                           expiresAt: Instant)

/** ブラウザのセッション・ログイン（複数アカウント）・ログインの途中の状態. */
final class SessionStore(xa: Transactor[IO]) extends TxStore(xa) {
  import Codecs.given

  // ------------------------------------------------------------------ ブラウザ

  /** domain は、作ったときのドメイン（アクセスしたホスト名. 既定のホスト名なら空）. */
  def createBrowser(tokenHash: Array[Byte],
                    ip: String,
                    ua: Option[String],
                    expiresAt: Instant,
                    domain: String = ""): IO[BrowserSession] = {
    val id = UUID.randomUUID()
    tx(
      sql"""insert into browser_sessions (id, token_hash, ip, user_agent, expires_at, domain)
            values ($id, $tokenHash, $ip, $ua, $expiresAt, $domain)""".update.run
    )
      .as(BrowserSession(id, None, expiresAt))
  }

  /** 作ったときと同じドメインでだけ見つかる（ほかのホスト名に Cookie を持ち込んでも使えない）. */
  def findBrowser(tokenHash: Array[Byte], now: Instant, domain: String = ""): IO[Option[BrowserSession]] =
    tx(
      sql"""select id, active_user, expires_at from browser_sessions
            where token_hash = $tokenHash and expires_at > $now and domain = $domain""".query[BrowserSession].option
    )

  /** Cookie の値を新しくする（ログインの完了時. セッションの固定化を防ぐ）. */
  def rotate(id: UUID, tokenHash: Array[Byte]): IO[Unit] =
    tx(sql"update browser_sessions set token_hash = $tokenHash where id = $id".update.run.void)

  def setActive(bsId: UUID, userId: Option[UUID]): IO[Unit] =
    tx(sql"update browser_sessions set active_user = $userId where id = $bsId".update.run.void)

  // ------------------------------------------------------------------ ログイン

  private val loginCols =
    fr"id, browser_session_id, user_id, auth_time, amr, ip, user_agent, created_at, last_seen_at, expires_at"

  def logins(bsId: UUID, now: Instant): IO[List[Login]] =
    tx((fr"select" ++ loginCols ++
      fr"from logins where browser_session_id = $bsId and expires_at > $now order by created_at").query[Login].to[List])

  def login(id: UUID): IO[Option[Login]] =
    tx((fr"select" ++ loginCols ++ fr"from logins where id = $id").query[Login].option)

  def loginsOfUser(userId: UUID, now: Instant): IO[List[Login]] =
    tx((fr"select" ++ loginCols ++
      fr"from logins where user_id = $userId and expires_at > $now order by last_seen_at desc").query[Login].to[List])

  /**
   * ログインを記録して、そのアカウントを使用中にする（同じアカウントなら認証の時刻と方法を更新）.
   * keepAuthTime は、本人確認をやり直していないとき（多要素認証の追加で、すでにある要素を確かめていない）に、前の認証の時刻を残す.
   */
  def upsertLogin(bsId: UUID,
                  userId: UUID,
                  amr: List[String],
                  ip: String,
                  ua: Option[String],
                  expiresAt: Instant,
                  keepAuthTime: Boolean = false): IO[Login] = tx(
    (sql"""insert into logins (id, browser_session_id, user_id, auth_time, amr, ip, user_agent, expires_at)
           values (${UUID.randomUUID()}, $bsId, $userId, now(), ${amr.distinct.toArray}, $ip, $ua, $expiresAt)
           on conflict (browser_session_id, user_id) do update set
             auth_time = case when $keepAuthTime then logins.auth_time else now() end, amr = excluded.amr, ip = excluded.ip,
             user_agent = excluded.user_agent, expires_at = excluded.expires_at, last_seen_at = now()
           returning """ ++ loginCols).query[Login].unique <*
      sql"update browser_sessions set active_user = $userId, expires_at = greatest(expires_at, $expiresAt) where id = $bsId".update.run
  )

  def touch(loginId: UUID): IO[Unit] =
    tx(sql"update logins set last_seen_at = now() where id = $loginId".update.run.void)

  def removeLogin(bsId: UUID, userId: UUID): IO[Option[UUID]] = tx(
    sql"delete from logins where browser_session_id = $bsId and user_id = $userId returning id".query[UUID].option <*
      sql"""update browser_sessions set active_user = (select user_id from logins where browser_session_id = $bsId order by last_seen_at desc limit 1)
            where id = $bsId and (active_user = $userId or active_user is null)""".update.run
  )

  def removeAll(bsId: UUID): IO[List[UUID]] =
    tx(sql"delete from logins where browser_session_id = $bsId returning id".query[UUID].to[List] <*
      sql"update browser_sessions set active_user = null where id = $bsId".update.run)

  def deleteLogin(id: UUID): IO[Option[Login]] =
    tx((fr"delete from logins where id = $id returning" ++ loginCols).query[Login].option)

  /** ユーザーのすべてのログインを消す（パスワードの変更・無効化）. except は残すログイン. */
  def deleteLoginsOfUser(userId: UUID, except: Option[UUID] = None): IO[List[UUID]] =
    tx(
      sql"delete from logins where user_id = $userId and id is distinct from $except returning id".query[UUID].to[List]
    )

  // ------------------------------------------------------------------ ログインの途中

  private val flowCols = fr"id, browser_session_id, user_id, stage, amr, auth_request_id, return_to, data, expires_at"

  def createFlow(bsId: UUID,
                 authRequestId: Option[UUID],
                 returnTo: Option[String],
                 expiresAt: Instant): IO[LoginFlow] = {
    val f = LoginFlow(UUID.randomUUID(), bsId, None, "identify", Nil, authRequestId, returnTo, Json.obj(), expiresAt)
    tx(sql"""insert into login_flows (id, browser_session_id, stage, auth_request_id, return_to, expires_at)
             values (${f.id}, $bsId, ${f.stage}, $authRequestId, $returnTo, $expiresAt)""".update.run).as(f)
  }

  def flow(id: UUID, bsId: UUID, now: Instant): IO[Option[LoginFlow]] =
    tx((fr"select" ++ flowCols ++
      fr"from login_flows where id = $id and browser_session_id = $bsId and expires_at > $now").query[LoginFlow].option)

  def saveFlow(f: LoginFlow): IO[Unit] = tx(
    sql"""update login_flows set user_id = ${f.userId}, stage = ${f.stage}, amr = ${f.amr.distinct.toArray}, data = ${f.data},
            auth_request_id = ${f.authRequestId}, return_to = ${f.returnTo}, expires_at = ${f.expiresAt} where id = ${f.id}""".update.run.void
  )

  def deleteFlow(id: UUID): IO[Unit] = tx(sql"delete from login_flows where id = $id".update.run.void)

  // ------------------------------------------------------------------ 掃除

  def purgeExpired(now: Instant): IO[Int] = tx(
    for {
      a <- sql"delete from login_flows where expires_at < $now".update.run
      c <- sql"delete from browser_sessions where expires_at < $now".update.run
    } yield a + c
  )

  /**
   * 期限切れのログイン（ブラウザのセッションが期限切れのものを含む）を消す.
   * 消したログイン (ID, ユーザー). 呼ぶ側でトークンの失効とバックチャネルの通知を行う. purgeExpired より先に呼ぶ.
   */
  def purgeLogins(now: Instant): IO[List[(UUID, UUID)]] = tx(
    sql"""delete from logins where expires_at < $now or browser_session_id in (select id from browser_sessions where expires_at < $now)
          returning id, user_id""".query[(UUID, UUID)].to[List]
  )

  /** 最後の操作が before より前のログイン (ID, ユーザー, 最後の操作, ドメイン)（ユーザー・ドメインごとの無操作の時間で消すかを決める）. */
  def idleLogins(before: Instant): IO[List[(UUID, UUID, Instant, String)]] =
    tx(sql"""select l.id, l.user_id, l.last_seen_at, b.domain from logins l
             join browser_sessions b on b.id = l.browser_session_id where l.last_seen_at < $before""".query[
      (UUID, UUID, Instant, String)
    ].to[List])

  // ------------------------------------------------------------------ ドメイン

  /** そのドメインのログイン (ID, ユーザー)（ドメインを消すときに終わらせる）. */
  def loginsOfDomain(domain: String): IO[List[(UUID, UUID)]] =
    tx(sql"""select l.id, l.user_id from logins l join browser_sessions b on b.id = l.browser_session_id
             where b.domain = $domain""".query[(UUID, UUID)].to[List])

  /** そのドメインのブラウザのセッションを消す（ログイン・ログインの途中の状態も一緒に消える）. */
  def deleteBrowsersOfDomain(domain: String): IO[Int] =
    tx(sql"delete from browser_sessions where domain = $domain".update.run)
}
