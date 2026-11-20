package sruru.db

import sbirds.db.*
import sbirds.shared.AppError

import cats.effect.*
import cats.syntax.all.*
import doobie.*
import doobie.implicits.*
import doobie.postgres.implicits.*
import io.circe.Json
import sruru.core.*

import java.time.Instant
import java.util.UUID

/** 新しいユーザー. */
final case class NewUser(username: String,
                         email: Option[String],
                         name: String,
                         givenName: Option[String] = None,
                         familyName: Option[String] = None,
                         passwordHash: Option[String] = None,
                         mustChangePassword: Boolean = false,
                         isAdmin: Boolean = false,
                         isService: Boolean = false,
                         emailVerified: Boolean = false,
                         attributes: Json = Json.obj(),
                         source: String = "local",
                         externalId: Option[String] = None,
                         pictureUrl: Option[String] = None)

/** ユーザーの一覧の絞り込み. */
final case class UserQuery(q: Option[String] = None,
                           status: Option[String] = None,
                           groupId: Option[UUID] = None,
                           source: Option[String] = None,
                           limit: Int = 50,
                           offset: Int = 0)

/** ユーザー・パスワード・ロック・アイコン. */
final class UserStore(xa: Transactor[IO]) extends TxStore(xa) {
  import Codecs.given

  private val cols =
    fr"""u.id, u.username, u.email, u.email_verified, u.verified_email, u.name, u.given_name, u.family_name, u.password_hash,
    u.password_changed_at, u.must_change_password, u.is_admin, u.is_service, u.disabled, u.locked_until, u.failed_attempts,
    u.attributes, u.avatar_updated_at, u.picture_url, u.source, u.external_id, u.locale, u.zoneinfo, u.phone_number,
    u.created_at, u.updated_at, u.last_login_at"""

  private def select(where: Fragment): Query0[User] = (fr"select" ++ cols ++ fr"from users u" ++ where).query[User]

  def find(id: UUID): IO[Option[User]] = tx(findC(id))
  def findC(id: UUID): ConnectionIO[Option[User]] = select(fr"where u.id = $id").option

  def findMany(ids: List[UUID]): IO[List[User]] =
    if ids.isEmpty then IO.pure(Nil) else tx(select(fr"where u.id = any(${ids.toArray})").to[List])

  def byUsername(username: String): IO[Option[User]] = tx(select(fr"where lower(u.username) = lower($username)").option)

  def byEmail(email: String): IO[List[User]] = tx(select(fr"where lower(u.email) = lower($email)").to[List])

  /** 確認済みのアドレスがこの値のユーザー（各サービスにこのアドレスで知られている人）. */
  def byVerifiedEmail(email: String): IO[List[User]] =
    tx(select(fr"where lower(u.verified_email) = lower($email)").to[List])

  /** ログインの名前（ユーザー名、またはメールアドレスで1人に決まるとき）. */
  def byLoginName(s: String): IO[Option[User]] =
    byUsername(s).flatMap {
      case Some(u) => IO.pure(Some(u))
      case None if s.contains('@') => byEmail(s).map { case List(u) => Some(u); case _ => None }
      case None => IO.pure(None)
    }

  def byExternal(source: String, externalId: String): IO[Option[User]] =
    tx(select(fr"where u.source = $source and u.external_id = $externalId").option)

  def all: IO[List[User]] = tx(select(fr"order by u.username").to[List])

  def count: IO[Int] = tx(sql"select count(*) from users where not is_service".query[Int].unique)

  def adminCount: IO[Int] = tx(sql"select count(*) from users where is_admin and not disabled".query[Int].unique)

  def list(q: UserQuery, now: Instant): IO[(List[User], Int)] = {
    val conds = List(
      q.q.map(_.trim).filter(_.nonEmpty).map { s =>
        val like = "%" + s.toLowerCase.replace("%", "\\%").replace("_", "\\_") + "%"
        fr"(lower(u.username) like $like or lower(u.name) like $like or lower(coalesce(u.email, '')) like $like or lower(coalesce(u.external_id, '')) like $like)"
      },
      q.status.collect {
        case "active" => fr"not u.disabled and not u.is_service"
        case "disabled" => fr"u.disabled"
        case "locked" => fr"u.locked_until > $now"
        case "service" => fr"u.is_service"
        case "admin" => fr"u.is_admin"
      },
      q.groupId.map(g =>
        fr"u.id in (select user_id from group_members where group_id = $g union select user_id from group_dynamic_members where group_id = $g)"
      ),
      q.source.map(s => fr"u.source = $s")
    ).flatten
    tx(for {
      rows <-
      (fr"select" ++ cols ++ fr"from users u" ++ Sql.whereAnd(conds) ++
        fr"order by lower(u.username) limit ${q.limit} offset ${q.offset}").query[User].to[List]
      total <- (fr"select count(*) from users u" ++ Sql.whereAnd(conds)).query[Int].unique
    } yield (rows, total))
  }

  def create(n: NewUser): IO[Either[AppError, User]] = {
    val id = UUID.randomUUID()
    val now = Instant.now()
    val verified = n.email.filter(_ => n.emailVerified)
    tx(
      sql"select exists(select 1 from users where lower(username) = lower(${n.username}))".query[Boolean].unique.flatMap {
        case true => fail(AppError(ErrorCode.UsernameTaken, s"ユーザー名「${n.username}」は使われています"))
        case false =>
          sql"""insert into users (id, username, email, email_verified, verified_email, name, given_name, family_name, password_hash, password_changed_at,
                  must_change_password, is_admin, is_service, attributes, source, external_id, picture_url)
                values ($id, ${n.username}, ${n.email}, ${n.emailVerified}, $verified, ${n.name}, ${n.givenName}, ${n.familyName}, ${n.passwordHash},
                  ${n.passwordHash.map(_ =>
              now
            )}, ${n.mustChangePassword}, ${n.isAdmin}, ${n.isService}, ${n.attributes}, ${n.source},
                  ${n.externalId}, ${n.pictureUrl})""".update.run *>
            n.passwordHash.traverse_(h =>
              sql"insert into password_history (user_id, hash) values ($id, $h)".update.run
            ) *>
            releaseVerifiedEmail(id, verified) *>
            findC(id).map(_.toRight(AppError(ErrorCode.UserNotFound)))
      }
    )
  }

  /** プロフィール・権限など、パスワード以外の項目を保存する. */
  def save(user: User): IO[Either[AppError, User]] = {
    // 確認済みの値は、email・emailVerified と食い違わないように必ず整えてから保存する
    val u = user.normalizedEmail
    tx(
      sql"select exists(select 1 from users where lower(username) = lower(${u.username}) and id <> ${u.id})".query[
        Boolean
      ].unique.flatMap {
        case true => fail(AppError(ErrorCode.UsernameTaken, s"ユーザー名「${u.username}」は使われています"))
        case false =>
          sql"""update users set username = ${u.username}, email = ${u.email}, email_verified = ${u.emailVerified},
                verified_email = ${u.verifiedEmail}, name = ${u.name},
                given_name = ${u.givenName}, family_name = ${u.familyName}, must_change_password = ${u.mustChangePassword},
                is_admin = ${u.isAdmin}, disabled = ${u.disabled}, attributes = ${u.attributes}, picture_url = ${u.pictureUrl},
                source = ${u.source}, external_id = ${u.externalId}, locale = ${u.locale}, zoneinfo = ${u.zoneinfo},
                phone_number = ${u.phoneNumber}, updated_at = now()
              where id = ${u.id}""".update.run *>
            releaseVerifiedEmail(u.id, u.verifiedEmail.filter(_ => u.emailVerified)) *>
            findC(u.id).map(_.toRight(AppError(ErrorCode.UserNotFound)))
      }
    )
  }

  /**
   * あるユーザーがアドレスを確認済みにしたら、そのアドレスを「以前の確認済みの値」として持っているだけの
   * ほかのユーザー（別のアドレスに変えて確認待ちの人）からは外す. 手放したアドレスを名乗り続けさせない.
   */
  private def releaseVerifiedEmail(owner: UUID, verified: Option[String]): ConnectionIO[Unit] =
    verified.traverse_(e =>
      sql"""update users set verified_email = null, updated_at = now()
            where id <> $owner and not email_verified and lower(verified_email) = lower($e)""".update.run
    )

  def delete(id: UUID): IO[Boolean] = tx(sql"delete from users where id = $id".update.run.map(_ > 0))

  // ------------------------------------------------------------------ パスワード

  /** パスワードを変える（履歴に残し、keep 件より古い履歴は消す）. */
  def setPassword(id: UUID, hash: Option[String], mustChange: Boolean, keep: Int): IO[Unit] = tx(
    sql"""update users set password_hash = $hash, password_changed_at = now(), must_change_password = $mustChange,
            failed_attempts = 0, locked_until = null, updated_at = now() where id = $id""".update.run *>
      hash.traverse_(h => sql"insert into password_history (user_id, hash) values ($id, $h)".update.run) *>
      sql"""delete from password_history where user_id = $id and ctid not in
            (select ctid from password_history where user_id = $id order by created_at desc limit ${math.max(
          keep,
          1
        )})""".update.run.void
  )

  def passwordHistory(id: UUID, n: Int): IO[List[String]] =
    tx(sql"select hash from password_history where user_id = $id order by created_at desc limit $n".query[
      String
    ].to[List])

  // ------------------------------------------------------------------ ロック

  /** 失敗を数える. max 回に達したら until までロックする（until が None なら管理者が解除するまで = 遠い未来）. 新しい失敗回数とロックの期限. */
  def recordFailure(id: UUID, max: Int, until: Instant): IO[(Int, Option[Instant])] = tx(
    sql"""update users set failed_attempts = failed_attempts + 1,
            locked_until = case when $max > 0 and failed_attempts + 1 >= $max then $until else locked_until end
          where id = $id returning failed_attempts, locked_until""".query[(Int, Option[Instant])].unique
  )

  def unlock(id: UUID): IO[Unit] = tx(
    sql"update users set failed_attempts = 0, locked_until = null, updated_at = now() where id = $id".update.run.void
  )

  def touchLogin(id: UUID): IO[Unit] =
    tx(sql"update users set last_login_at = now(), failed_attempts = 0 where id = $id".update.run.void)

  // ------------------------------------------------------------------ アイコン

  def avatar(id: UUID): IO[Option[(Array[Byte], String)]] =
    tx(sql"select avatar, avatar_type from users where id = $id and avatar is not null".query[(
      Array[Byte],
      String
    )].option)

  def setAvatar(id: UUID, data: Option[(Array[Byte], String)]): IO[Unit] = tx(
    sql"""update users set avatar = ${data.map(_._1)}, avatar_type = ${data.map(_._2)},
            avatar_updated_at = ${data.map(_ => Instant.now())}, updated_at = now() where id = $id""".update.run.void
  )

  // ------------------------------------------------------------------ 属性の定義

  def attributeDefs: IO[List[AttributeDef]] =
    tx(sql"select key, label, kind, description, user_editable, required, scim_path, sort from attribute_defs order by sort, key".query[
      AttributeDef
    ].to[List])

  def putAttributeDef(d: AttributeDef): IO[Unit] = tx(
    sql"""insert into attribute_defs (key, label, kind, description, user_editable, required, scim_path, sort)
          values (${d.key}, ${d.label}, ${d.kind}, ${d.description}, ${d.userEditable}, ${d.required}, ${d.scimPath}, ${d.sort})
          on conflict (key) do update set label = excluded.label, kind = excluded.kind, description = excluded.description,
            user_editable = excluded.user_editable, required = excluded.required, scim_path = excluded.scim_path, sort = excluded.sort""".update.run.void
  )

  def deleteAttributeDef(key: String): IO[Boolean] =
    tx(sql"delete from attribute_defs where key = $key".update.run.map(_ > 0))
}
