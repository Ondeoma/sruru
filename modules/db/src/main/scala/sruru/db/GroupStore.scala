package sruru.db

import cats.effect.*
import cats.syntax.all.*
import doobie.*
import doobie.implicits.*
import doobie.postgres.implicits.*
import io.circe.Json
import sruru.core.*

import java.time.Instant
import java.util.UUID

final case class NewGroup(name: String, description: String = "", parentId: Option[UUID] = None, attributes: Json = Json.obj(),
    isAdmin: Boolean = false, rule: Option[GroupRule] = None, source: String = "local", externalId: Option[String] = None,
    priority: Int = 0, policy: Option[sruru.shared.GroupPolicy] = None)

/** グループ・メンバー（直接・動的）. */
final class GroupStore(xa: Transactor[IO]) extends TxStore(xa):
  import Codecs.given

  private val cols = fr"g.id, g.name, g.description, g.parent_id, g.attributes, g.is_admin, g.rule, g.source, g.external_id, g.created_at, g.updated_at, " ++
    fr"g.priority, g.policy"
  private def select(where: Fragment): Query0[Group] = (fr"select" ++ cols ++ fr"from groups g" ++ where).query[Group]

  // グループの一覧の控え（所属の計算でリクエストごとに読むため. 5秒で読み直し、このノードでの変更ではすぐ捨てる）
  @volatile private var cached: Option[(Long, List[Group])] = None
  private def invalidate[A](io: IO[A]): IO[A] = io.flatTap(_ => IO { cached = None })

  def all: IO[List[Group]] =
    IO.monotonic.flatMap { now =>
      cached match
        case Some((at, gs)) if now.toMillis - at < 5000 => IO.pure(gs)
        case _ => tx(select(fr"order by lower(g.name)").to[List]).flatTap(gs => IO { cached = Some(now.toMillis -> gs) })
    }
  def find(id: UUID): IO[Option[Group]] = tx(select(fr"where g.id = $id").option)
  def byName(name: String): IO[Option[Group]] = tx(select(fr"where lower(g.name) = lower($name)").option)
  def byExternal(source: String, ext: String): IO[Option[Group]] = tx(select(fr"where g.source = $source and g.external_id = $ext").option)
  def findMany(ids: List[UUID]): IO[List[Group]] = if ids.isEmpty then IO.pure(Nil) else tx(select(fr"where g.id = any(${ids.toArray})").to[List])

  /** 親をたどって自分に戻るなら循環. */
  private def cycles(id: UUID, parent: Option[UUID]): ConnectionIO[Boolean] = parent match
    case None => false.pure[ConnectionIO]
    case Some(p) =>
      sql"""with recursive up(id, parent_id) as (select id, parent_id from groups where id = $p
              union select g.id, g.parent_id from groups g join up on g.id = up.parent_id)
            select exists(select 1 from up where id = $id)""".query[Boolean].unique

  def create(n: NewGroup): IO[Either[StoreError, Group]] =
    val id = UUID.randomUUID()
    invalidate(tx(sql"select exists(select 1 from groups where lower(name) = lower(${n.name}))".query[Boolean].unique.flatMap {
      case true => fail(StoreError.Conflict(s"グループ「${n.name}」はすでにあります"))
      case false =>
        sql"""insert into groups (id, name, description, parent_id, attributes, is_admin, rule, source, external_id, priority, policy)
              values ($id, ${n.name}, ${n.description}, ${n.parentId}, ${n.attributes}, ${n.isAdmin}, ${n.rule}, ${n.source}, ${n.externalId},
                ${n.priority}, ${n.policy})""".update.run *>
          select(fr"where g.id = $id").unique.map(Right(_))
    }))

  def save(g: Group): IO[Either[StoreError, Group]] = invalidate(tx(
    sql"select exists(select 1 from groups where lower(name) = lower(${g.name}) and id <> ${g.id})".query[Boolean].unique.flatMap {
      case true => fail(StoreError.Conflict(s"グループ「${g.name}」はすでにあります"))
      case false =>
        cycles(g.id, g.parentId).flatMap {
          case true => fail(StoreError.Invalid("親グループが循環しています"))
          case false =>
            sql"""update groups set name = ${g.name}, description = ${g.description}, parent_id = ${g.parentId}, attributes = ${g.attributes},
                    is_admin = ${g.isAdmin}, rule = ${g.rule}, source = ${g.source}, external_id = ${g.externalId},
                    priority = ${g.priority}, policy = ${g.policy}, updated_at = now()
                  where id = ${g.id}""".update.run *> select(fr"where g.id = ${g.id}").option.map(_.toRight(StoreError.NotFound("グループ")))
        }
    }
  ))

  def delete(id: UUID): IO[Boolean] = invalidate(tx(sql"delete from groups where id = $id".update.run.map(_ > 0)))

  // ------------------------------------------------------------------ メンバー

  /** 直接のメンバー. */
  def members(groupId: UUID): IO[List[UUID]] = tx(sql"select user_id from group_members where group_id = $groupId".query[UUID].to[List])

  /** 動的なメンバー. */
  def dynamicMembers(groupId: UUID): IO[List[UUID]] = tx(sql"select user_id from group_dynamic_members where group_id = $groupId".query[UUID].to[List])

  /** 子グループを含めたメンバー（子グループのメンバーは親のメンバーでもある）. */
  def effectiveMembers(groupId: UUID): IO[List[UUID]] = tx(
    sql"""with recursive down(id) as (select $groupId union select g.id from groups g join down on g.parent_id = down.id)
          select distinct user_id from (select user_id, group_id from group_members union select user_id, group_id from group_dynamic_members) m
          where m.group_id in (select id from down)""".query[UUID].to[List]
  )

  def memberCounts: IO[Map[UUID, Int]] = tx(
    sql"""select group_id, count(distinct user_id)::int from (select group_id, user_id from group_members union all
          select group_id, user_id from group_dynamic_members) m group by group_id""".query[(UUID, Int)].to[List].map(_.toMap)
  )

  def addMember(groupId: UUID, userId: UUID): IO[Boolean] =
    tx(sql"insert into group_members (group_id, user_id) values ($groupId, $userId) on conflict do nothing".update.run.map(_ > 0))

  def removeMember(groupId: UUID, userId: UUID): IO[Boolean] =
    tx(sql"delete from group_members where group_id = $groupId and user_id = $userId".update.run.map(_ > 0))

  def setMembers(groupId: UUID, userIds: List[UUID]): IO[Unit] = tx(
    sql"delete from group_members where group_id = $groupId and not (user_id = any(${userIds.toArray}))".update.run *>
      userIds.distinct.traverse_(u => sql"insert into group_members (group_id, user_id) values ($groupId, $u) on conflict do nothing".update.run)
  )

  /** すべてのグループの手動のメンバー（グループ → ユーザー）. */
  def allMembers: IO[Map[UUID, List[UUID]]] =
    tx(sql"select group_id, user_id from group_members".query[(UUID, UUID)].to[List].map(_.groupMap(_._1)(_._2)))

  /** すべてのユーザーの手動の所属（ユーザー → グループ）. */
  def allStatic: IO[Map[UUID, List[UUID]]] =
    tx(sql"select user_id, group_id from group_members".query[(UUID, UUID)].to[List].map(_.groupMap(_._1)(_._2)))

  /** 手動で所属しているグループ（動的なものを除く）. */
  def staticGroupIds(userId: UUID): IO[List[UUID]] = tx(sql"select group_id from group_members where user_id = $userId".query[UUID].to[List])

  /** 直接（手動・動的）に所属しているグループ. */
  def directGroupIds(userId: UUID): IO[List[UUID]] = tx(
    sql"select group_id from group_members where user_id = $userId union select group_id from group_dynamic_members where user_id = $userId"
      .query[UUID].to[List]
  )

  /** 親グループを含めた所属. */
  def membership(userId: UUID): IO[Membership] =
    (directGroupIds(userId), all).mapN((ids, gs) => Membership.expand(ids, gs.map(g => g.id -> g).toMap))

  /** 複数のユーザーの所属をまとめて求める. */
  def memberships(userIds: List[UUID]): IO[Map[UUID, Membership]] =
    if userIds.isEmpty then IO.pure(Map.empty)
    else
      for
        gs   <- all
        rows <- tx(sql"""select user_id, group_id from group_members where user_id = any(${userIds.toArray})
                         union select user_id, group_id from group_dynamic_members where user_id = any(${userIds.toArray})""".query[(UUID, UUID)].to[List])
        byId = gs.map(g => g.id -> g).toMap
        grouped = rows.groupMap(_._1)(_._2)
      yield userIds.map(u => u -> Membership.expand(grouped.getOrElse(u, Nil), byId)).toMap

  /** 動的なメンバーを置き換える（ユーザー1人分. 対象はルールのあるグループ）. */
  def setDynamicForUser(userId: UUID, groupIds: List[UUID]): IO[Unit] = tx(
    sql"delete from group_dynamic_members where user_id = $userId and not (group_id = any(${groupIds.toArray}))".update.run *>
      groupIds.traverse_(g => sql"insert into group_dynamic_members (group_id, user_id) values ($g, $userId) on conflict do nothing".update.run)
  )

  /** 動的なメンバーを置き換える（グループ1つ分）. */
  def setDynamicForGroup(groupId: UUID, userIds: List[UUID]): IO[Unit] = tx(
    sql"delete from group_dynamic_members where group_id = $groupId".update.run *>
      userIds.traverse_(u => sql"insert into group_dynamic_members (group_id, user_id) values ($groupId, $u) on conflict do nothing".update.run)
  )

  def touch(id: UUID, at: Instant): IO[Unit] = tx(sql"update groups set updated_at = $at where id = $id".update.run.void)
