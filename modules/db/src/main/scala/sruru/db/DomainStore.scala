package sruru.db

import sbirds.db.*
import cats.effect.*
import doobie.*
import doobie.implicits.*
import doobie.postgres.implicits.*
import sruru.core.Domain
import sruru.shared.DomainPolicy

import java.util.UUID

/** ドメイン（sruru にアクセスするホスト名）と、そのポリシーの上書き. */
final class DomainStore(xa: Transactor[IO]) extends TxStore(xa) {
  import Codecs.given

  private val cols = fr"id, host, note, policy, created_at, updated_at"

  def all: IO[List[Domain]] = tx((fr"select" ++ cols ++ fr"from domains order by host").query[Domain].to[List])

  def find(id: UUID): IO[Option[Domain]] =
    tx((fr"select" ++ cols ++ fr"from domains where id = $id").query[Domain].option)

  /** 追加する. 同じホスト名がすでにあれば None. */
  def create(host: String, note: String, policy: DomainPolicy): IO[Option[Domain]] =
    tx((fr"insert into domains (id, host, note, policy) values (${UUID.randomUUID()}, $host, $note, $policy)" ++
      fr"on conflict (host) do nothing returning" ++ cols).query[Domain].option)

  /** 説明とポリシーを変える（ホスト名は変えられない. セッション・トークンがホスト名に結び付いているため）. */
  def update(id: UUID, note: String, policy: DomainPolicy): IO[Option[Domain]] =
    tx((fr"update domains set note = $note, policy = $policy, updated_at = now() where id = $id returning" ++
      cols).query[
      Domain
    ].option)

  def delete(id: UUID): IO[Option[Domain]] =
    tx((fr"delete from domains where id = $id returning" ++ cols).query[Domain].option)
}
