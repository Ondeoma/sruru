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
final class SettingsStore(xa: Transactor[IO]) extends TxStore(xa) {
  import Codecs.given

  def get(key: String): IO[Option[Json]] = tx(sql"select value from settings where key = $key".query[Json].option)

  def getAs[A: Decoder](key: String, default: => A): IO[A] =
    get(key).map(_.flatMap(_.as[A].toOption).getOrElse(default))

  def put[A: Encoder](key: String, value: A): IO[Unit] = tx(
    sql"""insert into settings (key, value) values ($key, ${value.asJson}) on conflict (key) do update set value = excluded.value, updated_at = now()"""
      .update.run.void
  )

  def delete(key: String): IO[Unit] = tx(sql"delete from settings where key = $key".update.run.void)

  // ------------------------------------------------------------------ ロゴ

  def addLogo(data: Array[Byte], contentType: String): IO[UUID] = {
    val id = UUID.randomUUID()
    tx(sql"insert into brand_logos (id, data, content_type) values ($id, $data, $contentType)".update.run).as(id)
  }

  def logo(id: UUID): IO[Option[(Array[Byte], String)]] =
    tx(sql"select data, content_type from brand_logos where id = $id".query[(Array[Byte], String)].option)

  /** 使われていないロゴを消す（before より前に作ったもの. 作ったばかりで保存前のものは残す）. */
  def purgeLogos(inUse: Set[UUID], before: Instant): IO[Int] =
    tx(sql"delete from brand_logos where created_at < $before and not (id = any(${inUse.toArray}))".update.run)

  /** まだなければ入れる. 入れたら true（複数ノードで1回だけの初期化）. */
  def putIfAbsent(key: String, value: Json): IO[Boolean] =
    tx(sql"insert into settings (key, value) values ($key, $value) on conflict do nothing".update.run.map(_ > 0))
}
