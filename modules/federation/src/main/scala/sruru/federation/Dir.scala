package sruru.federation

import io.circe.{HCursor, Json}

private[federation] object Dir {
  val Parallelism = 4

  def str(
    c: HCursor,
    k: String
  ): Option[String] = c.get[String](k).toOption.filter(_.nonEmpty)

  def list(
    j: Json,
    k: String
  ): List[Json] = j.hcursor.get[List[Json]](k).getOrElse(Nil)

  /** 属性（値のないものは除く）. */
  def attrs(
    kv: (String, Option[Json])*
  ): Json = Json.fromFields(kv.collect { case (k, Some(v)) => k -> v })

  /** 所属がわかっている利用者だけ・重複なし. */
  def members(
    ids: List[String],
    known: Set[String]
  ): List[String] = ids.filter(known.contains).distinct
}
