package sruru.db

import doobie.*

/** JSON の列と、配列の列の型. */
object Codecs {
  import io.circe.{Decoder, Encoder}
  import doobie.postgres.circe.jsonb.implicits.*
  export doobie.postgres.circe.jsonb.implicits.{jsonbGet, jsonbPut}

  def jsonGet[A: Decoder]: Get[A] = pgDecoderGetT[A]
  def jsonPut[A: Encoder]: Put[A] = pgEncoderPutT[A]

  given Get[sruru.core.GroupRule] = jsonGet
  given Put[sruru.core.GroupRule] = jsonPut
  given Get[sruru.shared.GroupPolicy] = jsonGet
  given Put[sruru.shared.GroupPolicy] = jsonPut
  given Get[sruru.shared.DomainPolicy] = jsonGet
  given Put[sruru.shared.DomainPolicy] = jsonPut
}
