package sruru.api

import cats.syntax.all.*
import io.circe.Json
import sruru.core.*

/** 属性の値を定義に合わせて確かめる. */
object Attrs {
  def validate(defs: List[AttributeDef], attrs: Json, onlyEditable: Boolean, previous: Json): Either[String, Json] = {
    val obj = attrs.asObject.getOrElse(io.circe.JsonObject.empty)
    val byKey = defs.map(d => d.key -> d).toMap
    val checked = obj.toList.traverse {
      (k, v) =>
        byKey.get(k) match {
          case None => Left(s"属性「$k」は定義されていません")
          case Some(d) if onlyEditable && !d.userEditable => Left(s"属性「${d.label}」は変更できません")
          case Some(d) =>
            val ok = v.isNull ||
              (d.kind match {
                case "number" => v.isNumber
                case "boolean" => v.isBoolean
                case "list" => v.asArray.exists(_.forall(_.isString))
                case "date" => v.asString.exists(s => scala.util.Try(java.time.LocalDate.parse(s)).isSuccess)
                case _ => v.isString
              })
            Either.cond(ok, k -> v, s"属性「${d.label}」の値の形式が正しくありません")
        }
    }
    checked.flatMap { kvs =>
      // 変更できない属性は前の値を残す
      val merged = if onlyEditable then previous.deepMerge(Json.fromFields(kvs)) else Json.fromFields(kvs)
      val missing = defs.filter(d =>
        d.required && merged.hcursor.downField(d.key).focus.forall(j => j.isNull || j.asString.exists(_.isEmpty))
      )
      if missing.nonEmpty && !onlyEditable then Left(s"属性「${missing.head.label}」は必須です")
      else Right(merged.dropNullValues)
    }
  }
}
