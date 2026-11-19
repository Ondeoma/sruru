package sruru.api

import io.circe.{Json, JsonObject}
import sruru.core.*
import sruru.core.ScimFilter.{Filter, PatchPath}

/** SCIM の JSON の操作（PATCH の適用）. 属性名は大文字小文字を区別しない. */
object ScimJson {

  private def key(
    o: JsonObject,
    name: String
  ): String = o.keys.find(_.equalsIgnoreCase(name)).getOrElse(name)

  def get(
    j: Json,
    name: String
  ): Json = j.asObject.flatMap(o => o(key(o, name))).getOrElse(Json.Null)

  def set(
    j: Json,
    name: String,
    v: Json
  ): Json = j.mapObject(o => o.add(key(o, name), v))

  def remove(
    j: Json,
    name: String
  ): Json = j.mapObject(o => o.remove(key(o, name)))

  /** 複数値の属性に要素を加える（同じ value の要素は置き換える）. */
  private def addValues(
    cur: Json,
    v: Json
  ): Json = {
    val items = v.asArray.map(_.toList).getOrElse(List(v))
    val base = cur.asArray.map(_.toList).getOrElse(if cur.isNull then Nil else List(cur))
    val merged = items.foldLeft(base) {
      (
        acc,
        it
      ) =>
        val idv = get(it, "value")
        if !idv.isNull && acc.exists(x => get(x, "value") == idv) then
          acc.map(x => if get(x, "value") == idv then x.deepMerge(it) else x)
        else acc :+ it
    }
    Json.fromValues(merged)
  }

  /** eq だけの条件から新しい要素の値を作る（emails[type eq "work"].value の追加）. */
  private def seed(
    f: Filter
  ): Json = f match {
    case Filter.Compare(p, "eq", v) => Json.obj(p.attr -> v)
    case Filter.And(a, b) => seed(a).deepMerge(seed(b))
    case _ => Json.obj()
  }

  def applyOp(
    res: Json,
    op: String,
    path: Option[String],
    value: Json
  ): Either[String, Json] =
    path.filter(_.trim.nonEmpty) match {
      case None =>
        // パスなし: 値のオブジェクトの各キーをパスとして扱う（Entra は "name.givenName" のようなキーを送る）
        value.asObject.toRight("value はオブジェクトにしてください").flatMap(_.toList.foldLeft[Either[String, Json]](Right(res)) {
          case (acc, (k, v)) =>
            acc.flatMap { r =>
              if k.toLowerCase.startsWith("urn:") && v.isObject && (k.endsWith(":User") || k.endsWith(":Group")) then
                Right(set(r, k, (if get(r, k).isObject then get(r, k) else Json.obj()).deepMerge(v)))
              else applyOp(r, op, Some(k), v)
            }
        })
      case Some(p) =>
        ScimFilter.parsePatchPath(p.trim).map { pp =>
          val container = pp.attr.urn.fold(res)(u => get(res, u))
          val updated = applyAt(container, op, pp, value)
          pp.attr.urn.fold(updated)(u => set(res, u, updated))
        }
    }

  private def applyAt(
    obj: Json,
    op: String,
    pp: PatchPath,
    value: Json
  ): Json = {
    val attr = pp.attr.attr
    val cur = get(obj, attr)
    (pp.filter, pp.attr.sub.orElse(pp.subAttr)) match {
      case (None, None) =>
        op match {
          case "remove" => remove(obj, attr)
          case "add" if cur.isArray || value.isArray => set(obj, attr, addValues(cur, value))
          case "add" if cur.isObject && value.isObject => set(obj, attr, cur.deepMerge(value))
          case _ => set(obj, attr, value)
        }
      case (None, Some(sub)) =>
        if cur.isArray then {
          // 複数値の属性の副属性: 主の要素（なければ最初の要素）に適用する
          val arr = cur.asArray.get.toList
          val idx = arr.indexWhere(x => get(x, "primary").asBoolean.contains(true)) match { case -1 => 0; case i => i }
          val next = if arr.isEmpty then List(if op == "remove" then Json.obj() else Json.obj(sub -> value))
          else
            arr.zipWithIndex.map(
              (
                x,
                i
              ) => if i == idx then (if op == "remove" then remove(x, sub) else set(x, sub, value)) else x
            )
          set(obj, attr, Json.fromValues(next))
        } else {
          val base = if cur.isObject then cur else Json.obj()
          set(obj, attr, if op == "remove" then remove(base, sub) else set(base, sub, value))
        }
      case (Some(f), sub) =>
        val arr = cur.asArray.map(_.toList).getOrElse(Nil)
        val hit = arr.exists(ScimFilter.matches(f, _))
        val next =
          if op == "remove" then
            sub.fold(arr.filterNot(ScimFilter.matches(f, _)))(s =>
              arr.map(x => if ScimFilter.matches(f, x) then remove(x, s) else x)
            )
          else if !hit then arr :+ sub.fold(seed(f).deepMerge(value))(s => set(seed(f), s, value))
          else arr.map(x => if ScimFilter.matches(f, x) then sub.fold(x.deepMerge(value))(s => set(x, s, value)) else x)
        set(obj, attr, Json.fromValues(next))
    }
  }
}
