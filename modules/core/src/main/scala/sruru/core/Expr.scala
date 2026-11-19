package sruru.core

import io.circe.Json

/**
 * クレーム・SAML 属性・NameID の値を作る式（カスタム属性の対応付け）.
 *
 *  - `{{ user.attributes.department }}` だけなら、その値（文字列・数値・真偽値・リスト）をそのまま返す
 *  - `{{ user.family_name }} {{ user.given_name }}` のように文字と混ぜると文字列になる（リストは , でつなぐ）
 *  - フィルター: `{{ user.groups | filter_prefix:"app-" | strip_prefix:"app-" }}`
 *    lower・upper・trim・default:"値"・join:","・split:","・first・last・filter_prefix:"p"・strip_prefix:"p"・
 *    replace:"a":"b"・prepend:"p"・append:"s"・unique・email_local・email_domain・string・bool
 *  - `"文字列"` は文字そのもの
 */
object Expr {

  final case class Pipeline(head: Term, filters: List[(String, List[String])])
  enum Term {
    case Path(
      segments: List[String])
    case Lit(
      value: String)
  }

  enum Part {
    case Text(
      s: String)
    case Code(
      p: Pipeline)
  }

  private val Known = Set(
    "lower",
    "upper",
    "trim",
    "default",
    "join",
    "split",
    "first",
    "last",
    "filter_prefix",
    "strip_prefix",
    "replace",
    "prepend",
    "append",
    "unique",
    "email_local",
    "email_domain",
    "string",
    "bool"
  )

  // ------------------------------------------------------------------ 解析

  def parse(src: String): Either[String, List[Part]] = {
    val out = List.newBuilder[Part]
    var i = 0
    var err: Option[String] = None
    while i < src.length && err.isEmpty do {
      val open = src.indexOf("{{", i)
      if open < 0 then { out += Part.Text(src.substring(i)); i = src.length }
      else {
        if open > i then out += Part.Text(src.substring(i, open))
        val close = findClose(src, open + 2)
        if close < 0 then { err = Some("{{ に対応する }} がありません"); i = src.length }
        else {
          parsePipeline(src.substring(open + 2, close)) match {
            case Right(p) => out += Part.Code(p)
            case Left(e) => err = Some(e)
          }
          i = close + 2
        }
      }
    }
    err.toLeft(out.result())
  }

  /** 引用符の中の }} は閉じとみなさない. */
  private def findClose(s: String, from: Int): Int = {
    var i = from
    var q = false
    while i < s.length - 1 do {
      val c = s(i)
      if c == '"' then q = !q
      else if c == '\\' && q then i += 1
      else if !q && c == '}' && s(i + 1) == '}' then return i
      i += 1
    }
    -1
  }

  /** | と : で区切る（引用符の中は区切らない）. */
  private def split(s: String, sep: Char): List[String] = {
    val out = List.newBuilder[String]
    val cur = new StringBuilder
    var q = false
    var i = 0
    while i < s.length do {
      val c = s(i)
      if c == '"' then { q = !q; cur += c }
      else if c == '\\' && q && i + 1 < s.length then { cur += c; cur += s(i + 1); i += 1 }
      else if c == sep && !q then { out += cur.toString; cur.clear() }
      else cur += c
      i += 1
    }
    out += cur.toString
    out.result()
  }

  private def unquote(s: String): Either[String, String] = {
    val t = s.trim
    if t.length >= 2 && t.head == '"' && t.last == '"' then
      Right(t.substring(1, t.length - 1).replace("\\\"", "\"").replace("\\\\", "\\"))
    else Left(s"引数は \"...\" で囲んでください: $t")
  }

  private def parsePipeline(s: String): Either[String, Pipeline] =
    split(s, '|').map(_.trim) match {
      case Nil => Left("式が空です")
      case h :: fs =>
        val head =
          if h.startsWith("\"") then unquote(h).map(Term.Lit(_))
          else if h.nonEmpty && h.forall(c => c.isLetterOrDigit || c == '_' || c == '.' || c == '-' || c == ':') then
            Right(Term.Path(h.split('.').toList))
          else Left(s"値の指定が不正です: $h")
        val filters = fs.foldRight[Either[String, List[(String, List[String])]]](Right(Nil)) {
          (f, acc) =>
            acc.flatMap { l =>
              split(f, ':').map(_.trim) match {
                case name :: args if Known(name) =>
                  args.foldRight[Either[String, List[String]]](Right(Nil))((a, r) =>
                    r.flatMap(rs => unquote(a).map(_ :: rs))
                  ).map(as => (name, as) :: l)
                case name :: _ => Left(s"不明なフィルターです: $name")
                case Nil => Left("フィルターが空です")
              }
            }
        }
        for h2 <- head; f2 <- filters yield Pipeline(h2, f2)
    }

  def validate(src: String): Either[String, Unit] = parse(src).map(_ => ())

  // ------------------------------------------------------------------ 評価

  /** ctx の中のパス（キーの大文字小文字は区別する）. */
  def lookup(ctx: Json, path: List[String]): Json =
    path.foldLeft(ctx)((j, k) => j.asObject.flatMap(_(k)).getOrElse(Json.Null))

  def render(j: Json): String =
    j.fold(
      "",
      _.toString,
      n => n.toLong.map(_.toString).getOrElse(n.toString),
      identity,
      _.map(render).filter(_.nonEmpty).mkString(","),
      _ => j.noSpaces
    )

  private def strs(j: Json): List[String] =
    j.asArray.map(_.toList.map(render)).getOrElse(if j.isNull then Nil else List(render(j)))

  private def mapStr(j: Json)(f: String => String): Json =
    j.asArray match {
      case Some(a) => Json.fromValues(a.map(x => Json.fromString(f(render(x)))))
      case None => if j.isNull then j else Json.fromString(f(render(j)))
    }

  private def apply(j: Json, name: String, args: List[String]): Json = {
    def arg(i: Int) = args.lift(i).getOrElse("")
    name match {
      case "lower" => mapStr(j)(_.toLowerCase)
      case "upper" => mapStr(j)(_.toUpperCase)
      case "trim" => mapStr(j)(_.trim)
      case "default" => if j.isNull || render(j).isEmpty then Json.fromString(arg(0)) else j
      case "join" => Json.fromString(strs(j).mkString(args.headOption.getOrElse(",")))
      case "split" => if j.isNull then j
        else
          Json.fromValues(render(j).split(
            java.util.regex.Pattern.quote(args.headOption.getOrElse(","))
          ).map(_.trim).filter(_.nonEmpty).map(Json.fromString))
      case "first" => j.asArray.map(_.headOption.getOrElse(Json.Null)).getOrElse(j)
      case "last" => j.asArray.map(_.lastOption.getOrElse(Json.Null)).getOrElse(j)
      case "filter_prefix" => Json.fromValues(strs(j).filter(_.startsWith(arg(0))).map(Json.fromString))
      case "strip_prefix" => mapStr(j)(s => s.stripPrefix(arg(0)))
      case "replace" => mapStr(j)(_.replace(arg(0), arg(1)))
      case "prepend" => mapStr(j)(arg(0) + _)
      case "append" => mapStr(j)(_ + arg(0))
      case "unique" => j.asArray.map(a => Json.fromValues(a.distinct)).getOrElse(j)
      case "email_local" => mapStr(j)(s => s.takeWhile(_ != '@'))
      case "email_domain" => mapStr(j)(s => s.dropWhile(_ != '@').drop(1))
      case "string" => if j.isNull then j else Json.fromString(render(j))
      case "bool" =>
        Json.fromBoolean(j.asBoolean.getOrElse(Set("true", "1", "yes").contains(render(j).trim.toLowerCase)))
      case _ => j
    }
  }

  def evalPipeline(p: Pipeline, ctx: Json): Json = {
    val start = p.head match {
      case Term.Path(seg) => lookup(ctx, seg)
      case Term.Lit(s) => Json.fromString(s)
    }
    p.filters.foldLeft(start)((j, f) => apply(j, f._1, f._2))
  }

  /** 式を評価する. 式1つだけならその値、文字と混ざれば文字列. 解析できない式は null. */
  def eval(src: String, ctx: Json): Json =
    parse(src) match {
      case Left(_) => Json.Null
      case Right(List(Part.Code(p))) => evalPipeline(p, ctx)
      case Right(parts) =>
        Json.fromString(parts.map {
          case Part.Text(s) => s
          case Part.Code(p) => render(evalPipeline(p, ctx))
        }.mkString)
    }

  /** 値が「ない」（null・空文字・空のリスト）. */
  def isEmpty(j: Json): Boolean = j.isNull || j.asString.exists(_.isEmpty) || j.asArray.exists(_.isEmpty)
}
