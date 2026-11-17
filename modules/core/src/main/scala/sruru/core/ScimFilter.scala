package sruru.core

import io.circe.Json

/**
 * SCIM 2.0 のフィルター（RFC 7644 3.4.2.2）と PATCH のパス.
 * 属性名は大文字小文字を区別しない. 文字列の比較も区別しない（caseExact の属性はほぼ使われないため）.
 */
object ScimFilter:

  enum Filter:
    case And(a: Filter, b: Filter)
    case Or(a: Filter, b: Filter)
    case Not(f: Filter)
    case Present(path: AttrPath)
    case Compare(path: AttrPath, op: String, value: Json)
    case ValuePath(path: AttrPath, f: Filter)

  /** urn は拡張スキーマ（urn:ietf:params:scim:schemas:extension:enterprise:2.0:User など）. */
  final case class AttrPath(urn: Option[String], attr: String, sub: Option[String])

  /** PATCH のパス: emails[type eq "work"].value, members[value eq "…"], name.givenName */
  final case class PatchPath(attr: AttrPath, filter: Option[Filter], subAttr: Option[String])

  // ------------------------------------------------------------------ 字句

  private enum Tok:
    case Word(s: String)
    case Str(s: String)
    case LParen, RParen, LBracket, RBracket

  private def lex(s: String): Either[String, List[Tok]] =
    val out = List.newBuilder[Tok]
    var i = 0
    while i < s.length do
      val c = s(i)
      if c.isWhitespace then i += 1
      else if c == '(' then { out += Tok.LParen; i += 1 }
      else if c == ')' then { out += Tok.RParen; i += 1 }
      else if c == '[' then { out += Tok.LBracket; i += 1 }
      else if c == ']' then { out += Tok.RBracket; i += 1 }
      else if c == '"' then
        val sb = new StringBuilder
        i += 1
        var closed = false
        while i < s.length && !closed do
          s(i) match
            case '\\' if i + 1 < s.length =>
              s(i + 1) match
                case 'n' => sb += '\n'
                case 't' => sb += '\t'
                case 'u' if i + 5 < s.length =>
                  scala.util.Try(Integer.parseInt(s.substring(i + 2, i + 6), 16)).toOption match
                    case Some(n) => sb += n.toChar; i += 4
                    case None    => return Left("\\u の後ろは16進数の4桁にしてください")
                case x   => sb += x
              i += 2
            case '"' => closed = true; i += 1
            case x   => sb += x; i += 1
        if !closed then return Left("文字列が閉じていません")
        out += Tok.Str(sb.toString)
      else
        val start = i
        while i < s.length && !s(i).isWhitespace && !"()[]\"".contains(s(i)) do i += 1
        out += Tok.Word(s.substring(start, i))
    Right(out.result())

  // ------------------------------------------------------------------ 構文

  private val CompareOps = Set("eq", "ne", "co", "sw", "ew", "gt", "lt", "ge", "le")

  def parseAttrPath(s: String): Either[String, AttrPath] =
    val (urn, rest) =
      if s.toLowerCase.startsWith("urn:") then
        val idx = s.lastIndexOf(':')
        (Some(s.substring(0, idx)), s.substring(idx + 1))
      else (None, s)
    rest.split('.').toList match
      case a :: Nil if a.nonEmpty               => Right(AttrPath(urn, a, None))
      case a :: b :: Nil if a.nonEmpty && b.nonEmpty => Right(AttrPath(urn, a, Some(b)))
      case _                                    => Left(s"属性のパスが不正です: $s")

  private final class Parser(var toks: List[Tok]):
    def peekWord: Option[String] = toks.headOption.collect { case Tok.Word(w) => w.toLowerCase }

    def orExpr(): Either[String, Filter] =
      andExpr().flatMap { first =>
        var acc: Either[String, Filter] = Right(first)
        while acc.isRight && peekWord.contains("or") do
          toks = toks.tail
          acc = for a <- acc; b <- andExpr() yield Filter.Or(a, b)
        acc
      }

    def andExpr(): Either[String, Filter] =
      notExpr().flatMap { first =>
        var acc: Either[String, Filter] = Right(first)
        while acc.isRight && peekWord.contains("and") do
          toks = toks.tail
          acc = for a <- acc; b <- notExpr() yield Filter.And(a, b)
        acc
      }

    def notExpr(): Either[String, Filter] =
      if peekWord.contains("not") then
        toks = toks.tail
        toks match
          case Tok.LParen :: rest =>
            toks = rest
            for f <- orExpr(); _ <- expect(Tok.RParen) yield Filter.Not(f)
          case _ => Left("not の後には ( が必要です")
      else atom()

    def expect(t: Tok): Either[String, Unit] = toks match
      case `t` :: rest => toks = rest; Right(())
      case _           => Left(s"$t が必要です")

    def value(): Either[String, Json] = toks match
      case Tok.Str(s) :: rest => toks = rest; Right(Json.fromString(s))
      case Tok.Word(w) :: rest =>
        toks = rest
        w.toLowerCase match
          case "true"  => Right(Json.True)
          case "false" => Right(Json.False)
          case "null"  => Right(Json.Null)
          case _ => w.toLongOption.map(Json.fromLong).orElse(w.toDoubleOption.flatMap(Json.fromDouble)).toRight(s"値が不正です: $w")
      case _ => Left("値が必要です")

    def atom(): Either[String, Filter] = toks match
      case Tok.LParen :: rest =>
        toks = rest
        for f <- orExpr(); _ <- expect(Tok.RParen) yield f
      case Tok.Word(w) :: rest =>
        toks = rest
        parseAttrPath(w).flatMap { path =>
          toks match
            case Tok.LBracket :: r2 =>
              toks = r2
              for f <- orExpr(); _ <- expect(Tok.RBracket) yield Filter.ValuePath(path, f)
            case Tok.Word(op) :: r2 if op.equalsIgnoreCase("pr") => toks = r2; Right(Filter.Present(path))
            case Tok.Word(op) :: r2 if CompareOps(op.toLowerCase) =>
              toks = r2
              value().map(v => Filter.Compare(path, op.toLowerCase, v))
            case _ => Left(s"$w の後に比較（eq・co・sw・pr など）が必要です")
        }
      case _ => Left("フィルターが不正です")

  /** 入力の長さとかっこの深さの上限（再帰で解析するので、深いかっこでスタックを使い切らせない）. */
  val MaxLength = 4096
  val MaxDepth  = 32

  private def bounded(s: String): Either[String, List[Tok]] =
    if s.length > MaxLength then Left(s"フィルターが長すぎます（$MaxLength 文字まで）")
    else lex(s).flatMap { ts =>
      val depth = ts.scanLeft(0)((d, t) => t match
        case Tok.LParen | Tok.LBracket => d + 1
        case Tok.RParen | Tok.RBracket => d - 1
        case _                         => d).max
      Either.cond(depth <= MaxDepth, ts, s"かっこが深すぎます（$MaxDepth 段まで）")
    }

  def parse(s: String): Either[String, Filter] =
    bounded(s).flatMap { ts =>
      val p = new Parser(ts)
      p.orExpr().flatMap(f => if p.toks.isEmpty then Right(f) else Left("フィルターの後ろに余分な文字があります"))
    }

  /** PATCH のパス. */
  def parsePatchPath(s: String): Either[String, PatchPath] =
    val lb = s.indexOf('[')
    if lb < 0 then parseAttrPath(s).map(PatchPath(_, None, None))
    else
      val rb = s.lastIndexOf(']')
      if rb < lb then Left(s"パスが不正です: $s")
      else
        val sub = s.substring(rb + 1).stripPrefix(".")
        for
          a <- parseAttrPath(s.substring(0, lb))
          f <- parse(s.substring(lb + 1, rb))
        yield PatchPath(a, Some(f), Option(sub).filter(_.nonEmpty))

  // ------------------------------------------------------------------ 評価

  private def field(obj: Json, name: String): Json =
    obj.asObject.flatMap(o => o.toIterable.find(_._1.equalsIgnoreCase(name)).map(_._2)).getOrElse(Json.Null)

  /** パスの値（複数値の属性は配列を展開した一覧）. */
  def resolve(res: Json, p: AttrPath): List[Json] =
    val base = p.urn.fold(res)(u => field(res, u))
    val top  = field(base, p.attr)
    val items = top.asArray.map(_.toList).getOrElse(if top.isNull then Nil else List(top))
    p.sub match
      case None    => items
      case Some(s) => items.flatMap(i => field(i, s) match { case j if j.isNull => Nil; case j => j.asArray.map(_.toList).getOrElse(List(j)) })

  private def cmp(a: Json, op: String, v: Json): Boolean =
    (a.asString, v.asString) match
      case (Some(x), Some(y)) =>
        val (l, r) = (x.toLowerCase, y.toLowerCase)
        op match
          case "eq" => l == r
          case "ne" => l != r
          case "co" => l.contains(r)
          case "sw" => l.startsWith(r)
          case "ew" => l.endsWith(r)
          case "gt" => l > r
          case "lt" => l < r
          case "ge" => l >= r
          case "le" => l <= r
          case _    => false
      case _ =>
        (a.asNumber.map(_.toDouble), v.asNumber.map(_.toDouble)) match
          case (Some(x), Some(y)) =>
            op match
              case "eq" => x == y
              case "ne" => x != y
              case "gt" => x > y
              case "lt" => x < y
              case "ge" => x >= y
              case "le" => x <= y
              case _    => false
          case _ =>
            op match
              case "eq" => a == v
              case "ne" => a != v
              case _    => false

  def matches(f: Filter, res: Json): Boolean = f match
    case Filter.And(a, b)  => matches(a, res) && matches(b, res)
    case Filter.Or(a, b)   => matches(a, res) || matches(b, res)
    case Filter.Not(x)     => !matches(x, res)
    case Filter.Present(p) => resolve(res, p).exists(j => !Expr.isEmpty(j))
    case Filter.Compare(p, op, v) =>
      val vs = resolve(res, p)
      if op == "ne" then vs.isEmpty && !v.isNull || vs.forall(cmp(_, "ne", v))
      else if v.isNull && op == "eq" then vs.isEmpty
      else vs.exists(cmp(_, op, v))
    case Filter.ValuePath(p, sub) =>
      val top = field(p.urn.fold(res)(u => field(res, u)), p.attr)
      top.asArray.map(_.toList).getOrElse(if top.isNull then Nil else List(top)).exists(matches(sub, _))

  /** `attr eq "値"` の形なら (属性, 値)（DB で絞り込むため）. */
  def simpleEq(f: Filter): Option[(String, String)] = f match
    case Filter.Compare(AttrPath(None, a, sub), "eq", v) if v.isString => Some((a + sub.fold("")("." + _)).toLowerCase -> v.asString.get)
    case _ => None
