package sruru.core

import io.circe.*
import io.circe.derivation.ConfiguredCodec
import sruru.shared.given

/**
 * 動的なグループのメンバーの条件. 例:
 * {{{ {"match":"all","conditions":[{"path":"user.email","op":"ends_with","value":"@example.com"},
 *                                   {"path":"user.attributes.department","op":"in","values":["営業","企画"]}]} }}}
 * op: eq・ne・contains・starts_with・ends_with・in・exists・not_exists・regex（文字列の比較は大文字小文字を区別しない）.
 * 値がリスト（user.groups など）なら、要素のどれかが条件を満たせばよい（ne・not_exists はすべての要素）.
 */
final case class GroupCondition(
  path: String,
  op: String,
  value: String = "",
  values: List[String] = Nil) derives ConfiguredCodec
final case class GroupRule(
  `match`: String = "all",
  conditions: List[GroupCondition] = Nil) derives ConfiguredCodec

object GroupRule {
  val Ops = List("eq", "ne", "contains", "starts_with", "ends_with", "in", "exists", "not_exists", "regex")

  def validate(
    r: GroupRule
  ): Either[String, GroupRule] =
    for {
      _ <- Either.cond(Set("all", "any")(r.`match`), (), "match は all か any です")
      _ <- Either.cond(r.conditions.nonEmpty, (), "条件を1つ以上指定してください")
      _ <- r.conditions.find(c => !Ops.contains(c.op)).map(c => s"不明な比較です: ${c.op}").toLeft(())
      _ <- r.conditions.find(_.path.trim.isEmpty).map(_ => "属性を指定してください").toLeft(())
      _ <- r.conditions.filter(_.op == "regex").find(c => scala.util.Try(c.value.r).isFailure).map(c =>
        s"正規表現が不正です: ${c.value}"
      ).toLeft(())
    } yield r

  private def values(
    ctx: Json,
    path: String
  ): List[String] = {
    val j = Expr.lookup(ctx, path.split('.').toList)
    j.asArray.map(_.toList.map(Expr.render)).getOrElse(if j.isNull then Nil else List(Expr.render(j)))
  }

  def test(
    c: GroupCondition,
    ctx: Json
  ): Boolean = {
    val vs = values(ctx, c.path).map(_.toLowerCase)
    val v = c.value.toLowerCase
    c.op match {
      case "eq" => vs.contains(v)
      case "ne" => !vs.contains(v)
      case "contains" => vs.exists(_.contains(v))
      case "starts_with" => vs.exists(_.startsWith(v))
      case "ends_with" => vs.exists(_.endsWith(v))
      case "in" => val set = c.values.map(_.toLowerCase).toSet; vs.exists(set.contains)
      case "exists" => vs.exists(_.nonEmpty)
      case "not_exists" => !vs.exists(_.nonEmpty)
      case "regex" => scala.util.Try(("(?i)" + c.value).r).toOption.exists(re =>
          vs.exists(x => re.findFirstIn(x.take(MaxRegexInput)).isDefined)
        )
      case _ => false
    }
  }

  /** 正規表現で照合する値の長さの上限（本人が書ける値で、照合に時間がかかりすぎないように）. */
  val MaxRegexInput = 256

  def matches(
    r: GroupRule,
    ctx: Json
  ): Boolean =
    if r.conditions.isEmpty then false
    else if r.`match` == "any" then r.conditions.exists(test(_, ctx))
    else r.conditions.forall(test(_, ctx))
}
