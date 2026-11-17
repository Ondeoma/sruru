package sruru.web

import io.circe.Json
import io.circe.syntax.*
import io.github.ondeoma.scalactive.components.ComponentManager.*
import sruru.shared.*

/** 一覧の行の番号（v-for の :key）. */
object Ids {
  private var n = 0
  def next(): Int = { n += 1; n }
}

// ------------------------------------------------------------------ カスタム属性の入力

/** カスタム属性の入力欄 1つ（文字は str、真偽値は bool）. */
final case class AttrField(d: AttributeDefDto, str: RV[String], bool: RV[Boolean]) {
  def inputType: String = d.kind match {
    case "number" => "number"
    case "date"   => "date"
    case _        => "text"
  }
}

object Attrs {

  /** 属性の値を入力欄の文字にする（リストは1行に1つ）. */
  private def show(j: Json): String = j.fold("", _.toString, n => n.toString, identity, a => a.map(show).mkString("\n"), o => Json.fromJsonObject(o).noSpaces)

  def fields(defs: List[AttributeDefDto], attrs: Json): List[AttrField] =
    defs.sortBy(d => (d.sort, d.key)).map { d =>
      val v = attrs.hcursor.downField(d.key).focus
      AttrField(d, RV(v.map(show).getOrElse("")), RV(v.flatMap(_.asBoolean).getOrElse(false)))
    }

  /** 入力欄の値を属性の JSON に戻す（定義のない属性はそのまま残す. 空欄は消す）. */
  def build(base: Json, fs: List[AttrField]): Json = {
    val obj = base.asObject.getOrElse(io.circe.JsonObject.empty)
    val out = fs.foldLeft(obj) { (o, f) =>
      val s = f.str.v.trim
      val v: Option[Json] = f.d.kind match {
        case "boolean" => Some(Json.fromBoolean(f.bool.v))
        case "number"  => if (s.isEmpty) None else Some(s.toDoubleOption.flatMap(Json.fromDouble).getOrElse(Json.fromString(s)))
        case "list"    => val xs = Fmt.lines(s); if (xs.isEmpty) None else Some(xs.asJson)
        case _         => if (s.isEmpty) None else Some(Json.fromString(s))
      }
      v.fold(o.remove(f.d.key))(x => o.add(f.d.key, x))
    }
    Json.fromJsonObject(out)
  }

}

// ------------------------------------------------------------------ 動的なグループの条件

/** 条件 1行（value はカンマ区切りで複数にできる: in のとき）. */
final case class CondRow(id: Int, path: RV[String], op: RV[String], value: RV[String]) {
  def needsValue = op.mapC(o => o != "exists" && o != "not_exists")
}

object Rules {

  val ops: List[(String, String)] = List(
    "eq" -> "等しい", "ne" -> "等しくない", "contains" -> "含む", "starts_with" -> "で始まる", "ends_with" -> "で終わる",
    "in" -> "どれかに等しい（カンマ区切り）", "exists" -> "値がある", "not_exists" -> "値がない", "regex" -> "正規表現に合う")

  val paths: List[String] = List("user.email", "user.username", "user.name", "user.source", "user.groups", "user.is_admin", "user.external_id", "user.phone_number",
    "user.given_name", "user.family_name", "user.locale", "user.attributes.")

  def row(path: String = "user.email", op: String = "eq", value: String = ""): CondRow = CondRow(Ids.next(), RV(path), RV(op), RV(value))

  /** {match, conditions: [{path, op, value, values}]} を読む. */
  def parse(rule: Option[Json]): (String, List[CondRow]) = rule match {
    case None => ("all", Nil)
    case Some(j) =>
      val c = j.hcursor
      val m = c.get[String]("match").getOrElse("all")
      val rows = c.downField("conditions").values.toList.flatten.map { x =>
        val xc = x.hcursor
        val vs = xc.get[List[String]]("values").toOption.filter(_.nonEmpty).map(_.mkString(", "))
        val v  = xc.downField("value").focus.map(v => v.asString.getOrElse(v.noSpaces))
        row(xc.get[String]("path").getOrElse(""), xc.get[String]("op").getOrElse("eq"), vs.orElse(v).getOrElse(""))
      }
      (m, rows)
  }

  def build(mode: String, rows: List[CondRow]): Option[Json] =
    if (rows.isEmpty) None
    else Some(Json.obj(
      "match" -> mode.asJson,
      "conditions" -> rows.filter(_.path.v.trim.nonEmpty).map { r =>
        val base = Json.obj("path" -> r.path.v.trim.asJson, "op" -> r.op.v.asJson)
        r.op.v match {
          case "exists" | "not_exists" => base
          case "in"                    => base.deepMerge(Json.obj("values" -> Fmt.commas(r.value.v).asJson))
          case _                       => base.deepMerge(Json.obj("value" -> r.value.v.asJson))
        }
      }.asJson
    ))

}

// ------------------------------------------------------------------ 属性の対応付け（クレーム・SAML 属性）

final case class MappingRow(id: Int, name: RV[String], expression: RV[String], scope: RV[String], friendlyName: RV[String], multi: RV[Boolean]) {
  def toDto: MappingDto = MappingDto(name.v.trim, expression.v, Fmt.opt(scope.v), Fmt.opt(friendlyName.v), multi.v)
}

object Mappings {

  def row(m: MappingDto): MappingRow =
    MappingRow(Ids.next(), RV(m.name), RV(m.expression), RV(m.scope.getOrElse("")), RV(m.friendlyName.getOrElse("")), RV(m.multi))

  def empty(): MappingRow = row(MappingDto("", ""))

  /** 式の書き方の例. */
  val filters: List[(String, String)] = List(
    "lower" -> "小文字にする", "upper" -> "大文字にする", "trim" -> "前後の空白を除く", "default:\"値\"" -> "空のときの値",
    "join:\",\"" -> "リストをつなぐ", "split:\",\"" -> "文字をリストに分ける", "first" -> "最初の要素", "last" -> "最後の要素",
    "filter_prefix:\"app-\"" -> "この文字で始まるものだけ残す", "strip_prefix:\"app-\"" -> "先頭のこの文字を除く",
    "replace:\"a\",\"b\"" -> "置き換える", "prepend:\"x\"" -> "前に付ける", "append:\"x\"" -> "後に付ける", "unique" -> "重複を除く",
    "email_local" -> "メールアドレスの @ より前", "email_domain" -> "メールアドレスの @ より後")

}

// ------------------------------------------------------------------ グループの木

object GroupTree {

  /** 親子の順に並べる（深さ付き. 親が見つからないものは最上位にする）. */
  def flatten(gs: List[GroupDto]): List[(GroupDto, Int)] = {
    val ids = gs.map(_.id).toSet
    val byParent = gs.groupBy(g => g.parentId.filter(ids.contains))
    def walk(p: Option[java.util.UUID], d: Int, seen: Set[java.util.UUID]): List[(GroupDto, Int)] =
      byParent.getOrElse(p, Nil).sortBy(_.name).filterNot(g => seen.contains(g.id)).flatMap(g => (g, d) :: walk(Some(g.id), d + 1, seen + g.id))
    walk(None, 0, Set.empty)
  }

  /** 「親 / 子」の名前. */
  def path(gs: List[GroupDto], g: GroupDto): String = {
    val m = gs.map(x => x.id -> x).toMap
    def up(x: GroupDto, n: Int): List[String] = x.parentId.flatMap(m.get).filter(_ => n < 10).map(p => up(p, n + 1)).getOrElse(Nil) :+ x.name
    up(g, 0).mkString(" / ")
  }

  def indent(d: Int): String = s"padding-left: ${0.55 + d * 1.2}rem"

}

// ------------------------------------------------------------------ グループのポリシーの上書き

/** グループのポリシーの上書きの入力（数の欄は文字列. 空欄・チェックなしは上書きしない）. */
final case class PolicyEdit(
    minLength: RV[String], minClasses: RV[String], history: RV[String], maxAge: RV[String],
    upper: RV[Boolean], lower: RV[Boolean], digit: RV[Boolean], symbol: RV[Boolean], userInfo: RV[Boolean], common: RV[Boolean],
    lockEnabled: RV[Boolean], maxFailures: RV[String], lockMinutes: RV[String],
    mfaMode: RV[String], noTotp: RV[Boolean], noEmail: RV[Boolean], emailMinutes: RV[String],
    lifetime: RV[String], idle: RV[String], maxAccounts: RV[String],
    allow: RV[String], deny: RV[String],
    title: RV[String], logo: RV[Option[String]]
) {

  private def num(label: String, v: String): Either[String, Option[Int]] =
    if (v.trim.isEmpty) Right(None) else v.trim.toIntOption.map(Some(_)).toRight(s"「$label」は数で入力してください")

  def build: Either[String, GroupPolicy] = {
    def must(b: Boolean) = Option.when(b)(true)
    def forbid(b: Boolean) = Option.when(b)(false)
    for {
      minL  <- num("最小の長さ", minLength.v)
      cls   <- num("文字の種類の数", minClasses.v)
      his   <- num("再利用を禁じる数", history.v)
      age   <- num("有効期限", maxAge.v)
      fail  <- num("ロックするまでの回数", maxFailures.v)
      lockM <- num("ロックする時間", lockMinutes.v)
      mail  <- num("メールのコードの有効期間", emailMinutes.v)
      life  <- num("ログインの有効期間", lifetime.v)
      idl   <- num("無操作で切れるまで", idle.v)
      acc   <- num("同時に使えるアカウントの数", maxAccounts.v)
    } yield GroupPolicy(
      PasswordOverride(minL, must(upper.v), must(lower.v), must(digit.v), must(symbol.v), cls, his, age, must(userInfo.v), must(common.v)),
      LockoutOverride(must(lockEnabled.v), fail, lockM),
      MfaOverride(Fmt.opt(mfaMode.v), forbid(noTotp.v), forbid(noEmail.v), mail),
      SessionOverride(life, idl, acc),
      IpOverride(Fmt.lines(allow.v), Fmt.lines(deny.v)),
      BrandingOverride(Fmt.opt(title.v.trim), logo.v))
  }
}

object PolicyEdit {
  def from(p: GroupPolicy): PolicyEdit = {
    def n(o: Option[Int]) = RV(o.map(_.toString).getOrElse(""))
    def b(o: Option[Boolean]) = RV(o.contains(true))
    PolicyEdit(
      n(p.password.minLength), n(p.password.minClasses), n(p.password.historyCount), n(p.password.maxAgeDays),
      b(p.password.requireUpper), b(p.password.requireLower), b(p.password.requireDigit), b(p.password.requireSymbol),
      b(p.password.disallowUserInfo), b(p.password.disallowCommon),
      b(p.lockout.enabled), n(p.lockout.maxFailures), n(p.lockout.lockMinutes),
      RV(p.mfa.mode.getOrElse("")), RV(p.mfa.allowTotp.contains(false)), RV(p.mfa.allowEmail.contains(false)), n(p.mfa.emailCodeMinutes),
      n(p.session.lifetimeHours), n(p.session.idleMinutes), n(p.session.maxAccounts),
      RV(p.ip.allow.mkString("\n")), RV(p.ip.deny.mkString("\n")),
      RV(p.branding.title.getOrElse("")), RV(p.branding.logo))
  }

}
