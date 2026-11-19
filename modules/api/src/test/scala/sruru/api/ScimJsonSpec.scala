package sruru.api

import io.circe.parser.parse

class ScimJsonSpec extends munit.FunSuite {

  private val user = parse("""{"userName":"taro","active":true,"name":{"givenName":"太郎"},
    "emails":[{"value":"a@example.com","type":"work","primary":true}],
    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"department":"営業"}}""").toOption.get

  private def op(
    o: String,
    path: Option[String],
    v: String
  ) = ScimJson.applyOp(user, o, path, parse(v).toOption.get).fold(e => fail(e), identity)

  test("パスなしの replace（Entra の name.givenName 形式のキー）") {
    val r = op("replace", None, """{"active":false,"name.givenName":"次郎"}""")
    assertEquals(ScimJson.get(r, "active").asBoolean, Some(false))
    assertEquals(ScimJson.get(ScimJson.get(r, "name"), "givenName").asString, Some("次郎"))
  }

  test("フィルターつきのパス（emails[type eq \"work\"].value）と、ない要素の追加") {
    val r = op("replace", Some("emails[type eq \"work\"].value"), "\"b@example.com\"")
    assertEquals(
      ScimJson.get(r, "emails").asArray.map(_.map(e => ScimJson.get(e, "value").asString.get).toList),
      Some(List("b@example.com"))
    )
    val r2 = op("add", Some("emails[type eq \"home\"].value"), "\"h@example.com\"")
    assertEquals(ScimJson.get(r2, "emails").asArray.map(_.size), Some(2))
  }

  test("拡張スキーマの属性と、大文字小文字の違うキー") {
    val r = op("replace", Some("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department"), "\"企画\"")
    assertEquals(
      ScimJson.get(
        ScimJson.get(r, "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"),
        "department"
      ).asString,
      Some("企画")
    )
    assertEquals(ScimJson.get(op("replace", Some("USERNAME"), "\"jiro\""), "userName").asString, Some("jiro"))
  }

  test("メンバーの追加と、条件での削除") {
    val g = parse("""{"displayName":"g","members":[{"value":"1"}]}""").toOption.get
    val r =
      ScimJson.applyOp(g, "add", Some("members"), parse("""[{"value":"2"},{"value":"1"}]""").toOption.get).toOption.get
    assertEquals(ScimJson.get(r, "members").asArray.map(_.size), Some(2))
    val r2 = ScimJson.applyOp(r, "remove", Some("members[value eq \"1\"]"), io.circe.Json.Null).toOption.get
    assertEquals(
      ScimJson.get(r2, "members").asArray.map(_.map(m => ScimJson.get(m, "value").asString.get).toList),
      Some(List("2"))
    )
  }
}
