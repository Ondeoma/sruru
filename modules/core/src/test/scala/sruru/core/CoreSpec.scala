package sruru.core

import io.circe.Json
import io.circe.parser.parse
import sruru.shared.PasswordPolicy

class CoreSpec extends munit.FunSuite {

  private val ctx = parse("""{"user":{"username":"taro","email":"Taro@Example.com","given_name":"太郎","family_name":"山田",
    "groups":["app-sales","app-dev","staff"],"attributes":{"department":"営業","level":3}}}""").toOption.get

  test("Expr: 単独の式は値そのもの") {
    assertEquals(Expr.eval("{{user.attributes.level}}", ctx), Json.fromInt(3))
    assertEquals(
      Expr.eval("{{ user.groups | filter_prefix:\"app-\" | strip_prefix:\"app-\" }}", ctx),
      Json.arr(Json.fromString("sales"), Json.fromString("dev"))
    )
    assertEquals(Expr.eval("{{user.missing | default:\"なし\"}}", ctx), Json.fromString("なし"))
    assertEquals(Expr.eval("{{user.email | lower | email_domain}}", ctx), Json.fromString("example.com"))
  }

  test("Expr: 文字と混ぜると文字列") {
    assertEquals(Expr.eval("{{user.family_name}} {{user.given_name}}", ctx), Json.fromString("山田 太郎"))
    assertEquals(Expr.eval("g={{user.groups | join:\";\"}}", ctx), Json.fromString("g=app-sales;app-dev;staff"))
    assertEquals(Expr.eval("{{\"固定\"}}", ctx), Json.fromString("固定"))
  }

  test("Expr: 不正な式") {
    assert(Expr.validate("{{user.x | nope}}").isLeft)
    assert(Expr.validate("{{user.x").isLeft)
    assert(Expr.validate("abc {{ user.x | replace:\"a\":\"b\" }}").isRight)
  }

  test("GroupRule") {
    val r = GroupRule(
      "all",
      List(GroupCondition("user.email", "ends_with", "@example.com"), GroupCondition("user.groups", "contains", "dev"))
    )
    assert(GroupRule.matches(r, ctx))
    assert(!GroupRule.matches(
      r.copy(conditions = r.conditions :+ GroupCondition("user.attributes.department", "eq", "企画")),
      ctx
    ))
    assert(GroupRule.matches(
      GroupRule("any", List(GroupCondition("user.attributes.department", "in", values = List("企画", "営業")))),
      ctx
    ))
    assert(GroupRule.validate(GroupRule("all", List(GroupCondition("user.x", "bad")))).isLeft)
  }

  test("PasswordCheck") {
    val p = PasswordPolicy(minLength = 10, minClasses = 3)
    assert(PasswordCheck.violations("short", p).nonEmpty)
    assert(PasswordCheck.violations("abcdefghijk", p).nonEmpty)
    assertEquals(PasswordCheck.violations("Correct-Horse9", p), Nil)
    assert(PasswordCheck.violations("taro-Pass-123", p, List("taro")).nonEmpty)
    assert(PasswordCheck.violations("Password123", p.copy(minLength = 8)).exists(_.contains("よく使われる")) ||
      PasswordCheck.common.contains("password123"))
  }

  test("IpRules") {
    assert(IpRules.matches("192.168.1.5", List("192.168.0.0/16")))
    assert(!IpRules.matches("10.0.0.1", List("192.168.0.0/16")))
    assert(IpRules.matches("2001:db8::1", List("2001:db8::/32")))
    assert(IpRules.matches("::ffff:192.168.1.5", List("192.168.1.0/24")))
    assert(IpRules.allowed("1.2.3.4", Nil, Nil))
    assert(!IpRules.allowed("1.2.3.4", List("10.0.0.0/8"), Nil))
    assert(!IpRules.allowed("10.1.1.1", List("10.0.0.0/8"), List("10.1.0.0/16")))
    assert(IpRules.parseCidr("1.2.3.4/33").isLeft)
    assert(IpRules.parseCidr("example.com").isLeft)
    // 信頼するプロキシ経由のときだけ X-Forwarded-For を使う
    assertEquals(IpRules.clientIp("10.0.0.2", Some("203.0.113.9, 10.0.0.3"), List("10.0.0.0/8")), "203.0.113.9")
    assertEquals(IpRules.clientIp("198.51.100.1", Some("203.0.113.9"), List("10.0.0.0/8")), "198.51.100.1")
    // すべて信頼するプロキシなら、利用者が書けるいちばん左ではなく、もっとも近いプロキシ
    assertEquals(IpRules.clientIp("10.0.0.2", Some("10.9.9.9, 10.0.0.3"), List("10.0.0.0/8")), "10.0.0.3")
  }

  test("ScimFilter") {
    val u =
      parse("""{"userName":"Taro","active":true,"emails":[{"value":"taro@example.com","type":"work","primary":true}],
      "name":{"givenName":"Taro"},"meta":{"lastModified":"2026-01-01T00:00:00Z"},
      "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"department":"Sales"}}""").toOption.get
    def m(
      f: String
    ) = ScimFilter.parse(f).map(ScimFilter.matches(_, u)).fold(e => fail(e), identity)
    assert(m("userName eq \"taro\""))
    assert(m("emails[type eq \"work\" and value co \"example\"]"))
    assert(m("emails.value sw \"taro@\""))
    assert(m("name.givenName pr and active eq true"))
    assert(!m("not (userName eq \"taro\")"))
    assert(m("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department eq \"sales\""))
    assert(m("meta.lastModified gt \"2025-12-31T00:00:00Z\""))
    assert(m("userName eq \"x\" or (active eq true)"))
    assert(ScimFilter.parse("userName eq").isLeft)
    assertEquals(ScimFilter.parse("userName eq \"a\"").toOption.flatMap(ScimFilter.simpleEq), Some("username" -> "a"))
    val pp = ScimFilter.parsePatchPath("members[value eq \"abc\"]").toOption.get
    assertEquals(pp.attr.attr, "members")
    assert(pp.filter.isDefined)
    assertEquals(ScimFilter.parsePatchPath("emails[type eq \"work\"].value").toOption.get.subAttr, Some("value"))
  }

  test("Membership は親グループをたどる") {
    val now = java.time.Instant.now()
    def g(
      n: String,
      parent: Option[java.util.UUID]
    ) = Group(java.util.UUID.randomUUID(), n, "", parent.toList, Json.obj(), false, None, "local", None, now, now)
    val root = g("全社", None)
    val dept = g("営業部", Some(root.id))
    val team = g("営業1課", Some(dept.id))
    val all = List(root, dept, team).map(x => x.id -> x).toMap
    assertEquals(Membership.expand(List(team.id), all).names, List("営業1課", "営業部", "全社").sorted)
  }

  test("SCIM のフィルターは深いかっこ・長い入力・不正な \\u を拒否する") {
    assert(ScimFilter.parse("(" * 40 + "userName eq \"a\"" + ")" * 40).isLeft)
    assert(ScimFilter.parse("((userName eq \"a\"))").isRight)
    assert(ScimFilter.parse("userName eq \"" + "a" * 5000 + "\"").isLeft)
    assert(ScimFilter.parse("userName eq \"\\uZZZZ\"").isLeft)
  }

  test("試行の回数は IPv6 を /64 にまとめて数える") {
    assertEquals(IpRules.throttleKey("2001:db8:1:2:aaaa::1"), IpRules.throttleKey("2001:db8:1:2:bbbb::2"))
    assertNotEquals(IpRules.throttleKey("2001:db8:1:2::1"), IpRules.throttleKey("2001:db8:1:3::1"))
    assertEquals(IpRules.throttleKey("192.0.2.1"), "192.0.2.1")
  }

  test("グループのポリシー: セキュリティは厳しい方、表示は優先度の高いグループ") {
    import sruru.shared.*
    val global = PoliciesDto(
      password = PasswordPolicy(minLength = 10, historyCount = 0, maxAgeDays = 0),
      lockout = LockoutPolicy(maxFailures = 5, lockMinutes = 15),
      mfa = MfaPolicy(mode = "optional"),
      session = SessionPolicy(lifetimeHours = 336, idleMinutes = 0),
      ip = IpPolicy(deny = List("192.0.2.1")),
      branding = Branding(title = "全社")
    )
    val a = GroupPolicy(
      password = PasswordOverride(minLength = Some(14), maxAgeDays = Some(90)),
      session = SessionOverride(idleMinutes = Some(30)),
      branding = BrandingOverride(title = Some("営業"), logo = Some("l-a")),
      ip = IpOverride(allow = List("10.0.0.0/8"))
    )
    // 弱い値（短い最小長・長い有効期間・任意の多要素）は効かない
    val b = GroupPolicy(
      password = PasswordOverride(minLength = Some(8), maxAgeDays = Some(30)),
      mfa = MfaOverride(mode = Some("required")),
      lockout = LockoutOverride(lockMinutes = Some(0)),
      session = SessionOverride(lifetimeHours = Some(9999), idleMinutes = Some(60)),
      branding = BrandingOverride(title = Some("開発"))
    )
    val e = GroupPolicy.effective(global, List((1, "営業", a), (5, "開発", b)))
    assertEquals(e.password.minLength, 14)
    assertEquals(e.password.maxAgeDays, 30)
    assertEquals(e.mfa.mode, "required")
    assertEquals(e.lockout.lockMinutes, 0)
    assertEquals(e.session.lifetimeHours, 336)
    assertEquals(e.session.idleMinutes, 30)
    // 表示は優先度の高い「開発」. ロゴは開発が上書きしていないので次の「営業」
    assertEquals(e.branding.title, "開発")
    assertEquals(e.branding.logo, Some("l-a"))
    // IP: 全体の拒否にグループの許可が加わる
    assert(IpRules.allowedBy("10.1.2.3", e.ip))
    assert(!IpRules.allowedBy("198.51.100.1", e.ip))
    assert(!IpRules.allowedBy("192.0.2.1", e.ip))
    // グループがなければ全体のまま
    assertEquals(GroupPolicy.effective(global, Nil), global)
    // 両方の方法を禁じたら認証アプリは残す
    val noBoth = GroupPolicy.effective(
      global,
      List((0, "x", GroupPolicy(mfa = MfaOverride(allowTotp = Some(false), allowEmail = Some(false)))))
    )
    assert(noBoth.mfa.allowTotp && !noBoth.mfa.allowEmail)
  }
}
