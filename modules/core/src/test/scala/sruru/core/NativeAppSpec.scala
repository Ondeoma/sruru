package sruru.core

/** ネイティブアプリ向けの判定: ループバックのリダイレクト URI（RFC 8252）と、デバイスフローの user_code（RFC 8628）. */
class NativeAppSpec extends munit.FunSuite {

  private val v4 = List("http://127.0.0.1/callback")
  private val v6 = List("http://[::1]:7777/cb?x=1")

  test("公開クライアントのループバックは、ポートだけ違っても一致する（RFC 8252 7.3）") {
    List(
      v4 -> "http://127.0.0.1/callback",
      v4 -> "http://127.0.0.1:51234/callback",
      v4 -> "http://127.0.0.1:1/callback",
      v4 -> "http://127.0.0.1:65535/callback",
      v6 -> "http://[::1]:7777/cb?x=1",
      v6 -> "http://[::1]:40000/cb?x=1",
      v6 -> "http://[::1]/cb?x=1",
      // パスなしで登録したもの
      List("http://127.0.0.1") -> "http://127.0.0.1:8080"
    ).foreach((reg, req) => assert(RedirectUris.matches(reg, req, publicClient = true), s"$reg ← $req"))
  }

  test("スキーム・ホスト・パス・クエリの違い、localhost、ユーザー情報、不正なポートは一致しない") {
    List(
      v4 -> "http://127.0.0.1:51234/other",
      v4 -> "http://127.0.0.1:51234/callback/",
      v4 -> "http://127.0.0.1:51234/callback?x=1",
      v4 -> "http://127.0.0.1:51234/callback#frag",
      v4 -> "https://127.0.0.1:51234/callback",
      v4 -> "HTTP://127.0.0.1:51234/callback",
      v4 -> "http://127.0.0.2:51234/callback",
      v4 -> "http://[::1]:51234/callback",
      v4 -> "http://localhost:51234/callback",
      v4 -> "http://127.0.0.1.evil.example:51234/callback",
      v4 -> "http://evil.example:51234/callback",
      v4 -> "http://user@127.0.0.1:51234/callback",
      v4 -> "http://127.0.0.1:51234@evil.example/callback",
      v4 -> "http://127.0.0.1:99999/callback",
      v4 -> "http://127.0.0.1:/callback",
      v4 -> "http://127.0.0.1:80a/callback",
      v4 -> "http://127.0.0.1:51234",
      v6 -> "http://[::1]:40000/cb",
      v6 -> "http://[::1]:40000/cb?x=2",
      v6 -> "http://[::2]:7777/cb?x=1",
      v6 -> "http://127.0.0.1:7777/cb?x=1",
      // localhost で登録したものは、完全一致だけ（RFC 8252 8.3 が非推奨としているので、ポートの違いは許さない）
      List("http://localhost/callback") -> "http://localhost:51234/callback",
      List("http://localhost:3000/callback") -> "http://localhost:3001/callback",
      // ループバックでないホストは、完全一致だけ
      List("https://app.example.com/callback") -> "https://app.example.com:8443/callback",
      List("http://192.168.0.10/callback") -> "http://192.168.0.10:8080/callback",
      List("com.example.app:/callback") -> "com.example.app:/other"
    ).foreach((reg, req) => assert(!RedirectUris.matches(reg, req, publicClient = true), s"$reg ← $req"))
    // 完全一致は localhost・カスタムスキームでも通る
    assert(RedirectUris.matches(List("http://localhost:3000/callback"), "http://localhost:3000/callback", true))
    assert(RedirectUris.matches(List("com.example.app:/callback"), "com.example.app:/callback", true))
  }

  test("機密クライアントは完全一致だけ（ループバックでもポートの違いを許さない）") {
    assert(RedirectUris.matches(v4, "http://127.0.0.1/callback", publicClient = false))
    assert(!RedirectUris.matches(v4, "http://127.0.0.1:51234/callback", publicClient = false))
    assert(!RedirectUris.matches(v6, "http://[::1]:40000/cb?x=1", publicClient = false))
  }

  test("user_code: 母音と紛らわしい文字を除いた 8 文字. 入力は大文字小文字・ハイフン・空白の違いを吸収する") {
    val rnd = new java.security.SecureRandom()
    val codes = List.fill(200)(UserCodes.generate(rnd))
    assert(codes.forall(c => c.length == 8 && c.forall(UserCodes.Alphabet.contains(_))), codes.toString)
    assert(codes.forall(c => !c.exists("AEIOUY0123456789".contains(_))))
    assert(codes.distinct.size > 190)
    assertEquals(UserCodes.format("BCDFGHJK"), "BCDF-GHJK")
    List("BCDF-GHJK", "bcdf-ghjk", " bcdf ghjk ", "BCDFGHJK", "b-c-d-f-g-h-j-k", "ＢＣＤＦ－ｇｈｊｋ", "bcdf\tghjk\n")
      .foreach(in => assertEquals(UserCodes.normalize(in), Some("BCDFGHJK"), in))
    // 長さの違い・使わない文字（母音・数字・記号）はコードではない
    List("", "BCDF-GHJ", "BCDF-GHJKL", "ABCD-EFGH", "BCDF-GHJ1", "BCDF/GHJK", "BCDF-GHJ%").foreach(in =>
      assertEquals(UserCodes.normalize(in), None, in)
    )
    codes.foreach(c => assertEquals(UserCodes.normalize(UserCodes.format(c).toLowerCase), Some(c)))
  }
}
