package sruru.api

import sruru.core.OidcClientConfig

import java.util.UUID

/** ログアウト後に戻してよい URI. */
class PostLogoutSpec extends munit.FunSuite {
  private val c = OidcClientConfig(
    UUID.randomUUID(),
    "stui",
    None,
    List("https://stui.example.com/auth/callback"),
    List("https://other.example.com/bye"),
    Nil,
    Nil,
    "implicit",
    "id",
    "RS256",
    300,
    300,
    3600,
    false,
    None
  )

  test("登録したものと、リダイレクト URI と同じオリジンの URL は戻してよい") {
    assert(OidcRoutes.allowedPostLogout(c, "https://other.example.com/bye"))
    assert(OidcRoutes.allowedPostLogout(c, "https://stui.example.com/"))
    assert(OidcRoutes.allowedPostLogout(c, "https://STUI.example.com/login?loggedOut=1"))
  }

  test("ほかのオリジン・ポート違い・http への格下げ・ユーザー情報つきは戻さない") {
    assert(!OidcRoutes.allowedPostLogout(c, "https://evil.example.com/"))
    assert(!OidcRoutes.allowedPostLogout(c, "https://stui.example.com:8443/"))
    assert(!OidcRoutes.allowedPostLogout(c, "http://stui.example.com/"))
    assert(!OidcRoutes.allowedPostLogout(c, "https://stui.example.com@evil.example.com/"))
    assert(!OidcRoutes.allowedPostLogout(c, "https://other.example.com/"))
    assert(!OidcRoutes.allowedPostLogout(c, "not a url"))
  }

  test("公開クライアントが登録したループバックの URI は、ポートだけ違っても戻してよい（機密クライアント・ほかのパスは戻さない）") {
    val native = c.copy(
      redirectUris = List("http://127.0.0.1/callback", "com.example.app:/callback"),
      postLogoutRedirectUris = List("http://127.0.0.1/logged-out", "com.example.app:/logged-out")
    )
    assert(OidcRoutes.allowedPostLogout(native, "http://127.0.0.1:51234/logged-out"))
    assert(OidcRoutes.allowedPostLogout(native, "http://127.0.0.1/logged-out"))
    assert(OidcRoutes.allowedPostLogout(native, "com.example.app:/logged-out"))
    // 「同じオリジンなら任意のパス」は、ポートが同じ（= 同じオリジン）ときだけ. ポートの違うループバックの任意のパスには広げない
    assert(OidcRoutes.allowedPostLogout(native, "http://127.0.0.1/anything"))
    assert(!OidcRoutes.allowedPostLogout(native, "http://127.0.0.1:51234/anything"))
    assert(!OidcRoutes.allowedPostLogout(native, "http://127.0.0.1:51234/callback"))
    assert(!OidcRoutes.allowedPostLogout(native, "http://localhost:51234/logged-out"))
    assert(!OidcRoutes.allowedPostLogout(native, "com.example.app:/other"))
    val confidential = native.copy(secretHash = Some(Array[Byte](1)))
    assert(!OidcRoutes.allowedPostLogout(confidential, "http://127.0.0.1:51234/logged-out"))
    assert(OidcRoutes.allowedPostLogout(confidential, "http://127.0.0.1/logged-out"))
  }

  test("カスタムスキームの判定（CSP の form-action に足すスキーム）: http・https と、スキームの形でないものは足さない") {
    assertEquals(OidcRoutes.customScheme("com.example.app:/callback"), Some("com.example.app"))
    assertEquals(OidcRoutes.customScheme("my-app+x://cb?a=1"), Some("my-app+x"))
    List(
      "https://app.example.com/cb",
      "http://127.0.0.1:1/cb",
      "/oauth2/logout",
      "Evil:/x",
      "a b:/x",
      "x;script-src *:/y",
      ""
    )
      .foreach(u => assertEquals(OidcRoutes.customScheme(u), None, u))
  }
}
