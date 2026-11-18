package sruru.api

import sruru.core.OidcClientConfig

import java.util.UUID

/** ログアウト後に戻してよい URI. */
class PostLogoutSpec extends munit.FunSuite:
  private val c = OidcClientConfig(UUID.randomUUID(), "stui", None, List("https://stui.example.com/auth/callback"),
    List("https://other.example.com/bye"), Nil, Nil, "implicit", "id", "RS256", 300, 300, 3600, false, None)

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
