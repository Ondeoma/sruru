package sruru.shared

/** ログインの前でも開く画面のパス（画面の 401 の扱い・ヘッダーの有無と、サーバーの CSP で共有する）. */
object Pages {

  /** ログイン・同意などの画面（401 でもログイン画面へ移らない）. */
  val login: List[String] =
    List("/login", "/choose", "/consent", "/forgot", "/reset-password", "/setup", "/error", "/logged-out")

  /**
   * ログインしていなくても開く画面（ヘッダーを出さない. 画面のブラウザの観測（RUM）も読まない）.
   * /device（デバイスフローの確認）は、コードの入力にログインが要るが、許可を選ぶ画面なのでここに入れる（401 ならログイン画面へ移る）.
   */
  val public: List[String] = "/verify-email" :: "/device" :: login

  private def under(path: String, ps: List[String]): Boolean = ps.exists(x => path == x || path.startsWith(x + "/"))

  def isLogin(path: String): Boolean = under(path, login)
  def isPublic(path: String): Boolean = under(path, public)
}
