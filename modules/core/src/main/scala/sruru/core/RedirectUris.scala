package sruru.core

/**
 * OIDC のリダイレクト URI の照合. ふつうは登録した文字列との完全一致.
 * ネイティブアプリ（公開クライアント）がループバックで受けるときだけ、ポートの違いを許す（RFC 8252 7.3・8.3:
 * アプリは空いているポートを OS からもらうので、ポートは毎回変わる）.
 */
object RedirectUris {

  /** ループバックの IP アドレス（127.0.0.1・[::1]）の http の URI. localhost は対象にしない（RFC 8252 8.3 が非推奨としている）. */
  private val Loopback = """^http://(127\.0\.0\.1|\[::1\])(?::([0-9]{1,5}))?(/[^#]*)?$""".r

  /** ループバックの URI なら（ホスト, パスとクエリ）. ポートは捨てる. ユーザー情報・フラグメント付きや、範囲の外のポートは対象にしない. */
  private def loopback(uri: String): Option[(String, String)] = uri match {
    case Loopback(host, port, rest) if Option(port).forall(_.toInt <= 65535) => Some((host, Option(rest).getOrElse("")))
    case _ => None
  }

  /** ポートだけが違うループバックの URI か（スキーム・ホスト・パス・クエリは完全一致）. */
  def sameLoopback(registered: String, requested: String): Boolean =
    loopback(registered).exists(r => loopback(requested).contains(r))

  /**
   * 要求の URI が登録に合うか. 完全一致のほか、公開クライアント（publicClient）に限って、ループバックのポートだけの違いを許す.
   * 機密クライアント（サーバーで動く Web アプリ）は戻り先が決まっているので、完全一致だけ.
   */
  def matches(registered: List[String], requested: String, publicClient: Boolean): Boolean =
    registered.contains(requested) || (publicClient && registered.exists(sameLoopback(_, requested)))
}
