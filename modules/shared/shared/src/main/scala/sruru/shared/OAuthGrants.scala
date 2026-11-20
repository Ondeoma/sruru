package sruru.shared

/** OIDC のクライアントが使える方式（grant type）. 管理画面の選択肢・登録の検査・トークンのエンドポイントで共有する. */
object OAuthGrants {
  val AuthorizationCode = "authorization_code"
  val RefreshToken = "refresh_token"
  val ClientCredentials = "client_credentials"

  /** デバイスフロー（RFC 8628）. ブラウザや入力の手段がない端末・CLI 向け. */
  val DeviceCode = "urn:ietf:params:oauth:grant-type:device_code"

  /** 画面に出す順と説明. */
  val labels: List[(String, String)] = List(
    AuthorizationCode -> "認可コード（ブラウザでログイン）",
    RefreshToken -> "リフレッシュトークン",
    ClientCredentials -> "クライアントクレデンシャル（サーバー同士）",
    DeviceCode -> "デバイスコード（ブラウザのない端末・CLI）"
  )

  val all: List[String] = labels.map(_._1)
}
