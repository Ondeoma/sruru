# sruru

<p align="center"><img src="frontend/public/logo.svg" width="128" height="128" alt="sruru のロゴ"></p>

sruru は、組織のための認証基盤（IdP）です。OpenID Connect・OAuth 2.0・SAML 2.0 でアプリケーションにシングルサインオンを提供し、
ユーザー・グループ・多要素認証・監査ログをまとめて管理します。ライセンス: MIT

アプリケーションとの連携の手順は [docs/integration.md](docs/integration.md) を参照してください。

## 機能

- **OpenID Connect / OAuth 2.0**: 認可コード（PKCE）・リフレッシュトークン（ローテーションと再利用の検出）・クライアントクレデンシャル、
  ディスカバリー、JWKS（RS256・ES256。鍵の入れ替え）、UserInfo、イントロスペクション（RFC 7662）、失効（RFC 7009）、
  RP からのログアウト（end_session）、バックチャネルのログアウト、`prompt`（none・login・consent・select_account）・`max_age`、
  `response_mode=form_post`、同意の画面、アクセストークンは JWT（RFC 9068）
- **ネイティブアプリ**: iOS・Android・デスクトップ・CLI の認証に使える。公開クライアント + PKCE、カスタムスキーム・Universal Links / App Links、
  ループバックの任意のポート（RFC 8252）、ブラウザのない端末・CLI 向けのデバイスフロー（RFC 8628）。手引きは [docs/integration.md](docs/integration.md)
- **SAML 2.0**: SP 起点（HTTP-Redirect・HTTP-POST）と IdP 起点の SSO、応答・アサーションの署名（RSA-SHA256）、AuthnRequest の署名の検証、
  SP からのログアウト、IdP のメタデータ、SP のメタデータの読み込み
- **カスタム属性**: ユーザーに任意の属性（文字列・数値・真偽値・日付・リスト）を定義し、アプリごとにクレーム・SAML 属性へ対応付ける。
  式は `{{user.attributes.department}}` や `{{user.groups | filter_prefix:"app-" | strip_prefix:"app-"}}` のように書ける
- **多要素認証**: 認証アプリ（TOTP）、メールのワンタイムコード、回復コード。全員・管理者・特定のグループ・アプリごとに必須にできる。
  必須なのに未登録の人には、ログインの途中で登録してもらう
- **マジックリンク**: 管理者・許可したサービスが、1回限りのログインのリンクを発行できる（メールで送るか、サービスが自分のメールに埋め込む）。
  開いただけではログインせず確認の画面のボタンで使う・多要素認証が必要な人には2つ目の要素も求める（`docs/design.md`）
- **ユーザーの移行**: 管理 API でユーザーを bcrypt（jBCrypt の `$2a$` など）のハッシュ付きで取り込め、初めてのログインで Argon2id に置き換わる
- **アカウントのロック・パスワードポリシー**: 連続の失敗でロック（時間・回数）、IP アドレスごとの試行の制限、
  長さ・文字の種類・履歴・有効期限・よく使われるパスワードの禁止、パスワードの再設定のメール
- **IP 制限**: 全体の許可・拒否、管理画面だけの許可、アプリごとの許可（CIDR。IPv4・IPv6）。ロードバランサーの X-Forwarded-For に対応
- **グループ**: 親子の階層（親は複数にできる。子のメンバーはすべての親のメンバー）、属性、管理者のグループ、条件による動的なメンバー
  （例: メールアドレスが `@example.com` で終わり、部署が「営業」）。アプリを使えるグループの制限
- **グループごとのポリシー**: パスワード・ロック・多要素認証・セッション・IP 制限を、グループごとに上書きできる。
  全体と所属するグループのうち、より厳しい方が効く。サービス名・ロゴはグループの優先度で決まる
- **マルチドメイン**: 同じ sruru を複数のホスト名で公開し、アクセスしたホスト名ごとにポリシーと表示を上書きできる
  （issuer・エンティティ ID・ログインはホスト名ごと。ユーザー・グループ・アプリケーションは共通。`docs/design.md`）
- **ブランド**: サービス名とロゴ（PNG・JPEG・WebP・GIF・SVG）を管理画面で変えられる
- **アイコン**: ユーザーのアイコンの画像を登録でき、OIDC の `picture`・SCIM の `photos` で他のサービスに渡す。
  外部の IdP の画像・Gravatar も使える。アプリのアイコンはポータルに出る（登録したときにサイトのアイコン（favicon）を自動で取り込む）
- **複数のアカウント**: 1つのブラウザで複数のアカウントにログインし、切り替えられる（`prompt=select_account` のアカウントの選択の画面）
- **Google Workspace / Microsoft Entra ID**: 外部の IdP でのログイン（ドメインの制限・自動作成・メールアドレスでの結び付け）と、
  ディレクトリ（ユーザー・グループ・写真）の定期的な同期。汎用の OIDC プロバイダも使える
- **クライアント証明書**: リバースプロキシのヘッダー、または sruru 自身の TLS で受けた証明書でログイン。
  登録した証明書・SAN のメールアドレス・UPN・CN でユーザーに対応付ける
- **SCIM 2.0**: ユーザー・グループの作成・更新・PATCH・削除、フィルター、Enterprise User 拡張（カスタム属性に対応付け）
- **API・MCP**: スコープ付きの API トークン（read・write・admin・scim）、REST API、MCP（AI から管理の操作ができる）
- **監査ログ**: ログイン・失敗・設定の変更・トークンの発行などをすべて記録。検索・CSV の書き出し・保存期間、
  ハッシュの鎖による改ざんの検出
- **冗長化**: アプリはステートレス（セッション・署名鍵・定期処理のリースも DB）で複数ノードで動く。PostgreSQL は Patroni
- 画面はレスポンシブ・ダークモード対応。利用者のポータル（アプリの一覧. ドラッグで自分用に並べ替えられる）・個人設定・管理画面

設計は [docs/design.md](docs/design.md)、構築・運用は [docs/operations.md](docs/operations.md) を参照してください。

## 構成

| モジュール | 内容 |
|---|---|
| `modules/shared` | バックエンドと画面（Scala.js）で共有する API の型・ポリシーの型（circe） |
| `modules/core` | 純粋なロジック（パスワードの条件・IP 制限・属性の式・動的なグループの条件・SCIM のフィルター） |
| `modules/security` | Argon2id・JWS/JWK・TOTP・X.509（クライアント証明書の検証）・秘密の値の暗号化 |
| `modules/db` | doobie のストア、Flyway のマイグレーション、ジョブのリース、監査ログのハッシュの鎖 |
| `modules/saml` | SAML 2.0（XML の安全な読み込み・署名と検証・メタデータ） |
| `modules/federation` | 外部の OIDC プロバイダでのログイン、Google Workspace・Entra ID のディレクトリの取得 |
| `modules/notify` | メール（SMTP） |
| `modules/api` | http4s のルート（ログイン・OIDC・SAML・SCIM・管理・MCP）とサービス |
| `modules/app` | 起動・設定（環境変数）・画面の配信 |
| `modules/web` | 画面（[Scalactive](https://github.com/Ondeoma/scalactive) の `.st` 単一ファイルコンポーネント） |
| `frontend/` | Vite。Scala.js の出力をまとめてビルドする |
| `deploy/` | Docker（試験用の3ノード構成）と VM 構築用の設定のひな形 |

技術: Scala 3.9 LTS、Cats Effect 3、http4s 1.0（マイルストーン版）、doobie、Flyway、PostgreSQL 17、BouncyCastle、Scala.js + Scalactive。

## 開発

必要なもの: JDK 25、sbt、Node.js、Docker。

```bash
docker compose -f docker-compose.dev.yml up -d --wait   # PostgreSQL (:54360)、Mailpit (SMTP :1031、画面 :8031)
scripts/dev-restart.sh                                   # バックエンドを :9100 で起動（scripts/dev-env.sh の設定）
(cd frontend && npm install && npm run dev)              # 画面の開発サーバー http://localhost:5180（/api などは :9100 へ中継）
sbt ~web/fastLinkJS                                      # 画面の変更を再リンクし続ける
```

- 初めて起動すると、ログ（既定 `/tmp/sruru-dev.log`）に「セットアップのトークン」が出ます。画面の `/setup` で最初の管理者を作ってください。
- `scripts/smoke.sh` で、ログイン・OIDC・SAML・SCIM・MCP・多要素認証・ロックを一通り確かめられます
  （初回は `SETUP_TOKEN=<トークン> scripts/smoke.sh` で管理者 `admin` を作る）。
- 送信されたメール（ワンタイムコードなど）は Mailpit（http://localhost:8031）で見られます。

テスト:

```bash
sbt test
```

**DB マイグレーション**（`modules/db/src/main/resources/db/migration`）: スキーマを変えるときは新しい番号の `V<n>__*.sql` を追加し、適用済みのファイルは書き換えないでください。

## 配布・起動

```bash
scripts/dist.sh                   # dist/lib/*.jar と dist/static（画面）を作る
java -cp 'dist/lib/*' sruru.app.Main
```

主な環境変数（すべては `modules/app/src/main/scala/sruru/app/Main.scala` の `Config`）:

| 変数 | 内容 |
|---|---|
| `DATABASE_URL` / `DATABASE_USER` / `DATABASE_PASSWORD` | PostgreSQL。冗長構成では3台を並べて `targetServerType=primary` |
| `PUBLIC_URL` | 公開 URL（既定のホスト名）。OIDC の issuer・SAML のエンティティ ID（`${PUBLIC_URL}/saml/metadata`）になる。`https://` なら Cookie に Secure が付く。ほかのホスト名は管理画面の「ドメイン」で足す（issuer・ポリシーはホスト名ごと。スキームは `PUBLIC_URL` と同じ） |
| `APP_SECRET` | 署名鍵・外部 IdP のシークレット・TOTP の鍵の暗号化に使う16文字以上の値（全ノードで同じ。変えると保存済みの値を読めない） |
| `STATIC_DIR` | ビルド済みの画面（`dist/static`） |
| `HTTP_PORT` | 待ち受けるポート（既定 8080） |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_TLS` / `SMTP_USER` / `SMTP_PASSWORD` / `MAIL_FROM` | メール（未設定ならメールは送らず、ログに出す） |
| `TLS_KEYSTORE` / `TLS_KEYSTORE_PASSWORD` / `HTTPS_PORT` | sruru 自身で TLS を受ける（クライアント証明書を求める）。PKCS#12 |
| `NODE_ID` | ノード名（ログ・定期処理のリース） |
| `OTEL_EXPORTER_OTLP_ENDPOINT` / `OTEL_EXPORTER_OTLP_HEADERS` | ログ・メトリクス・トレースの送り先（skorimako の URL と `Authorization=Bearer sko_…`（ingest のキー））。未設定なら送らない。そのほか OpenTelemetry の標準の `OTEL_*` が使える。パスワード・トークン・認可コード・SAML の応答・URL のクエリは送らない |
| `LOG_FORMAT` / `LOG_LEVEL` | 標準出力のログの形（`text`（既定）・`json`）と水準（既定 `INFO`）。ログにはトレースの ID と操作したユーザーが付く |
| `RATE_LIMIT_AUTH` | ログインの入口（`POST /api/login/…`・`POST /api/setup`）の、IP ごとの 1 分あたりの回数の上限。既定 60。0 なら制限しない。IP の決め方はポリシー（信じるプロキシ）に従う。各ノードのメモリで数える |
| `MAGIC_LINK_MINUTES` | マジックリンク（メールなどで送る1回限りのログインのリンク）の有効期限（分）。既定 15。1〜1440 |
| `SKORIMAKO_RUM_TOKEN` / `SKORIMAKO_RUM_URL` / `SKORIMAKO_RUM_SAMPLE_RATE` | 画面のブラウザの観測（skorimako の RUM）。ログインした後の画面だけで読み込む（ログイン・同意・パスワードの再設定の画面では読まない）。トークンは skorimako の管理の画面で登録したアプリのもの。URL を省略すると `SKORIMAKO_URL` |
| `VAPID_SUBJECT` | プッシュ通知（PWA. パスワードの変更・アカウントのロックなどを本人に知らせる）の連絡先（`mailto:…` か `https://…`。省略すると `PUBLIC_URL`）。VAPID の鍵は初回の起動で作って DB に保存する |
| `OAUTH_CLIENTS` | 兄弟のサービス（skakapo など）が利用者の権限で REST API・MCP を使うための OAuth のクライアント（JSON の配列 `[{"id","secret"（16文字以上）,"redirectUri","name","scopes":["read"]}]`）。渡せるのは `read` だけ（管理の操作はできない）。利用者は個人設定の「API トークン」で連携を確かめ・やめられる |
| `DEV_MODE` | 開発用（`APP_SECRET` を省略できる）。本番では使わない |

ポリシー（パスワード・ロック・多要素認証・セッション・IP 制限・クライアント証明書・表示・監査ログの保存期間）は管理画面の「ポリシー」で変えます。
グループごとの上書きは、グループの画面の「ポリシーの上書き」で設定します。

## エンドポイント

| 用途 | URL |
|---|---|
| OIDC のディスカバリー | `${PUBLIC_URL}/.well-known/openid-configuration` |
| 認可・トークン・UserInfo | `/oauth2/authorize`・`/oauth2/token`・`/oauth2/userinfo` |
| デバイスフロー（RFC 8628） | 開始は `/oauth2/device_authorization`、利用者が開く確認の画面は `/device`、トークンは `/oauth2/token` |
| JWKS・イントロスペクション・失効・ログアウト | `/oauth2/jwks`・`/oauth2/introspect`・`/oauth2/revoke`・`/oauth2/logout` |
| SAML のメタデータ・SSO・ログアウト | `/saml/metadata`・`/saml/sso`・`/saml/slo`（IdP 起点は `/saml/idp/{スラッグ}`） |
| SCIM 2.0 | `/scim/v2`（`Authorization: Bearer <scim スコープのトークン>`） |
| REST API の一覧 | `GET /api/endpoints` |
| MCP | `POST /mcp`（Streamable HTTP） |
| 兄弟のサービスとの連携（OAuth. 認可コード + PKCE（S256）・クライアントの認証は Basic） | `/oauth/authorize`・`/oauth/token`・`/oauth/revoke`（OIDC の `/oauth2/…` とは別。read の API トークンとリフレッシュトークンを発行する） |

MCP の例（Claude Code）:

```bash
claude mcp add --transport http sruru https://id.example.com/mcp --header "Authorization: Bearer sruru_xxxxxxxx"
```

MCP のツール: `get_me`・`search_users`・`get_user`・`create_user`・`update_user`・`set_user_disabled`・`unlock_user`・`reset_password`・
`list_groups`・`get_group_members`・`add_group_member`・`remove_group_member`・`list_applications`・`search_audit_log`、
および画面でできるすべての操作のための `list_api_endpoints`・`call_api`。
