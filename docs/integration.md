# アプリケーションとの連携

## OIDC でログインする Web アプリ

OIDC（認可コード + PKCE + nonce. ID トークンの署名は JWKS で検証）でログインし、`groups` クレームを所属グループとして使うアプリの例です。
sruru 側は次のように登録します（管理画面 →「アプリケーション」→「OIDC / OAuth2」）。

| 項目 | 値 |
|---|---|
| スラッグ・クライアント ID | 例 `myapp` |
| クライアントの種類 | 機密（シークレットあり）。作成時に表示されるシークレットを控える |
| リダイレクト URI | `https://<サービスの PUBLIC_URL>/auth/callback` |
| ログアウト後の URI | `https://<サービスの PUBLIC_URL>/`（リダイレクト URI と同じオリジンの URL は、登録しなくても戻せる） |
| スコープ | `openid profile email groups`（`groups` を外しても、「グループを ID トークンに含める」がオンなら `groups` クレームは入る） |
| 起動の URL | `https://<サービスの PUBLIC_URL>/`（ポータルに出す） |

`email` クレームに入るのは、確認済みのメールアドレスだけです（入るときは `email_verified` は常に `true`）。
本人がアドレスを変えても、確認が済むまでは以前の確認済みのアドレスが入ります。確認済みのアドレスがないユーザーでは、
`email` も `email_verified` も入りません。アプリ側は `email` がないログインを扱えるようにし、本人の特定には `sub` を使ってください。

アプリ側の設定の例（環境変数の名前はアプリによって違います）:

```bash
OIDC_ISSUER=https://id.example.com          # sruru の PUBLIC_URL（末尾の / なし）
OIDC_CLIENT_ID=myapp
OIDC_CLIENT_SECRET=<作成時に表示されたシークレット>
OIDC_GROUPS_CLAIM=groups                    # 既定のまま
ADMIN_GROUPS=myapp-admins                   # sruru のグループ名
```

- 利用者のアイコンは `picture` クレーム（`https://id.example.com/avatars/<ユーザー ID>`. 版は付けない決まった URL）で渡ります。画像は認証なしで読めます。
  アイコンがまだ無い人にも同じ URL を渡すので、アプリがログインしたときの URL を持ち続けても、sruru で登録・変更すると数分（キャッシュは5分）で新しい画像に変わります。
  自分の画像が無いときは、外部 IdP・Gravatar の画像があればそこへ転送し、なければ 404 を返します（アプリは画像の読み込みに失敗したら名前の1文字目を出すこと）。
- アプリのログアウトで sruru からもログアウトさせるには、アプリが `end_session_endpoint` を使います。
  バックチャネルのログアウトに対応したアプリなら、「バックチャネルのログアウトの URI」も登録します。
- 特定のグループだけに使わせるときは、アプリの「利用できるグループを制限する」をオンにして、グループを選びます。
- 多要素認証を必須にするときは、アプリの「多要素認証を必須にする」をオンにします（済んでいなければログインの途中で求めます）。

## ネイティブアプリ（iOS・Android・デスクトップ・CLI）

ネイティブアプリは、シークレットを隠し持てないので**公開クライアント**（「シークレットを使う」をオフ）として登録し、
**システムのブラウザ**で認可コード + PKCE（S256）のログインをします（RFC 8252）。ブラウザや入力の手段がない環境では、デバイスフロー（RFC 8628）を使います。

- **アプリの中の WebView は使わないでください。** アプリが入力中のパスワードや Cookie を読めてしまい、ブラウザに残っているログイン（シングルサインオン）・
  パスワードマネージャー・パスキーも使えません。必ずシステムのブラウザ（下の表の方式）で開きます。
- 公開クライアントには PKCE が必須です（`code_challenge` のない要求は断ります）。`state` と、`openid` を使うなら `nonce` も付けてください。
- ログアウトしても使い続けるアプリ（常駐するもの・CLI）は、スコープに `offline_access` を足します。足さなければ、リフレッシュトークンは
  ブラウザのログインに結び付き、利用者がブラウザでログアウトしたとき・ログインの期限が切れたときに失効します。
- リフレッシュトークンは使うたびに新しい値に替わります。古い値をもう一度使うと、系列ごと失効します（アプリは、常に最後に受け取った値を保存する）。
- トークンは、OS の安全な保管場所（iOS・macOS のキーチェーン、Android の Keystore、Windows の資格情報マネージャー、Linux の Secret Service）に置きます。

| 環境 | 開き方 | sruru に登録するリダイレクト URI | 方式（grant type） |
|---|---|---|---|
| iOS | `ASWebAuthenticationSession`（AppAuth-iOS など） | カスタムスキーム `com.example.app:/callback`、または Universal Links `https://app.example.com/callback` | 認可コード・リフレッシュトークン |
| Android | Custom Tabs（AppAuth-Android など） | カスタムスキーム `com.example.app:/callback`、または App Links `https://app.example.com/callback` | 認可コード・リフレッシュトークン |
| デスクトップ（Windows・macOS・Linux） | 既定のブラウザを開き、アプリは `127.0.0.1` の空いているポートで待ち受ける | `http://127.0.0.1/callback`（IPv6 なら `http://[::1]/callback`） | 認可コード・リフレッシュトークン |
| CLI（ブラウザを開ける） | デスクトップと同じ | `http://127.0.0.1/callback` | 認可コード・リフレッシュトークン |
| CLI（SSH の先・コンテナの中など、ブラウザを開けない）・テレビなどの端末 | 利用者が別の機器のブラウザで `https://id.example.com/device` を開く | 不要（空のまま登録できる） | デバイスコード・リフレッシュトークン |

リダイレクト URI の決まり:

- **カスタムスキーム**は、自分のドメインを逆にした名前にします（`com.example.app:/callback`。ほかのアプリと重ならないように。RFC 8252 7.1）。
  登録した文字列との完全一致で確かめます。ほかのアプリが同じスキームを名乗れる OS があるので、できれば Universal Links・App Links（`https://…`。こちらも完全一致）を使ってください。
- **ループバック**は `http://127.0.0.1/…` か `http://[::1]/…` で登録します。公開クライアントに限り、認可の要求の `redirect_uri` は**ポートだけ違ってよい**ので
  （RFC 8252 7.3）、アプリは OS から空いているポートをもらい、`http://127.0.0.1:51234/callback` のように指定します。スキーム・ホスト・パス・クエリは
  登録と同じにします。トークンの交換の `redirect_uri` には、認可の要求と同じ値（ポートまで）を送ります。
  `http://localhost/…` も登録できますが、ポートまで完全一致です（RFC 8252 8.3 が `localhost` を勧めていないため。名前の解決をほかに向けられることがある）。
- ログアウト後の URI（`post_logout_redirect_uri`）も、登録したループバックの URI とポートだけ違うものを受け付けます（公開クライアントだけ。パスは完全一致）。

### デスクトップ・CLI（ループバック）

```bash
# 1. アプリが 127.0.0.1 の空いているポート（例 51234）で待ち受け、code_verifier・state を作って、既定のブラウザで開く
https://id.example.com/oauth2/authorize?response_type=code&client_id=mycli&scope=openid%20profile%20offline_access
  &redirect_uri=http%3A%2F%2F127.0.0.1%3A51234%2Fcallback&state=<乱数>&code_challenge=<S256>&code_challenge_method=S256
# 2. ログインの後、ブラウザが http://127.0.0.1:51234/callback?code=…&state=…&iss=… に戻る（state と iss を確かめる）
# 3. コードをトークンに替える（シークレットは送らない）
curl -s https://id.example.com/oauth2/token -d grant_type=authorization_code -d client_id=mycli \
  -d code=<コード> -d redirect_uri=http://127.0.0.1:51234/callback -d code_verifier=<verifier>
```

### デバイスフロー（ブラウザを開けない CLI・端末）

アプリケーションの「使う方式」で「デバイスコード」を選んだクライアントだけが使えます。

```bash
# 1. 端末が開始する（公開クライアントは client_id だけ。機密クライアントはトークンのエンドポイントと同じ認証）
curl -s https://id.example.com/oauth2/device_authorization -d client_id=mycli --data-urlencode 'scope=openid profile offline_access'
# → {"device_code":"…","user_code":"BCDF-GHJK","verification_uri":"https://id.example.com/device",
#    "verification_uri_complete":"https://id.example.com/device?user_code=BCDF-GHJK","expires_in":600,"interval":5}
# 2. 端末は verification_uri と user_code を表示する（QR コードにするなら verification_uri_complete）
# 3. interval 秒ごとにトークンのエンドポイントに尋ねる
curl -s https://id.example.com/oauth2/token -d grant_type=urn:ietf:params:oauth:grant-type:device_code \
  -d client_id=mycli -d device_code=<device_code>
```

- 利用者は、手元の機器のブラウザで `verification_uri` を開き、ログインして（多要素認証・IP 制限・利用できるグループの制限は通常のログインと同じ）、
  コードを入力し、アプリの名前と求めているスコープを確かめて「許可」か「拒否」を選びます。コード付きの URL で開いても、この確認は必ず出ます。
- 3 の応答: 許可を待っている間は `authorization_pending`、間隔より早く尋ねると `slow_down`（以後の間隔を 5 秒延ばすこと）、
  拒否されたら `access_denied`、期限（10 分）が切れたら `expired_token`。どれも HTTP 400 で、`error` に入ります。許可されたらトークンが返ります。
- `device_code` は 1 回だけ使えます（トークンを受け取った後にもう一度使うと、そのとき出したトークンも失効します）。
- `/oauth2/device_authorization` が HTTP 429（`temporarily_unavailable`）を返したら、確認待ちの要求が上限
  （クライアントごとに 500 件・全体で 5000 件）に達しています。`Retry-After` の秒数を待ってからやり直してください。
- 利用者には「自分で操作している端末のコードだけを入力する」よう案内してください（他人から送られたコードを入力させるフィッシングがあるため）。
- 複数のホスト名（ドメイン）で使うとき: `verification_uri` は、端末が開始の要求を送ったホスト名のものです。確認もトークンの取得も、同じホスト名で行います。

## カスタム属性をクレームにする

管理画面の「属性」で属性を定義し（例 `department`）、アプリの「クレーム・属性の対応」に行を足します。

| 名前 | 式 | スコープ |
|---|---|---|
| `department` | `{{user.attributes.department}}` | `profile` |
| `roles` | `{{user.groups \| filter_prefix:"myapp-" \| strip_prefix:"myapp-"}}` | （空 = 常に） |
| `display` | `{{user.family_name}} {{user.given_name}}` | |

使える値: `user.id`・`username`・`email`・`email_verified`・`name`・`given_name`・`family_name`・`picture`・`locale`・`zoneinfo`・
`phone_number`・`is_admin`・`source`・`external_id`・`groups`・`group_ids`・`attributes.<キー>`、`app.slug`・`app.name`。
フィルター: `lower`・`upper`・`trim`・`default:"値"`・`join:","`・`split:","`・`first`・`last`・`filter_prefix:"p"`・`strip_prefix:"p"`・
`replace:"a":"b"`・`prepend:"p"`・`append:"s"`・`unique`・`email_local`・`email_domain`・`string`・`bool`。
`user.email` は確認済みのメールアドレスです（確認待ちの間は以前の確認済みのアドレス。なければ空で、`email_verified` は `false`）。
アプリの画面の「試す」で、ユーザーを選んで実際に渡す値を確かめられます。

## SAML の SP

1. SP のメタデータ（XML）があれば、アプリの作成の画面に貼り付けて読み込みます（エンティティ ID・ACS・証明書が入る）。
2. NameID の式（既定 `{{user.email}}`）と形式を選びます。永続的な ID にするなら `{{user.id}}` と `persistent`。
   `user.email` は確認済みのアドレスだけなので、確認済みのアドレスがないユーザーは NameID が空になります（メールアドレスを確認してもらうか、`{{user.id}}` を使う）。
3. SP には sruru のメタデータ `https://id.example.com/saml/metadata` を登録します（SSO の URL `…/saml/sso`、証明書を含む）。
4. 対応がなければ `email`・`name`・`username`・`givenName`・`surname`・`groups` の属性を送ります。

## 複数のホスト名（ドメイン）で使う

管理画面の「ドメイン」でホスト名を登録すると、同じ sruru をそのホスト名でも公開でき、ホスト名ごとにポリシーと表示を変えられます
（DNS とリバースプロキシは別に設定します。リバースプロキシは `Host` か `X-Forwarded-Host` をそのまま渡します）。

- 各ホスト名は自分の issuer・エンティティ ID を持ちます（`https://<ホスト名>/.well-known/openid-configuration`・`https://<ホスト名>/saml/metadata`）。
  サービスには、使いたいポリシーのホスト名の URL を設定します。クライアント ID・シークレット・署名鍵は全ホスト名で共通です。
- ログイン（Cookie）とトークンはホスト名ごとです。あるホスト名で出した認可コード・トークンは、ほかのホスト名では使えません。
- 外部 IdP をそのホスト名からも使うなら、`https://<ホスト名>/auth/fed/<スラッグ>/callback` も外部 IdP に登録します。

## SCIM で外部から同期する

1. 管理者で API トークンを作ります（スコープ `scim`）。サービスアカウント（管理画面でユーザーを「サービスアカウント」として作り、管理者にする）に発行するのがおすすめです。
2. 送り手（Entra ID のエンタープライズアプリのプロビジョニングなど）に、テナントの URL `https://id.example.com/scim/v2` とトークンを設定します。
3. Enterprise User 拡張の属性（`department` など）は、属性の定義の「SCIM のパス」に
   `urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department` のように書くと、カスタム属性に入ります。

## Google Workspace / Microsoft Entra ID

管理画面の「外部 IdP」で追加します。表示されるコールバック URL（`https://id.example.com/auth/fed/<スラッグ>/callback`）を、
Google Cloud の OAuth クライアント・Entra のアプリの登録のリダイレクト URI に登録します。

- **ログイン**: 許可するドメイン（Google は Workspace のドメイン（hd）、Entra はテナント ID。Entra のメールアドレスは、ここに書いたテナントのときだけ信頼します）、初めてのログインでのユーザーの作成、
  同じメールアドレスのユーザーへの結び付け、外部での多要素認証を認めるか、を選べます。
- **ディレクトリの同期**:
  - Google: ドメイン全体の委任を許可したサービスアカウントの JSON 鍵と、管理者のメールアドレス。
    スコープ `admin.directory.user.readonly`・`admin.directory.group.readonly`・`admin.directory.group.member.readonly`。
  - Entra: アプリの登録のテナント ID・クライアント ID・シークレット。Graph のアプリケーションの権限 `User.Read.All`・`GroupMember.Read.All`。
  - 同期したユーザーは外部の IdP でのログインと自動で結び付きます（Google の sub、Entra の oid がディレクトリの ID と同じ）。
    ディレクトリから消えたユーザーは無効に、消えたグループは削除します。
