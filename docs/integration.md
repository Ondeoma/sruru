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
