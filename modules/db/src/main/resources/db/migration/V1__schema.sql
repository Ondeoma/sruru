-- sruru のスキーマ。アプリはステートレスで、セッション・署名鍵・定期処理のリースもすべてここに置く（複数ノードで共有する）。

-- ------------------------------------------------------------------ 設定（ポリシー類。キーごとの JSON）
create table settings (
  key        text primary key,
  value      jsonb not null,
  updated_at timestamptz not null default now()
);

-- ------------------------------------------------------------------ ユーザー・グループ
create table users (
  id                  uuid primary key,
  username            text not null,
  email               text,
  email_verified      boolean not null default false,
  name                text not null,
  given_name          text,
  family_name         text,
  password_hash       text,
  password_changed_at timestamptz,
  must_change_password boolean not null default false,
  is_admin            boolean not null default false,
  is_service          boolean not null default false,   -- サービスアカウント（API・MCP 用。ログインはできない）
  disabled            boolean not null default false,
  locked_until        timestamptz,
  failed_attempts     int not null default 0,
  attributes          jsonb not null default '{}',        -- カスタム属性（attribute_defs）
  avatar              bytea,
  avatar_type         text,
  avatar_updated_at   timestamptz,
  picture_url         text,                               -- 外部の IdP の画像（自分の画像がなければ使う）
  source              text not null default 'local',      -- local | scim | <federation_providers.slug>
  external_id         text,
  locale              text,
  zoneinfo            text,
  phone_number        text,
  created_at          timestamptz not null default now(),
  updated_at          timestamptz not null default now(),
  last_login_at       timestamptz
);
create unique index users_username on users (lower(username));
create index users_email on users (lower(email));
create index users_external on users (source, external_id);

create table password_history (
  user_id    uuid not null references users(id) on delete cascade,
  hash       text not null,
  created_at timestamptz not null default now()
);
create index password_history_user on password_history (user_id, created_at desc);

create table groups (
  id          uuid primary key,
  name        text not null,
  description text not null default '',
  parent_id   uuid references groups(id) on delete set null,   -- 親グループ（子のメンバーは親のメンバーでもある）
  attributes  jsonb not null default '{}',
  is_admin    boolean not null default false,                  -- メンバーをシステム管理者にする
  rule        jsonb,                                           -- 動的なメンバー（属性の条件）。null なら手動のみ
  source      text not null default 'local',
  external_id text,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now(),
  priority    integer not null default 0,                      -- 優先度（表示の上書きが重なったときは大きい方）
  policy      jsonb                                            -- ポリシーの上書き（GroupPolicy. null なら上書きなし）
);
create unique index groups_name on groups (lower(name));
create index groups_external on groups (source, external_id);

create table group_members (
  group_id uuid not null references groups(id) on delete cascade,
  user_id  uuid not null references users(id) on delete cascade,
  added_at timestamptz not null default now(),
  primary key (group_id, user_id)
);
create index group_members_user on group_members (user_id);

-- 動的なメンバー（rule）の結果。ユーザー・グループの変更時に計算し直す
create table group_dynamic_members (
  group_id uuid not null references groups(id) on delete cascade,
  user_id  uuid not null references users(id) on delete cascade,
  primary key (group_id, user_id)
);
create index group_dynamic_members_user on group_dynamic_members (user_id);

-- カスタム属性の定義
create table attribute_defs (
  key           text primary key,
  label         text not null,
  kind          text not null default 'string',   -- string | number | boolean | date | list
  description   text not null default '',
  user_editable boolean not null default false,
  required      boolean not null default false,
  scim_path     text,                              -- SCIM の属性（例 urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department）
  sort          int not null default 0
);

-- ------------------------------------------------------------------ 多要素認証
create table mfa_totp (
  id             uuid primary key,
  user_id        uuid not null references users(id) on delete cascade,
  name           text not null,
  secret_enc     text not null,
  confirmed      boolean not null default false,
  last_used_step bigint not null default 0,
  created_at     timestamptz not null default now()
);
create index mfa_totp_user on mfa_totp (user_id);

create table mfa_recovery_codes (
  user_id   uuid not null references users(id) on delete cascade,
  code_hash bytea not null,
  used_at   timestamptz,
  primary key (user_id, code_hash)
);

-- メールのワンタイムコード・パスワード再設定のリンク・メールアドレスの確認
create table email_tokens (
  id          uuid primary key,
  user_id     uuid not null references users(id) on delete cascade,
  purpose     text not null,        -- login | reset | verify
  token_hash  bytea not null,
  attempts    int not null default 0,
  expires_at  timestamptz not null,
  consumed_at timestamptz,
  created_at  timestamptz not null default now()
);
create index email_tokens_user on email_tokens (user_id, purpose);

-- ------------------------------------------------------------------ ブラウザのセッション（複数アカウント）
create table browser_sessions (
  id          uuid primary key,
  token_hash  bytea not null unique,
  active_user uuid references users(id) on delete set null,
  ip          text,
  user_agent  text,
  created_at  timestamptz not null default now(),
  expires_at  timestamptz not null
);

-- 1つのブラウザでログインしているアカウント（切り替えられる）
create table logins (
  id                 uuid primary key,
  browser_session_id uuid not null references browser_sessions(id) on delete cascade,
  user_id            uuid not null references users(id) on delete cascade,
  auth_time          timestamptz not null,
  amr                text[] not null default '{}',
  ip                 text,
  user_agent         text,
  created_at         timestamptz not null default now(),
  last_seen_at       timestamptz not null default now(),
  expires_at         timestamptz not null,
  unique (browser_session_id, user_id)
);
create index logins_user on logins (user_id);

-- ログインの途中（パスワードの後の多要素認証など）
create table login_flows (
  id                 uuid primary key,
  browser_session_id uuid not null references browser_sessions(id) on delete cascade,
  user_id            uuid references users(id) on delete cascade,
  stage              text not null,             -- identify | mfa | enroll_mfa | change_password | done
  amr                text[] not null default '{}',
  auth_request_id    uuid,
  return_to          text,
  data               jsonb not null default '{}',
  created_at         timestamptz not null default now(),
  expires_at         timestamptz not null
);

-- ------------------------------------------------------------------ アプリケーション（OIDC・OAuth2・SAML）
create table applications (
  id           uuid primary key,
  slug         text not null unique,
  name         text not null,
  description  text not null default '',
  protocol     text not null,                    -- oidc | saml
  enabled      boolean not null default true,
  launch_url   text,
  show_in_portal boolean not null default true,
  icon         bytea,
  icon_type    text,
  icon_updated_at timestamptz,
  require_mfa  boolean not null default false,
  ip_allow     text[] not null default '{}',     -- 空ならどこからでも
  restrict_access boolean not null default false, -- true なら application_groups のメンバーだけ
  created_at   timestamptz not null default now(),
  updated_at   timestamptz not null default now()
);

create table application_groups (
  app_id   uuid not null references applications(id) on delete cascade,
  group_id uuid not null references groups(id) on delete cascade,
  primary key (app_id, group_id)
);

create table oidc_clients (
  app_id                    uuid primary key references applications(id) on delete cascade,
  client_id                 text not null unique,
  secret_hash               bytea,                     -- null なら公開クライアント（PKCE 必須）
  redirect_uris             text[] not null default '{}',
  post_logout_redirect_uris text[] not null default '{}',
  grant_types               text[] not null default '{authorization_code,refresh_token}',
  scopes                    text[] not null default '{openid,profile,email,groups,offline_access}',
  consent                   text not null default 'implicit',   -- implicit | explicit
  sub_mode                  text not null default 'id',         -- id | username | email
  signing_alg               text not null default 'RS256',      -- RS256 | ES256
  access_token_ttl          int not null default 3600,
  id_token_ttl              int not null default 3600,
  refresh_token_ttl         int not null default 2592000,
  include_groups            boolean not null default true,
  backchannel_logout_uri    text
);

create table saml_providers (
  app_id              uuid primary key references applications(id) on delete cascade,
  entity_id           text not null unique,
  acs_url             text not null,
  acs_binding         text not null default 'post',       -- post | redirect
  slo_url             text,
  name_id_format      text not null default 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
  name_id_expr        text not null default '{{user.email}}',
  sign_response       boolean not null default true,
  sign_assertion      boolean not null default true,
  sp_certificate      text,                                -- AuthnRequest の署名の検証用（PEM）
  want_signed_requests boolean not null default false,
  session_ttl         int not null default 28800
);

-- クレーム・SAML 属性の対応（カスタム属性を含む式）
create table attribute_mappings (
  id          uuid primary key,
  app_id      uuid not null references applications(id) on delete cascade,
  name        text not null,              -- クレーム名・SAML の属性名
  expression  text not null,              -- {{user.attributes.department}} など
  scope       text,                       -- OIDC: このスコープのときだけ（null なら常に）
  friendly_name text,                     -- SAML
  multi       boolean not null default false,
  sort        int not null default 0
);
create index attribute_mappings_app on attribute_mappings (app_id);

create table consents (
  user_id    uuid not null references users(id) on delete cascade,
  app_id     uuid not null references applications(id) on delete cascade,
  scopes     text[] not null,
  created_at timestamptz not null default now(),
  primary key (user_id, app_id)
);

-- 認可の要求（ログイン・同意の画面をはさむ間だけ保存する）
create table auth_requests (
  id         uuid primary key,
  app_id     uuid not null references applications(id) on delete cascade,
  protocol   text not null,
  params     jsonb not null,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null
);

create table auth_codes (
  code_hash      bytea primary key,
  app_id         uuid not null references applications(id) on delete cascade,
  user_id        uuid not null references users(id) on delete cascade,
  login_id       uuid,
  redirect_uri   text not null,
  scopes         text[] not null,
  nonce          text,
  code_challenge text,
  challenge_method text,
  auth_time      timestamptz not null,
  amr            text[] not null default '{}',
  expires_at     timestamptz not null,
  used_at        timestamptz
);

create table refresh_tokens (
  id         uuid primary key,
  token_hash bytea not null unique,
  family     uuid not null,                 -- ローテーションの系列（再利用を検出したら系列ごと失効）
  app_id     uuid not null references applications(id) on delete cascade,
  user_id    uuid not null references users(id) on delete cascade,
  login_id   uuid,
  scopes     text[] not null,
  auth_time  timestamptz not null,
  amr        text[] not null default '{}',
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  used_at    timestamptz,
  revoked_at timestamptz
);
create index refresh_tokens_family on refresh_tokens (family);
create index refresh_tokens_user on refresh_tokens (user_id);

-- 発行したアクセストークン（JWT）の失効の確認用
create table access_tokens (
  jti        uuid primary key,
  app_id     uuid references applications(id) on delete cascade,
  user_id    uuid references users(id) on delete cascade,
  login_id   uuid,
  scopes     text[] not null,
  expires_at timestamptz not null,
  revoked_at timestamptz
);
create index access_tokens_user on access_tokens (user_id);

-- 署名鍵（全ノードで共有。秘密鍵は APP_SECRET で暗号化）
create table signing_keys (
  kid         text primary key,
  alg         text not null,                -- RS256 | ES256
  private_enc text not null,
  public_jwk  jsonb not null,
  cert_pem    text,                         -- SAML 用の自己署名証明書（RS256 のみ）
  active      boolean not null default false,
  created_at  timestamptz not null default now(),
  retired_at  timestamptz
);

-- ------------------------------------------------------------------ APIトークン（REST・MCP・SCIM）
create table api_tokens (
  id           uuid primary key,
  user_id      uuid not null references users(id) on delete cascade,
  name         text not null,
  prefix       text not null,
  token_hash   bytea not null unique,
  scopes       text[] not null,               -- read | write | admin | scim
  expires_at   timestamptz,
  last_used_at timestamptz,
  created_at   timestamptz not null default now()
);
create index api_tokens_user on api_tokens (user_id);

-- ------------------------------------------------------------------ 外部の IdP（Google Workspace・Entra ID・汎用 OIDC）
create table federation_providers (
  id                uuid primary key,
  slug              text not null unique,
  kind              text not null,               -- google | entra | oidc
  name              text not null,
  enabled           boolean not null default true,
  issuer            text not null,
  client_id         text not null,
  client_secret_enc text not null,
  scopes            text not null default 'openid profile email',
  subject_claim     text not null default 'sub',  -- Entra は oid（Graph のユーザー ID と同じ）
  jit               boolean not null default true,       -- 初めてのログインでユーザーを作る
  link_by_email     boolean not null default false,      -- 同じメールアドレスのユーザーに結び付ける
  allowed_domains   text[] not null default '{}',
  default_groups    uuid[] not null default '{}',
  trust_mfa         boolean not null default false,      -- 外部での多要素認証を認める（amr に mfa があれば）
  sync_enabled      boolean not null default false,
  sync_config_enc   text,                                -- 同期の設定（サービスアカウントの鍵など。暗号化）
  sync_interval_min int not null default 60,
  last_sync_at      timestamptz,
  last_sync_result  text,
  created_at        timestamptz not null default now()
);

create table federated_identities (
  provider_id   uuid not null references federation_providers(id) on delete cascade,
  subject       text not null,
  user_id       uuid not null references users(id) on delete cascade,
  email         text,
  created_at    timestamptz not null default now(),
  last_login_at timestamptz,
  primary key (provider_id, subject)
);
create index federated_identities_user on federated_identities (user_id);

-- ------------------------------------------------------------------ クライアント証明書
create table cert_authorities (
  id         uuid primary key,
  name       text not null,
  pem        text not null,
  enabled    boolean not null default true,
  created_at timestamptz not null default now()
);

create table user_certificates (
  id          uuid primary key,
  user_id     uuid not null references users(id) on delete cascade,
  fingerprint text not null unique,    -- SHA-256（16進）
  subject     text not null,
  issuer      text not null,
  not_after   timestamptz not null,
  created_at  timestamptz not null default now()
);

-- ------------------------------------------------------------------ 監査ログ（ハッシュの鎖で改ざんを検出できる）
create table audit_log (
  id          bigserial primary key,
  at          timestamptz not null default now(),
  actor_id    uuid,
  actor_name  text,
  via         text not null,           -- web | api | scim | mcp | system | oidc | saml
  action      text not null,
  target_type text,
  target_id   text,
  target_name text,
  ip          text,
  user_agent  text,
  success     boolean not null default true,
  detail      jsonb not null default '{}',
  prev_hash   bytea,
  hash        bytea not null
);
create index audit_log_at on audit_log (at desc);
create index audit_log_actor on audit_log (actor_id, at desc);
create index audit_log_action on audit_log (action, at desc);
create index audit_log_target on audit_log (target_id);

-- ------------------------------------------------------------------ 定期処理・メール・ログインの試行の制限
create table job_lock (
  name       text primary key,
  holder     text not null,
  expires_at timestamptz not null
);

create table mail_outbox (
  id         bigserial primary key,
  to_addr    text not null,
  subject    text not null,
  body       text not null,
  attempts   int not null default 0,
  next_at    timestamptz not null default now(),
  sent_at    timestamptz,
  error      text,
  created_at timestamptz not null default now()
);
create index mail_outbox_pending on mail_outbox (next_at) where sent_at is null;

-- IP アドレスごとのログイン失敗の回数（一定時間の窓）
create table login_throttle (
  key          text primary key,
  failures     int not null,
  window_start timestamptz not null
);

-- ロゴ（全体・グループのブランド）. 参照されなくなったものは掃除で消す
create table brand_logos (
  id           uuid primary key,
  data         bytea not null,
  content_type text not null,
  created_at   timestamptz not null default now()
);
