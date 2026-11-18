-- 兄弟のサービス（skakapo など）への OAuth（認可コード + PKCE）. クライアントは環境変数 OAUTH_CLIENTS で登録する.
-- OIDC（/oauth2/*. applications に登録したアプリ）とは別. 渡せるのは read だけ.

-- 認可コード（60秒・1回だけ）
create table oauth_codes (
  code_hash      bytea primary key,
  client_id      text not null,
  user_id        uuid not null references users(id) on delete cascade,
  redirect_uri   text not null,
  code_challenge text not null,
  scopes         text[] not null,
  expires_at     timestamptz not null
);

-- 連携（利用者 × クライアントで1つ）. アクセストークンは API トークン（api_tokens）として発行し、
-- そのトークンを消すと連携も消える（API トークンの画面・管理画面から取り消せる）
create table oauth_grants (
  id                uuid primary key,
  user_id           uuid not null references users(id) on delete cascade,
  client_id         text not null,
  scopes            text[] not null,
  refresh_hash      bytea not null unique,
  prev_refresh_hash bytea,                    -- 1つ前のリフレッシュトークン（再利用されたら盗まれたとみて連携ごと消す）
  token_id          uuid not null unique references api_tokens(id) on delete cascade,
  created_at        timestamptz not null default now(),
  refreshed_at      timestamptz,
  expires_at        timestamptz not null,     -- リフレッシュトークンの期限（使うたびに延びる）
  unique (user_id, client_id)
);
create index oauth_grants_prev on oauth_grants (prev_refresh_hash);
