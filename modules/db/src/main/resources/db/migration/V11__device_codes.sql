-- デバイスフロー（RFC 8628. Device Authorization Grant）の要求。
-- 端末（CLI・テレビなど）が device_code で結果を取りに来て、利用者はブラウザで user_code を入力して許可する。
create table device_codes (
  id               uuid primary key,
  device_code_hash bytea not null unique,       -- device_code は SHA-256 で保存する（認可コード・トークンと同じ）
  user_code        text not null unique,        -- 利用者が打ち込むコード（8文字。ハイフンなし・大文字）
  app_id           uuid not null references applications(id) on delete cascade,
  scopes           text[] not null,
  domain           text not null default '',    -- 要求を受けたドメイン（既定のホスト名なら空）。確認もトークンの発行も同じドメインでだけ
  interval_seconds int not null,                -- ポーリングの間隔。早すぎるポーリング（slow_down）のたびに 5 秒延びる
  last_poll_at     timestamptz,
  status           text not null default 'pending' check (status in ('pending', 'approved', 'denied')),
  user_id          uuid references users(id) on delete cascade,   -- 許可・拒否した利用者
  login_id         uuid,                        -- 許可したときのログイン（offline_access でなければ、トークンをこのログインに結び付ける）
  auth_time        timestamptz,
  amr              text[] not null default '{}',
  created_at       timestamptz not null default now(),
  expires_at       timestamptz not null,
  used_at          timestamptz                  -- トークンを発行した日時（device_code は1回だけ使える）
);
create index device_codes_app_idx on device_codes (app_id, expires_at);
create index device_codes_expires_idx on device_codes (expires_at);
