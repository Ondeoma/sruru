-- ドメイン（sruru にアクセスするホスト名）ごとのポリシーの上書き。
-- 既定のホスト名（PUBLIC_URL）は行を持たない。ほかの表の domain 列は、既定のホスト名なら空文字。
create table domains (
  id         uuid primary key,
  host       text not null unique,          -- 小文字の host か host:port
  note       text not null default '',
  policy     jsonb not null default '{}',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- ブラウザのセッション・認可の要求・認可コード・トークンは、作ったときのドメインに結び付ける
-- （緩いポリシーのホスト名で作ったものを、ほかのホスト名に持ち込めないように）
alter table browser_sessions add column domain text not null default '';
alter table auth_requests    add column domain text not null default '';
alter table auth_codes       add column domain text not null default '';
alter table refresh_tokens   add column domain text not null default '';
alter table access_tokens    add column domain text not null default '';
