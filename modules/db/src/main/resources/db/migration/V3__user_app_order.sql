-- 利用者ごとのポータルのアプリの並び順（ドラッグで並べ替えたもの. ここにないアプリは後ろに名前の順で並ぶ）
create table user_app_order (
  user_id    uuid primary key references users(id) on delete cascade,
  app_ids    uuid[] not null,
  updated_at timestamptz not null default now()
);
