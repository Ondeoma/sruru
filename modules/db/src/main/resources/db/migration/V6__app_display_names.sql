-- sbirds のサービスに、アプリケーションの表示名（sruru でつけた名前）を ID トークンで知らせる
alter table oidc_clients add column include_app_names boolean not null default false;

-- グループごとのアプリケーションの表示名の上書き（所属するグループのうち優先度の大きいものが使われる）
create table application_group_names (
  app_id   uuid not null references applications(id) on delete cascade,
  group_id uuid not null references groups(id) on delete cascade,
  name     text not null,
  primary key (app_id, group_id)
);
create index application_group_names_group on application_group_names (group_id);

-- グループのポリシーを編集できる人（ユーザーかグループ. 管理者が付与する）
create table group_policy_editors (
  group_id        uuid not null references groups(id) on delete cascade,
  editor_user_id  uuid references users(id) on delete cascade,
  editor_group_id uuid references groups(id) on delete cascade,
  created_at      timestamptz not null default now(),
  check (num_nonnulls(editor_user_id, editor_group_id) = 1)
);
create unique index group_policy_editors_user on group_policy_editors (group_id, editor_user_id) where editor_user_id is not null;
create unique index group_policy_editors_group on group_policy_editors (group_id, editor_group_id) where editor_group_id is not null;
create index group_policy_editors_by_user on group_policy_editors (editor_user_id);
create index group_policy_editors_by_group on group_policy_editors (editor_group_id);
