-- 親グループを複数にする（子のメンバーは、すべての親のメンバーでもある）
create table group_parents (
  group_id  uuid not null references groups(id) on delete cascade,
  parent_id uuid not null references groups(id) on delete cascade,
  primary key (group_id, parent_id),
  check (group_id <> parent_id)
);
create index group_parents_parent on group_parents (parent_id);

insert into group_parents (group_id, parent_id) select id, parent_id from groups where parent_id is not null;
alter table groups drop column parent_id;
