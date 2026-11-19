-- グループごとのアプリケーションのロゴの上書き（brand_logos の ID）. 名前だけ・ロゴだけの上書きもできるよう、名前は空を許す
alter table application_group_names add column logo text;
alter table application_group_names alter column name drop not null;
