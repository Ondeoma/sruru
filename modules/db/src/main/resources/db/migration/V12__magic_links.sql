-- マジックリンク（一時トークンによるログイン. 発行は管理者か、許可した OAuth クライアント）
-- email_tokens の purpose に magic を足す（これまでの値: login・reset・verify）
alter table email_tokens add constraint email_tokens_purpose check (purpose in ('login', 'reset', 'verify', 'magic'));
-- マジックリンクの付帯の情報（発行した人・ドメイン・戻り先のアプリと認可の要求の値）. ほかの目的では空
alter table email_tokens add column data jsonb not null default '{}';
-- サービス（OAuth クライアント）にマジックリンクの発行を許すか（既定は許さない）
alter table oidc_clients add column magic_links boolean not null default false;
