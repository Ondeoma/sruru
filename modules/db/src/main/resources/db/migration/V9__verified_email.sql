-- 最後に確認済みだったメールアドレス. 各サービスに渡す（OIDC の email・SAML・SCIM）のは、この値だけ.
-- email を変えても、確認が済むまでは以前の確認済みの値を残す（未確認のアドレスで他人になりすませないように）.
alter table users add column verified_email text;

-- 既存の行: いま確認済みの人は今のアドレス、未確認の人は null
update users set verified_email = email where email_verified and email is not null;

create index users_verified_email on users (lower(verified_email));
