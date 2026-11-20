-- ログアウト・期限切れのたびに、ログインに結び付いたトークンを失効させる（TokenStore.revokeLogin）ための索引
create index if not exists refresh_tokens_login on refresh_tokens (login_id) where login_id is not null;
create index if not exists access_tokens_login on access_tokens (login_id) where login_id is not null;
-- パスワードの再設定・メールの確認のリンクは、トークンのハッシュで探す（FactorStore.emailTokenByHash）
create index if not exists email_tokens_hash on email_tokens (token_hash);
