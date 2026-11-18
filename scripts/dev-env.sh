# 開発用の環境変数（source scripts/dev-env.sh）。docker-compose.dev.yml の DB・Mailpit を使う
export DATABASE_URL=jdbc:postgresql://localhost:54360/sruru DATABASE_USER=sruru DATABASE_PASSWORD=sruru
export PUBLIC_URL=http://localhost:9100 HTTP_PORT=9100
export DEV_MODE=true
export SMTP_HOST=localhost SMTP_PORT=1031 SMTP_TLS=none MAIL_FROM=sruru@example.com
export NODE_ID=dev1
export STATIC_DIR=${STATIC_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)/frontend/dist}   # ビルド済みの画面（npm run build）
# OAuth で連携する兄弟のサービス（渡せるのは read だけ）
export OAUTH_CLIENTS='[{"id":"skakapo","secret":"skakapo-dev-secret-0123456789","redirectUri":"http://localhost:5199/api/connections/callback","name":"skakapo","scopes":["read"]}]'
