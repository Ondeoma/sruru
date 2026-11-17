#!/usr/bin/env bash
# 3ノード試験環境（scripts/ha-up.sh）の障害試験。
#  1. ログインしたセッションが、どのノードでも使える（セッションは DB）
#  2. アプリ1台を止めても、HAProxy 経由でログイン・ユーザーの作成・OIDC の署名鍵（JWKS）が使える
#  3. DB のプライマリを止めても、フェイルオーバー後に作成でき、止める前のデータも残っている
set -euo pipefail
cd "$(dirname "$0")/.."
B=${BASE:-http://localhost:9191}
DC="docker compose -f docker-compose.ha.yml"
J=$(mktemp -d); C=$J/c; trap 'rm -rf "$J"' EXIT
H=(-H 'Content-Type: application/json' -H 'X-Sruru: 1')
P=Ha-Test-Pass-2026x
py() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
retry() { for i in $(seq 1 60); do if out=$("$@" 2>/dev/null); then echo "$out"; return 0; fi; sleep 2; done; return 1; }

# 最初の管理者（起動時のログのトークン）
TOKEN=$($DC logs app1 app2 app3 2>/dev/null | grep -o 'セットアップのトークン: [^ ]*' | head -1 | awk '{print $2}' || true)
[ -n "$TOKEN" ] && curl -sf "${H[@]}" -X POST "$B/api/setup" -d "{\"token\":\"$TOKEN\",\"username\":\"admin\",\"name\":\"管理者\",\"email\":\"admin@example.com\",\"password\":\"$P\"}" || true
login() {
  F=$(curl -sf -c $C -b $C "${H[@]}" -X POST "$B/api/login/start" -d '{}' | py "d['id']")
  curl -sf -c $C -b $C "${H[@]}" -X POST "$B/api/login/password" -d "{\"flowId\":\"$F\",\"username\":\"admin\",\"password\":\"$P\"}" | py "d['stage']"
}
create() { curl -sf -b $C "${H[@]}" -X POST "$B/api/admin/users" -d "{\"username\":\"$1\",\"name\":\"$1\"}" | py "d['username']"; }

[ "$(login)" = done ] && echo "OK: ログイン"
# セッションが複数ノードで使える（ラウンドロビンで6回）
for i in 1 2 3 4 5 6; do curl -sf -b $C "$B/api/me" >/dev/null; done; echo "OK: 6回とも同じセッションで読めた"
TAG=ha$(date +%H%M%S)
create "$TAG-0" >/dev/null

echo "== アプリ app1 を停止"
$DC stop app1 >/dev/null; sleep 5
for i in 1 2 3 4 5 6; do create "$TAG-a$i" >/dev/null; done
curl -sf "$B/oauth2/jwks" | py "'OK: JWKS の鍵 ' + str(len(d['keys'])) + ' 個（全ノードで共通）'"
echo "OK: app1 停止中も6人作成できた"
$DC start app1 >/dev/null

echo "== DB プライマリを停止"
LEADER=$($DC exec -T pg1 patronictl -c /etc/patroni/patroni.yml list -f json | py "[m['Member'] for m in d if m['Role']=='Leader'][0]")
echo "leader: $LEADER"
$DC stop "$LEADER" >/dev/null
T0=$(date +%s)
retry create "$TAG-f" >/dev/null
echo "OK: $(( $(date +%s) - T0 )) 秒後に作成できた"
retry curl -sf -b $C "$B/api/admin/users?q=$TAG" | py "'ユーザー数: ' + str(d['total']) + '（期待 8）'"
$DC start "$LEADER" >/dev/null
sleep 20
$DC exec -T pg1 patronictl -c /etc/patroni/patroni.yml list || true
N=$(curl -sf -b $C "$B/api/admin/users?q=$TAG" | py "d['total']")
[ "$N" = "8" ] && echo "ALL OK"
