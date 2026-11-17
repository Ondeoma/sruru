#!/usr/bin/env bash
# 開発用: API を一通り確かめる（scripts/dev-restart.sh で起動したサーバーに対して）。
# 使い方: SETUP_TOKEN=<起動時のログのトークン> scripts/smoke.sh   （管理者がすでにいれば ADMIN_USER / ADMIN_PASS でログインする）
set -euo pipefail
B=${BASE:-http://localhost:9100}
U=${ADMIN_USER:-admin}; P=${ADMIN_PASS:-Smoke-Test-Pass-2026}
J=$(mktemp -d); trap 'rm -rf "$J"' EXIT
C="$J/cookies"
H=(-H 'Content-Type: application/json' -H 'X-Sruru: 1')
ok() { echo "✔ $*"; }
die() { echo "✘ $*"; exit 1; }

# 開発用 DB のログインの試行の記録を消す（繰り返し実行すると、IP アドレスごとの失敗の上限に達するため）
docker compose -f "$(dirname "$0")/../docker-compose.dev.yml" exec -T db psql -q -U sruru -c "delete from login_throttle" >/dev/null 2>&1 || true

if [ -n "${SETUP_TOKEN:-}" ]; then
  curl -sf "${H[@]}" -X POST "$B/api/setup" -d "{\"token\":\"$SETUP_TOKEN\",\"username\":\"$U\",\"name\":\"管理者\",\"email\":\"admin@example.com\",\"password\":\"$P\"}" \
    && ok "最初の管理者を作成"
fi

# ---- ログイン
FLOW=$(curl -sf -c "$C" -b "$C" "${H[@]}" -X POST "$B/api/login/start" -d '{}' | jq -r .id)
ST=$(curl -sf -c "$C" -b "$C" "${H[@]}" -X POST "$B/api/login/password" -d "{\"flowId\":\"$FLOW\",\"username\":\"$U\",\"password\":\"$P\"}" | jq -r .stage)
[ "$ST" = done ] || die "ログイン: stage=$ST"
ok "パスワードでログイン"
# ログインの完了で Cookie の値が変わる（セッションの固定化の対策）
F0=$(curl -sf -c "$J/c4" -b "$J/c4" "${H[@]}" -X POST "$B/api/login/start" -d '{}' | jq -r .id); V0=$(awk '/sruru_session/{print $7}' "$J/c4")
curl -sf -c "$J/c4" -b "$J/c4" "${H[@]}" -X POST "$B/api/login/password" -d "{\"flowId\":\"$F0\",\"username\":\"$U\",\"password\":\"$P\"}" >/dev/null
[ "$V0" != "$(awk '/sruru_session/{print $7}' "$J/c4")" ] && ok "ログインの完了で Cookie を再発行"
code=$( (printf '{"name":"'; head -c 3000000 /dev/zero | tr '\0' 'a'; printf '"}') | curl -s -o /dev/null -w '%{http_code}' -b "$C" "${H[@]}" -X PUT "$B/api/me" --data-binary @-)
[ "$code" = 413 ] && ok "大きすぎる本文は 413"
curl -sf -b "$C" "$B/api/me" | jq -e '.isAdmin == true' >/dev/null && ok "自分の情報（管理者）"

# 間違ったパスワードは 401
code=$(curl -s -o /dev/null -w '%{http_code}' -c "$J/c2" -b "$J/c2" "${H[@]}" -X POST "$B/api/login/password" \
  -d "{\"flowId\":\"$(curl -sf -c "$J/c2" -b "$J/c2" "${H[@]}" -X POST "$B/api/login/start" -d '{}' | jq -r .id)\",\"username\":\"$U\",\"password\":\"wrong\"}")
[ "$code" = 401 ] && ok "誤ったパスワードは 401"

# ---- アプリ（OIDC・機密クライアント）
SLUG="smoke-$RANDOM"
APP=$(curl -sf -b "$C" "${H[@]}" -X POST "$B/api/admin/apps" -d "{\"slug\":\"$SLUG\",\"name\":\"Smoke\",\"protocol\":\"oidc\",
  \"mappings\":[{\"name\":\"dept\",\"expression\":\"{{user.attributes.department | default:\\\"none\\\"}}\"}],
  \"oidc\":{\"clientId\":\"$SLUG\",\"confidential\":true,\"redirectUris\":[\"http://localhost:1/cb\"],\"postLogoutRedirectUris\":[\"http://localhost:1/\"]}}")
SECRET=$(echo "$APP" | jq -r .clientSecret)
[ "$SECRET" != null ] && ok "OIDC アプリを作成（${SLUG}）"

VER=$(python3 -c 'import secrets;print(secrets.token_urlsafe(48))')
CH=$(python3 -c "import hashlib,base64,sys;print(base64.urlsafe_b64encode(hashlib.sha256(sys.argv[1].encode()).digest()).decode().rstrip('='))" "$VER")
LOC=$(curl -s -o /dev/null -w '%{redirect_url}' -b "$C" -c "$C" "$B/oauth2/authorize?response_type=code&client_id=$SLUG&redirect_uri=http://localhost:1/cb&scope=openid%20profile%20email%20groups%20offline_access&state=xyz&nonce=n1&code_challenge=$CH&code_challenge_method=S256")
CODE=$(python3 -c "import urllib.parse,sys;q=urllib.parse.parse_qs(urllib.parse.urlparse(sys.argv[1]).query);print(q['code'][0] if 'code' in q else 'NONE:'+sys.argv[1])" "$LOC")
[[ "$CODE" != NONE* ]] || die "認可コードが出ない: $LOC"
ok "認可コード（state・iss つき）"
TOK=$(curl -sf -u "$SLUG:$SECRET" -X POST "$B/oauth2/token" -d grant_type=authorization_code -d "code=$CODE" -d redirect_uri=http://localhost:1/cb -d "code_verifier=$VER")
AT=$(echo "$TOK" | jq -r .access_token); RT=$(echo "$TOK" | jq -r .refresh_token); IDT=$(echo "$TOK" | jq -r .id_token)
python3 - "$IDT" <<'PY'
import sys,json,base64
p=sys.argv[1].split('.')[1]; p+='='*(-len(p)%4); c=json.loads(base64.urlsafe_b64decode(p))
assert c['nonce']=='n1' and 'groups' in c and c['preferred_username'] and c['dept']=='none', c
print("✔ ID トークンのクレーム", {k:c[k] for k in ('sub','preferred_username','email','groups','amr','dept')})
PY
curl -sf -H "Authorization: Bearer $AT" "$B/oauth2/userinfo" | jq -e '.email == "admin@example.com"' >/dev/null && ok "UserInfo"
curl -sf "$B/oauth2/jwks" | jq -e '.keys | length >= 2' >/dev/null && ok "JWKS"
curl -sf -u "$SLUG:$SECRET" -X POST "$B/oauth2/introspect" -d "token=$AT" | jq -e '.active == true' >/dev/null && ok "イントロスペクション"
RT2=$(curl -sf -u "$SLUG:$SECRET" -X POST "$B/oauth2/token" -d grant_type=refresh_token -d "refresh_token=$RT" | jq -r .refresh_token)
[ -n "$RT2" ] && [ "$RT2" != null ] && ok "リフレッシュ（ローテーション）"
code=$(curl -s -o /dev/null -w '%{http_code}' -u "$SLUG:$SECRET" -X POST "$B/oauth2/token" -d grant_type=refresh_token -d "refresh_token=$RT")
[ "$code" = 400 ] && ok "使用済みのリフレッシュトークンは拒否"
code=$(curl -s -o /dev/null -w '%{http_code}' -u "$SLUG:$SECRET" -X POST "$B/oauth2/token" -d grant_type=refresh_token -d "refresh_token=$RT2")
[ "$code" = 400 ] && ok "再利用の検出で系列ごと失効"
code=$(curl -s -o /dev/null -w '%{http_code}' -u "$SLUG:$SECRET" -X POST "$B/oauth2/token" -d grant_type=authorization_code -d "code=$CODE" -d redirect_uri=http://localhost:1/cb -d "code_verifier=$VER")
[ "$code" = 400 ] && ok "認可コードの再利用は拒否"
curl -sf -u "$SLUG:$SECRET" -X POST "$B/oauth2/revoke" -d "token=$AT" >/dev/null
curl -sf -u "$SLUG:$SECRET" -X POST "$B/oauth2/introspect" -d "token=$AT" | jq -e '.active == false' >/dev/null && ok "失効"

# ---- SAML
curl -sf "$B/saml/metadata" | grep -q IDPSSODescriptor && ok "SAML のメタデータ"

# ---- API トークン・SCIM・MCP
TK=$(curl -sf -b "$C" "${H[@]}" -X POST "$B/api/me/tokens" -d '{"name":"smoke","scopes":["read","write","admin","scim"],"days":1}' | jq -r .token)
SU="scim-$RANDOM"
SID=$(curl -sf -H "Authorization: Bearer $TK" -H 'Content-Type: application/scim+json' -X POST "$B/scim/v2/Users" \
  -d "{\"schemas\":[\"urn:ietf:params:scim:schemas:core:2.0:User\"],\"userName\":\"$SU\",\"name\":{\"givenName\":\"太郎\",\"familyName\":\"山田\"},\"emails\":[{\"value\":\"$SU@example.com\",\"primary\":true}],\"active\":true}" | jq -r .id)
ok "SCIM: ユーザーを作成"
curl -sf -H "Authorization: Bearer $TK" "$B/scim/v2/Users?filter=userName%20eq%20%22$SU%22" | jq -e '.totalResults == 1' >/dev/null && ok "SCIM: フィルター"
curl -sf -H "Authorization: Bearer $TK" -H 'Content-Type: application/scim+json' -X PATCH "$B/scim/v2/Users/$SID" \
  -d '{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":false},{"op":"replace","value":{"name.givenName":"次郎"}}]}' \
  | jq -e '.active == false and .name.givenName == "次郎"' >/dev/null && ok "SCIM: PATCH"
GID=$(curl -sf -H "Authorization: Bearer $TK" -H 'Content-Type: application/scim+json' -X POST "$B/scim/v2/Groups" \
  -d "{\"schemas\":[\"urn:ietf:params:scim:schemas:core:2.0:Group\"],\"displayName\":\"g-$SU\",\"members\":[{\"value\":\"$SID\"}]}" | jq -r .id)
curl -sf -H "Authorization: Bearer $TK" "$B/scim/v2/Groups/$GID" | jq -e '.members | length == 1' >/dev/null && ok "SCIM: グループ"
# ブランド: ロゴとグループのポリシーの上書き
LOGO=$(printf 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=' | base64 -d \
  | curl -sf -b "$C" -H 'X-Sruru: 1' -H 'Content-Type: image/png' --data-binary @- "$B/api/admin/logos" | jq -r .id)
curl -sf -D - -o /dev/null "$B/brand-logos/$LOGO" | grep -qi 'sandbox' && [ "$(curl -sf "$B/brand-logos/$LOGO" | head -c 4 | xxd -p)" = 89504e47 ] \
  && ok "ロゴを上げて配信（画像のまま・CSP の sandbox つき）" || die "ロゴ: $LOGO"
code=$(curl -s -o /dev/null -w '%{http_code}' -b "$C" -H 'X-Sruru: 1' -H 'Content-Type: image/svg+xml' --data '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>' "$B/api/admin/logos")
[ "$code" = 400 ] && ok "スクリプトを含む SVG は拒否" || die "SVG: $code"
curl -sf -b "$C" "${H[@]}" -X PUT "$B/api/admin/groups/$GID" \
  -d "{\"name\":\"g-$SU\",\"priority\":3,\"policy\":{\"password\":{\"minLength\":16},\"branding\":{\"title\":\"smoke-brand\",\"logo\":\"$LOGO\"}}}" \
  | jq -e '.priority == 3 and .policy.password.minLength == 16 and .policy.branding.title == "smoke-brand"' >/dev/null && ok "グループのポリシーの上書きを保存"
code=$(curl -s -o /dev/null -w '%{http_code}' -b "$C" "${H[@]}" -X PUT "$B/api/admin/groups/$GID" -d "{\"name\":\"g-$SU\",\"policy\":{\"password\":{\"minLength\":2}}}")
[ "$code" = 400 ] && ok "不正な上書きは 400" || die "上書きの検証: $code"
curl -sf -H "Authorization: Bearer $TK" -H 'Content-Type: application/json' -X POST "$B/mcp" -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
  | jq -e '.result.tools | length > 10' >/dev/null && ok "MCP: tools/list"
curl -sf -H "Authorization: Bearer $TK" -H 'Content-Type: application/json' -X POST "$B/mcp" \
  -d "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"get_user\",\"arguments\":{\"user\":\"$SU\"}}}" \
  | jq -e '.result.isError == false' >/dev/null && ok "MCP: get_user"
# ポータルの並び順（本人だけ. 逆順に保存して戻す）
IDS=$(curl -sf -b "$C" "$B/api/me/apps" | jq -c '[.[].id]')
if [ "$(echo "$IDS" | jq length)" -ge 2 ]; then
  curl -sf -b "$C" "${H[@]}" -X PUT "$B/api/me/apps/order" -d "{\"appIds\":$(echo "$IDS" | jq -c reverse)}" >/dev/null
  [ "$(curl -sf -b "$C" "$B/api/me/apps" | jq -c '[.[].id]')" = "$(echo "$IDS" | jq -c reverse)" ] && ok "ポータルの並び順を保存" || die "並び順"
  curl -sf -b "$C" "${H[@]}" -X DELETE "$B/api/me/apps/order" >/dev/null
fi
# 漏れたトークンでアカウントを乗っ取れない・SCIM で管理者を変えられない
code=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TK" -X POST "$B/api/me/recovery-codes")
[ "$code" = 403 ] && ok "トークンでは回復コードを作れない" || die "回復コード: $code"
AID=$(curl -sf -H "Authorization: Bearer $TK" "$B/api/me" | jq -r .id)
code=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TK" -H 'Content-Type: application/scim+json' -X PATCH "$B/scim/v2/Users/$AID" \
  -d '{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":false}]}')
[ "$code" = 403 ] && ok "SCIM では管理者を変更できない" || die "SCIM の管理者: $code"
code=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TK" -H 'Content-Type: application/json' -X POST "$B/api/admin/users/$AID/password" -d '{"sendResetMail":false,"mustChange":false}')
[ "$code" = 403 ] && ok "admin のトークンでもパスワードは設定できない" || die "admin トークンでのパスワード: $code"
DEEP=$(python3 -c 'import urllib.parse; print(urllib.parse.quote("("*100 + "userName eq \"x\"" + ")"*100))')
code=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TK" "$B/scim/v2/Users?filter=$DEEP")
[ "$code" = 400 ] && ok "SCIM: 深すぎるフィルターは 400" || die "深いフィルター: $code"
# id_token_hint のない GET のログアウトは確認を挟む（ログインはそのまま）
curl -sf -b "$C" "$B/oauth2/logout" | grep -q 'ログアウトしますか' && curl -sf -b "$C" "$B/api/me" >/dev/null && ok "ヒントのないログアウトは確認を挟む"


# ---- 多要素認証（TOTP）とアカウントのロック
totp() { python3 -c '
import hmac,hashlib,struct,time,base64,sys
k=base64.b32decode(sys.argv[1]+"="*(-len(sys.argv[1])%8)); t=int(time.time())//30+int(sys.argv[2])
h=hmac.new(k,struct.pack(">Q",t),hashlib.sha1).digest(); o=h[-1]&15
print("%06d"%((struct.unpack(">I",h[o:o+4])[0]&0x7fffffff)%1000000))' "$1" "${2:-0}"; }
MU="mfa-$RANDOM"; MP="Mfa-User-Pass-2026x"
curl -sf -b "$C" "${H[@]}" -X POST "$B/api/admin/users" -d "{\"username\":\"$MU\",\"name\":\"MFA\",\"email\":\"$MU@example.com\",\"password\":\"$MP\"}" >/dev/null
C3="$J/c3"
login_pw() { local f; f=$(curl -sf -c "$C3" -b "$C3" "${H[@]}" -X POST "$B/api/login/start" -d '{}' | jq -r .id)
  curl -s -c "$C3" -b "$C3" "${H[@]}" -X POST "$B/api/login/password" -d "{\"flowId\":\"$f\",\"username\":\"$MU\",\"password\":\"$1\"}"; }
login_pw "$MP" | jq -e '.stage == "done"' >/dev/null
SETUP=$(curl -sf -b "$C3" "${H[@]}" -X POST "$B/api/me/totp")
DEV=$(echo "$SETUP" | jq -r .id); SEC=$(echo "$SETUP" | jq -r .secret)
curl -sf -b "$C3" "${H[@]}" -X POST "$B/api/me/totp/verify" -d "{\"id\":\"$DEV\",\"code\":\"$(totp "$SEC" -1)\"}" | jq -e '.codes | length == 10' >/dev/null && ok "TOTP の登録と回復コード"
R=$(login_pw "$MP"); [ "$(echo "$R" | jq -r .stage)" = mfa ] && ok "パスワードの後に2つ目の要素を求める"
F2=$(echo "$R" | jq -r .id)
curl -sf -c "$C3" -b "$C3" "${H[@]}" -X POST "$B/api/login/mfa" -d "{\"flowId\":\"$F2\",\"method\":\"totp\",\"code\":\"$(totp "$SEC")\"}" \
  | jq -e '.stage == "done"' >/dev/null && ok "TOTP でログイン"
curl -sf -b "$C3" "$B/api/me/sessions" | jq -e 'map(select(.amr | index("mfa"))) | length >= 1' >/dev/null && ok "amr に mfa"
for i in 1 2 3 4 5; do login_pw "bad-$i" >/dev/null; done
login_pw "$MP" | jq -e '.error | contains("ロック")' >/dev/null && ok "5回の失敗でロック"
UID2=$(curl -sf -b "$C" "$B/api/admin/users?q=$MU" | jq -r '.users[0].id')
curl -sf -b "$C" "${H[@]}" -X POST "$B/api/admin/users/$UID2/unlock" >/dev/null
login_pw "$MP" | jq -e '.stage == "mfa"' >/dev/null && ok "管理者がロックを解除"

# ---- アカウントの切り替え（同じブラウザに2人目を追加）
F3=$(curl -sf -c "$C" -b "$C" "${H[@]}" -X POST "$B/api/login/start" -d '{"add":true}' | jq -r .id)
SU2="sw-$RANDOM"; curl -sf -b "$C" "${H[@]}" -X POST "$B/api/admin/users" -d "{\"username\":\"$SU2\",\"name\":\"切替\",\"password\":\"$MP\"}" >/dev/null
curl -sf -c "$C" -b "$C" "${H[@]}" -X POST "$B/api/login/password" -d "{\"flowId\":\"$F3\",\"username\":\"$SU2\",\"password\":\"$MP\"}" >/dev/null
curl -sf -b "$C" "$B/api/accounts" | jq -e 'length == 2' >/dev/null && ok "2つのアカウントでログイン"
ADM=$(curl -sf -b "$C" "$B/api/accounts" | jq -r ".[] | select(.username == \"$U\") | .userId")
curl -sf -b "$C" "${H[@]}" -X POST "$B/api/accounts/switch" -d "{\"userId\":\"$ADM\"}"
curl -sf -b "$C" "$B/api/me" | jq -e ".username == \"$U\"" >/dev/null && ok "アカウントの切り替え"

# ---- SAML の SSO（SP 起点・HTTP-Redirect）
SP="https://sp-$RANDOM.example.com"
curl -sf -b "$C" "${H[@]}" -X POST "$B/api/admin/apps" -d "{\"slug\":\"saml-$RANDOM\",\"name\":\"SAML SP\",\"protocol\":\"saml\",
  \"saml\":{\"entityId\":\"$SP\",\"acsUrl\":\"$SP/acs\"},\"mappings\":[{\"name\":\"mail\",\"expression\":\"{{user.email}}\"}]}" >/dev/null
REQ=$(python3 - "$SP" <<'PY2'
import zlib,base64,urllib.parse,sys,uuid,datetime
sp=sys.argv[1]
x=f'<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_{uuid.uuid4().hex}" Version="2.0" IssueInstant="{datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")}" AssertionConsumerServiceURL="{sp}/acs" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"><saml:Issuer>{sp}</saml:Issuer></samlp:AuthnRequest>'
c=zlib.compressobj(9,zlib.DEFLATED,-15); d=c.compress(x.encode())+c.flush()
print(urllib.parse.quote(base64.b64encode(d).decode()))
PY2
)
curl -sf -b "$C" "$B/saml/sso?SAMLRequest=$REQ&RelayState=rs1" > "$J/saml.html"
python3 - "$J/saml.html" <<'PY2'
import re,base64,sys,html
s=open(sys.argv[1]).read()
v=html.unescape(re.search(r'name="SAMLResponse" value="([^"]+)"',s).group(1))
x=base64.b64decode(v).decode()
assert 'StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"' in x and 'admin@example.com' in x and 'ds:Signature' in x, x[:500]
assert 'value="rs1"' in s
print("✔ SAML の応答（署名・NameID・属性・RelayState）")
PY2

# ---- 監査ログ
curl -sf -b "$C" -X POST "${H[@]}" "$B/api/admin/audit/verify" | jq -e '.brokenAt == null' >/dev/null && ok "監査ログのハッシュの鎖"
echo "すべて成功"
