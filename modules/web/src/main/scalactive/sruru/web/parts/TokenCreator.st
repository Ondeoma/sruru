<script lang="scala">
import sruru.shared.*
import sruru.web.*


// API トークンを作るフォームと、作ったトークンの表示（この1回だけ）. url は作成の API（自分用・管理者がほかのユーザー用に）.
case class Props(url: String, allowAdmin: Boolean, onCreated: Unit => Unit = _ => ())

case class State(name: RV[String] = RV(""),
                 scopes: RV[List[String]] = RV(List(TokenScopes.Read)),
                 days: RV[String] = RV("90"),
                 created: RV[Option[String]] = RV(None),
                 error: RV[String] = RV(""),
                 busy: RV[Boolean] = RV(false))

def initState() = State()

def create(s: State, props: Props): Unit =
  if (s.name.v.trim.isEmpty) s.error := "用途を入力してください"
  else if (s.scopes.v.isEmpty) s.error := "スコープを1つ以上選んでください"
  else Store.inline(Api.post[CreatedTokenDto](props.url, Api.json(TokenReq(s.name.v.trim, s.scopes.v, s.days.v.toIntOption))), s.error, s.busy) { r =>
    s.created := Some(r.token)
    s.name := ""
    props.onCreated(())
  }

def scopeList(props: Props): List[String] =
  if (props.allowAdmin) TokenScopes.all else TokenScopes.all.filterNot(x => x == TokenScopes.Admin || x == TokenScopes.Scim)

def mcpCommand(s: State) = s.created.mapC(k =>
  s"claude mcp add --transport http sruru ${Dom.origin}/mcp --header \"Authorization: Bearer ${k.getOrElse("<トークン>")}\"")
def token(s: State) = s.created.mapC(_.getOrElse(""))
</script>

<template>
  <div>
    <form @submit.prevent="create(s, props)">
      <div class="row">
        <input type="text" v-model="s.name" placeholder="用途（例: Claude Code・連携スクリプト）" class="grow">
        <select v-model="s.days">
          <option value="30">30日</option>
          <option value="90">90日</option>
          <option value="365">1年</option>
          <option value="">無期限</option>
        </select>
      </div>
      <div class="row scopes">
        <span class="small muted">スコープ:</span>
        <label v-for="sc in scopeList(props)" class="small"><input type="checkbox" :value="sc" v-model="s.scopes"> {{ TokenScopes.label(sc) }}</label>
      </div>
      <p v-if="s.error.v.nonEmpty" class="error small">{{ s.error }}</p>
      <button type="submit" class="primary" :disabled="s.busy">トークンを作る</button>
    </form>
    <div v-if="s.created.mapC(_.isDefined)" class="secret">
      <p class="small"><b>トークンを作りました。</b>この画面を離れると二度と表示できません。安全な場所に保存してください。</p>
      <div class="row"><code class="codebox grow">{{ token(s) }}</code><button class="small" @click="Dom.copy(s.created.v.getOrElse(&quot;&quot;))">コピー</button></div>
      <p class="small">Claude Code から使う（MCP）:</p>
      <div class="row"><code class="codebox grow">{{ mcpCommand(s) }}</code><button class="small" @click="Dom.copy(mcpCommand(s).v)">コピー</button></div>
      <p><button class="small" @click="s.created := None">閉じる</button></p>
    </div>
  </div>
</template>

<style scoped>
.scopes { margin: .6rem 0; gap: .4rem 1rem; }
</style>
