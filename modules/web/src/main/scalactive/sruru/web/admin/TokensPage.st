<script lang="scala">
import sruru.shared.*
import sruru.web.*
import sruru.web.parts.*

// 管理: すべての API トークン
case class State(tokens: RV[List[ApiTokenDto]] = RV(Nil), q: RV[String] = RV(""))

def initState() = State()

def mounted(s: State): Unit = { pageTitle("API トークン"); load(s) }

def load(s: State): Unit = Store.report(Api.get[List[ApiTokenDto]]("/api/admin/tokens"))(s.tokens := _)

def remove(s: State, t: ApiTokenDto): Unit =
  Dialog.confirm(s"API トークン「${t.name}」（${t.owner.map(_.name).getOrElse("")}）を削除しますか？", "削除") {
    Store.report(Api.delete(s"/api/admin/tokens/${t.id}"))(_ => load(s))
  }

def shown(s: State) = computed {
  val q = s.q.v.trim.toLowerCase
  s.tokens.v.filter(t => q.isEmpty || t.name.toLowerCase.contains(q) || t.owner.exists(o => o.name.toLowerCase.contains(q) || o.username.toLowerCase.contains(q)))
}
</script>

<template>
  <section>
    <div class="page-head"><h1>API トークン</h1></div>
    <p class="small muted">すべてのユーザーの API トークンです。サービスアカウントのトークンは、ユーザーの詳細の画面で作れます。</p>
    <div class="filters"><input type="search" v-model="s.q" placeholder="用途・持ち主で絞り込み" class="grow"></div>
    <div class="table-wrap">
      <table class="list">
        <thead><tr><th>持ち主</th><th>用途</th><th>トークン</th><th>スコープ</th><th class="hide-sp">有効期限</th><th>最後の使用</th><th></th></tr></thead>
        <tbody>
          <tr v-for="t in shown(s)" :key="t.id">
            <td><template v-for="o in t.owner.toList"><RouterLink :to='"/admin/users/" + o.id' class="owner"><Avatar :user="Some(o)" :size="20" /> {{ o.name }}</RouterLink></template></td>
            <td>{{ t.name }}</td>
            <td><code>{{ t.prefix }}…</code></td>
            <td class="small">{{ t.scopes.mkString(", ") }}</td>
            <td class="small nowrap hide-sp">{{ t.expiresAt.map(Fmt.date).getOrElse("無期限") }}</td>
            <td class="small nowrap">{{ Fmt.optAgo(t.lastUsedAt, "未使用") }}</td>
            <td><button class="ghost small" @click="remove(s, t)">削除</button></td>
          </tr>
          <tr v-if="s.tokens.mapC(_.isEmpty)"><td colspan="7" class="muted">API トークンはありません</td></tr>
        </tbody>
      </table>
    </div>
  </section>
</template>
