<script lang="scala">
import sruru.shared.*
import sruru.web.*
import sruru.web.parts.*

// 管理: 監査ログ（絞り込み・ページ送り・詳細・CSV・改ざんの検査）
case class State(items: RV[List[AuditDto]] = RV(Nil), total: RV[Int] = RV(0), offset: RV[Int] = RV(0),
                 q: RV[String] = RV(""), action: RV[String] = RV(""), success: RV[String] = RV(""), via: RV[String] = RV(""),
                 from: RV[String] = RV(""), to: RV[String] = RV(""), detail: RV[Option[AuditDto]] = RV(None),
                 verify: RV[Option[AuditVerifyDto]] = RV(None), verifying: RV[Boolean] = RV(false))

def initState() = State()

val limit = 100

def mounted(s: State): Unit = { pageTitle("監査ログ"); load(s) }

def params(s: State): String = Api.query("q" -> Some(s.q.v.trim), "action" -> Some(s.action.v.trim), "success" -> Some(s.success.v),
  "via" -> Some(s.via.v), "from" -> Some(s.from.v), "to" -> Some(s.to.v))

def load(s: State): Unit = {
  val p = params(s)
  val url = "/api/admin/audit" + p + (if (p.isEmpty) "?" else "&") + s"limit=$limit&offset=${s.offset.v}"
  Toasts.report(Api.get[AuditListDto](url)) { r => s.items := r.items; s.total := r.total }
}

def search(s: State): Unit = { s.offset := 0; load(s) }
def page(s: State, d: Int): Unit = { s.offset := math.max(0, s.offset.v + d * limit); load(s) }

def csvUrl(s: State) = computed { "/api/admin/audit.csv" + params(s) }

def verify(s: State): Unit = {
  s.verifying := true
  Toasts.report(Api.post[AuditVerifyDto]("/api/admin/audit/verify")) { r => s.verifying := false; s.verify := Some(r) }
}

def detailList(s: State) = s.detail.mapC(_.toList)
def verifyList(s: State) = s.verify.mapC(_.toList)
def target(a: AuditDto): String = a.targetName.orElse(a.targetId.map(_.take(8))).getOrElse("")
def viaLabel(v: String): String = v match {
  case "web"  => "画面"
  case "api"  => "API"
  case "mcp"  => "MCP"
  case "scim" => "SCIM"
  case "sync" => "同期"
  case "system" => "システム"
  case x      => x
}
</script>

<template>
  <section>
    <div class="page-head"><h1>監査ログ</h1>
      <a :href="csvUrl(s)" class="btn">CSV で書き出す</a>
      <button :disabled="s.verifying" @click="verify(s)">改ざんを検査</button></div>
    <template v-for="v in verifyList(s)">
      <p v-if="v.brokenAt.isEmpty" class="notice ok small">{{ v.checked }} 件を検査しました。改ざんは見つかりませんでした。</p>
      <p v-else class="notice danger small">{{ v.checked }} 件を検査しました。ID {{ v.brokenAt.get }} の記録で、つながりが壊れています（改ざん・削除の疑い）。</p>
    </template>
    <form class="filters" @submit.prevent="search(s)">
      <input type="search" v-model="s.q" placeholder="名前・対象・IP アドレスで検索" class="grow">
      <input type="text" v-model="s.action" placeholder="操作（例: login.）" class="mono act">
      <select v-model="s.success" @change="search(s)"><option value="">成功・失敗</option><option value="true">成功</option><option value="false">失敗</option></select>
      <select v-model="s.via" @change="search(s)"><option value="">すべての経路</option><option value="web">画面</option><option value="api">API</option>
        <option value="mcp">MCP</option><option value="scim">SCIM</option><option value="sync">同期</option><option value="system">システム</option></select>
      <label class="small">から <input type="datetime-local" v-model="s.from"></label>
      <label class="small">まで <input type="datetime-local" v-model="s.to"></label>
      <button type="submit">検索</button>
    </form>
    <div class="table-wrap">
      <table class="list">
        <thead><tr><th>日時</th><th>操作した人</th><th>操作</th><th>対象</th><th class="hide-sp">経路</th><th class="hide-sp">IP アドレス</th><th>結果</th></tr></thead>
        <tbody>
          <tr v-for="a in s.items" :key="a.id" class="clickable" @click="s.detail := Some(a)">
            <td class="small nowrap">{{ Fmt.dateTime(a.at) }}</td>
            <td class="small">{{ a.actorName.getOrElse("") }}</td>
            <td><code class="small">{{ a.action }}</code></td>
            <td class="small">{{ target(a) }}</td>
            <td class="small hide-sp">{{ viaLabel(a.via) }}</td>
            <td class="small mono hide-sp">{{ a.ip.getOrElse("") }}</td>
            <td><span v-if="a.success" class="badge ok">成功</span><span v-else class="badge danger">失敗</span></td>
          </tr>
          <tr v-if="s.items.mapC(_.isEmpty)"><td colspan="7" class="muted">該当する記録はありません</td></tr>
        </tbody>
      </table>
    </div>
    <div class="pager">
      <Pager :offset="s.offset.v" :total="s.total.v" :limit="limit" :onPage="d => page(s, d)" />
    </div>
    <Modal v-for="a in detailList(s)" :onClose="_ => s.detail := None" :wide="true">
      <h2>{{ a.action }} <span v-if="a.success" class="badge ok">成功</span><span v-else class="badge danger">失敗</span></h2>
      <table class="kv small">
        <tbody>
          <tr><th>日時</th><td>{{ Fmt.dateTime(a.at) }}（ID {{ a.id }}）</td></tr>
          <tr><th>操作した人</th><td>{{ a.actorName.getOrElse("") }} <span class="muted mono">{{ a.actorId.map(_.toString).getOrElse("") }}</span></td></tr>
          <tr><th>対象</th><td>{{ a.targetType.getOrElse("") }} {{ a.targetName.getOrElse("") }} <span class="muted mono">{{ a.targetId.getOrElse("") }}</span></td></tr>
          <tr><th>経路</th><td>{{ viaLabel(a.via) }}</td></tr>
          <tr><th>IP アドレス</th><td class="mono">{{ a.ip.getOrElse("") }}</td></tr>
          <tr><th>ブラウザ</th><td class="break">{{ a.userAgent.getOrElse("") }}</td></tr>
        </tbody>
      </table>
      <pre class="json">{{ a.detail.spaces2 }}</pre>
      <div class="actions"><button @click="Dom.copy(a.detail.spaces2)">詳細をコピー</button><button class="primary" @click="s.detail := None">閉じる</button></div>
    </Modal>
  </section>
</template>

<style scoped>
.act { width: 11rem; }
.kv { border-collapse: collapse; margin-bottom: .8rem; width: 100%; }
.kv th { text-align: left; color: var(--muted); font-weight: 500; padding: .25rem .8rem .25rem 0; white-space: nowrap; vertical-align: top; width: 8em; }
.kv td { padding: .25rem 0; }
</style>
