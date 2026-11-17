<script lang="scala">
import sruru.shared.*
import sruru.web.*

// 管理: 署名鍵（ID トークン・SAML の署名に使う鍵. 入れ替えと退役）
case class State(keys: RV[List[KeyDto]] = RV(Nil))

def initState() = State()

def mounted(s: State): Unit = { pageTitle("署名鍵"); load(s) }

def load(s: State): Unit = Store.report(Api.get[List[KeyDto]]("/api/admin/keys"))(s.keys := _)

def rotate(s: State, alg: String): Unit =
  Dialog.confirm(s"$alg の署名鍵を新しくしますか？今の鍵は、発行済みのトークンを確かめるために公開したまま残ります。", "新しくする", danger = false) {
    Store.report(Api.post[KeyDto](s"/api/admin/keys/rotate?alg=$alg")) { _ => Store.toast("署名鍵を新しくしました"); load(s) }
  }

def retire(s: State, k: KeyDto): Unit =
  Dialog.confirm(s"鍵 ${k.kid} を退役させますか？この鍵で署名したトークンは確かめられなくなります。", "退役させる") {
    Store.report(Api.delete(s"/api/admin/keys/${Api.enc(k.kid)}"))(_ => load(s))
  }

def sorted(s: State) = s.keys.mapC(_.sortBy(k => (k.retiredAt.isDefined, !k.active, -k.createdAt.toEpochMilli)))
</script>

<template>
  <section>
    <div class="page-head"><h1>署名鍵</h1>
      <button @click='rotate(s, "RS256")'>RS256 の鍵を新しくする</button>
      <button @click='rotate(s, "ES256")'>ES256 の鍵を新しくする</button></div>
    <p class="small muted">ID トークン・アクセストークン・SAML の署名に使う鍵です。定期的に新しくすると安全です。新しくした後も、古い鍵は JWKS で公開したまま残り、
      使い終わったら退役させます。</p>
    <div class="table-wrap">
      <table class="list">
        <thead><tr><th>鍵 ID（kid）</th><th>アルゴリズム</th><th>状態</th><th>作成</th><th>退役</th><th></th></tr></thead>
        <tbody>
          <tr v-for="k in sorted(s)" :key="k.kid">
            <td class="mono small break">{{ k.kid }}</td>
            <td>{{ k.alg }}</td>
            <td><span v-if="k.active" class="badge ok">使用中</span><span v-else-if="k.retiredAt.isDefined" class="badge">退役</span><span v-else class="badge warn">公開のみ</span></td>
            <td class="small nowrap">{{ Fmt.dateTime(k.createdAt) }}</td>
            <td class="small nowrap">{{ Fmt.optDateTime(k.retiredAt, "") }}</td>
            <td><button v-if="!k.active && k.retiredAt.isEmpty" class="ghost small" @click="retire(s, k)">退役させる</button></td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>
</template>
