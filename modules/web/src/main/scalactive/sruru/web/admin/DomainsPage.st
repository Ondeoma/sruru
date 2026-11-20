<script lang="scala">
import sruru.shared.*
import sruru.web.*
import sruru.web.parts.*

// 管理: ドメイン（sruru にアクセスするホスト名）ごとのポリシーの上書き
case class State(data: RV[Option[DomainsDto]] = RV(None), providers: RV[List[FederationDto]] = RV(Nil),
                 // 編集中のもの（Some(None) は追加）と、その入力欄
                 editing: RV[Option[Option[DomainDto]]] = RV(None), form: RV[Option[DomainEdit]] = RV(None),
                 error: RV[String] = RV(""), busy: RV[Boolean] = RV(false))

def initState() = State()

def mounted(s: State): Unit = {
  pageTitle("ドメイン")
  load(s)
  Store.report(Api.get[List[FederationDto]]("/api/admin/federation"))(s.providers := _)
}

def load(s: State): Unit = Store.report(Api.get[DomainsDto]("/api/admin/domains"))(d => s.data := Some(d))

def edit(s: State, d: Option[DomainDto]): Unit = {
  s.form := Some(DomainEdit.from(d.fold("")(_.host), d.fold("")(_.note), d.fold(DomainPolicy())(_.policy)))
  s.error := ""
  s.editing := Some(d)
}

def close(s: State): Unit = { s.editing := None; s.form := None }

def save(s: State): Unit = s.form.v.foreach(_.build match {
  case Left(e) => s.error := e
  case Right(req) =>
    val f = s.editing.v.flatten match {
      case Some(x) => Api.put[DomainDto](s"/api/admin/domains/${x.id}", Api.json(req))
      case None    => Api.post[DomainDto]("/api/admin/domains", Api.json(req))
    }
    Store.inline(f, s.error, s.busy) { x =>
      Store.toast("保存しました")
      load(s)
      edit(s, Some(x))
    }
})

def remove(s: State, d: DomainDto): Unit =
  Dialog.confirm(s"ドメイン「${d.host}」を削除しますか？このホスト名でのログインは終わり、以後は既定のホスト名として扱われます。", "削除") {
    Store.report(Api.delete(s"/api/admin/domains/${d.id}")) { _ => close(s); load(s) }
  }

def rows(s: State) = s.data.mapC(_.toList.flatMap(_.domains))
def primary(s: State) = s.data.mapC(_.fold("")(_.primaryUrl))
def isCurrent(s: State, d: DomainDto): Boolean = s.data.v.exists(_.current.contains(d.id))
def onPrimary(s: State) = s.data.mapC(_.exists(_.current.isEmpty))
def current(s: State) = s.editing.mapC(_.flatten.toList)
def forms(s: State) = s.form.mapC(_.toList)
</script>

<template>
  <section>
    <div class="page-head"><h1>ドメイン</h1><button class="primary" @click="edit(s, None)">＋ ドメインを追加</button></div>
    <p class="small muted">同じ sruru を複数のホスト名で公開し、アクセスしたホスト名ごとにポリシーと表示を変えます。ユーザー・グループ・アプリケーションは全ホスト名で共通です。
      各ホスト名は自分の issuer（OIDC）・エンティティ ID（SAML）を持ち、ログイン（Cookie）もホスト名ごとです。各サービスには、使いたいポリシーのホスト名の URL を設定します。</p>
    <div class="table-wrap">
      <table class="list">
        <thead><tr><th>ホスト名</th><th class="hide-sp">説明</th><th>上書きしている項目</th><th></th></tr></thead>
        <tbody>
          <tr>
            <td><span class="mono">{{ primary(s) }}</span> <span class="badge">既定</span><span v-if="onPrimary(s)" class="badge accent">いま開いています</span></td>
            <td class="small hide-sp muted">PUBLIC_URL のホスト名。登録のないホスト名もここに含まれます</td>
            <td class="small muted">全体のポリシーのまま</td>
            <td class="nowrap"><RouterLink to="/admin/policies" class="small">ポリシー</RouterLink></td>
          </tr>
          <tr v-for="d in rows(s)" :key="d.id">
            <td><span class="mono">{{ d.url }}</span> <span v-if="isCurrent(s, d)" class="badge accent">いま開いています</span></td>
            <td class="small hide-sp">{{ d.note }}</td>
            <td class="small">
              <span v-for="x in DomainEdit.summary(d.policy)" class="badge">{{ x }}</span>
              <span v-if="!d.policy.admin" class="badge danger">管理機能なし</span>
              <span v-if="DomainEdit.summary(d.policy).isEmpty && d.policy.admin" class="muted">なし（全体のまま）</span>
            </td>
            <td class="nowrap">
              <button class="ghost small" @click="edit(s, Some(d))">編集</button>
              <button class="ghost small" @click="remove(s, d)">削除</button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <Modal v-if="s.editing.mapC(_.isDefined)" :onClose="_ => close(s)" :wide="true">
      <form v-for="e in forms(s)" @submit.prevent="save(s)">
        <h2>{{ if (current(s).v.isEmpty) "ドメインを追加" else "ドメインを編集" }}</h2>
        <div class="grid2">
          <label class="field"><span>ホスト名（例: auth.example.com。既定のポートでなければ :ポート を付ける）</span>
            <input type="text" v-model="e.host" class="mono" autocapitalize="none" placeholder="auth.example.com" :disabled="current(s).v.nonEmpty"></label>
          <label class="field"><span>説明</span><input type="text" v-model="e.note"></label>
        </div>
        <p v-if="current(s).v.nonEmpty" class="hint">ホスト名は変えられません（ログインとトークンがホスト名に結び付いているため）。変えるときは、消してから作り直してください。</p>
        <p v-if="current(s).v.isEmpty" class="hint">このホスト名で sruru に届くように、DNS とリバースプロキシ（証明書）を別に設定してください。リバースプロキシは Host ヘッダー（または X-Forwarded-Host）をそのまま渡すようにします。</p>
        <template v-for="d in current(s)">
          <div class="field"><span>このドメインの URL（OIDC の issuer）</span><CopyRow :value="d.url" /></div>
          <div class="field"><span>OIDC の設定の URL ／ SAML のメタデータ（エンティティ ID）</span>
            <CopyRow :value='d.url + "/.well-known/openid-configuration"' /><CopyRow :value='d.url + "/saml/metadata"' /></div>
          <p class="hint">このホスト名から外部の IdP でログインさせるには、外部の IdP に <span class="mono">{{ d.url }}/auth/fed/（識別子）/callback</span> もリダイレクト URI として登録してください。</p>
        </template>
        <DomainPolicyFields :e="e" :providers="s.providers" />
        <p v-if="s.error.v.nonEmpty" class="error small">{{ s.error }}</p>
        <div class="actions"><button type="button" @click="close(s)">閉じる</button><button type="submit" class="primary" :disabled="s.busy">保存</button></div>
      </form>
    </Modal>
  </section>
</template>
