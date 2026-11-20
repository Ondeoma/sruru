<script lang="scala">
import sruru.shared.*
import sruru.web.*
import sruru.web.parts.*

import scala.scalajs.concurrent.JSExecutionContext.Implicits.queue

// 管理: クライアント証明書の認証局（この認証局が発行した証明書でのログインを受け付ける）
case class State(cas: RV[List[CertAuthorityDto]] = RV(Nil), adding: RV[Boolean] = RV(false), name: RV[String] = RV(""), pem: RV[String] = RV(""),
                 policy: RV[Option[CertAuthPolicy]] = RV(None), error: RV[String] = RV(""), busy: RV[Boolean] = RV(false))

def initState() = State()

def mounted(s: State): Unit = {
  pageTitle("証明書の認証局")
  load(s)
  Api.get[PoliciesDto]("/api/admin/policies").foreach(p => s.policy := Some(p.cert))
}

def load(s: State): Unit = Toasts.report(Api.get[List[CertAuthorityDto]]("/api/admin/cert-authorities"))(s.cas := _)

def add(s: State): Unit =
  Store.inline(Api.post[CertAuthorityDto]("/api/admin/cert-authorities", Api.json(CertAuthorityReq(s.name.v.trim, s.pem.v.trim))), s.error, s.busy) { _ =>
    s.adding := false; s.name := ""; s.pem := ""; Toasts.show("認証局を追加しました"); load(s)
  }

def remove(s: State, c: CertAuthorityDto): Unit =
  Dialog.confirm(s"認証局「${c.name}」を削除しますか？この認証局の証明書ではログインできなくなります。", "削除") {
    Toasts.report(Api.delete(s"/api/admin/cert-authorities/${c.id}"))(_ => load(s))
  }

def pol(s: State) = s.policy.mapC(_.toList)
</script>

<template>
  <section>
    <div class="page-head"><h1>証明書の認証局</h1><button class="primary" @click="s.adding := true">＋ 認証局を追加</button></div>
    <template v-for="p in pol(s)">
      <div :class='if (p.enabled) "notice small" else "notice warn small"'>
        <p v-if="!p.enabled">証明書でのログインは使わない設定です。「ポリシー → クライアント証明書でのログイン」で有効にしてください。</p>
        <p>クライアント証明書の検証はリバースプロキシ（nginx など）で行い、証明書を <code>{{ p.header }}</code> ヘッダーで sruru に渡してください。
          sruru は <code>/auth/cert</code> へのアクセスでこのヘッダーを読みます。プロキシのアドレスは「ポリシー → 信頼するプロキシ」に入れてください。</p>
        <p>例（nginx）: <code>ssl_verify_client optional;</code> と <code>proxy_set_header {{ p.header }} $ssl_client_escaped_cert;</code></p>
      </div>
    </template>
    <div class="table-wrap">
      <table class="list">
        <thead><tr><th>名前</th><th>サブジェクト</th><th>有効期限</th><th></th></tr></thead>
        <tbody>
          <tr v-for="c in s.cas" :key="c.id">
            <td>{{ c.name }} <span v-if="!c.enabled" class="badge">無効</span></td>
            <td class="small break">{{ c.subject }}</td>
            <td class="small nowrap">{{ Fmt.optDateTime(c.notAfter) }}</td>
            <td><button class="ghost small" @click="remove(s, c)">削除</button></td>
          </tr>
          <tr v-if="s.cas.mapC(_.isEmpty)"><td colspan="4" class="muted">認証局はまだありません</td></tr>
        </tbody>
      </table>
    </div>
    <Modal v-if="s.adding" :onClose="_ => s.adding := false">
      <form @submit.prevent="add(s)">
        <h2>認証局を追加</h2>
        <label class="field"><span>名前</span><input type="text" v-model="s.name" placeholder="社内 CA"></label>
        <label class="field"><span>認証局の証明書（PEM）</span><textarea class="code" v-model="s.pem" placeholder="-----BEGIN CERTIFICATE-----"></textarea></label>
        <p v-if="s.error.v.nonEmpty" class="error small">{{ s.error }}</p>
        <div class="actions"><button type="button" @click="s.adding := false">キャンセル</button><button type="submit" class="primary" :disabled="s.busy">追加</button></div>
      </form>
    </Modal>
  </section>
</template>
