<script lang="scala">
import sruru.shared.*
import sruru.web.*
import sruru.web.parts.*

import scala.scalajs.concurrent.JSExecutionContext.Implicits.queue

// 個人設定: API トークン（REST API・MCP・SCIM から使う）
case class State(tokens: RV[List[ApiTokenDto]] = RV(Nil), grants: RV[List[OAuthGrantDto]] = RV(Nil))

def initState() = State()

def mounted(s: State): Unit = { pageTitle("API トークン"); load(s) }

// OAuth の連携で発行したトークンは「連携しているサービス」に出す
def load(s: State): Unit = {
  Api.get[List[ApiTokenDto]]("/api/me/tokens").foreach(ts => s.tokens := ts.filter(_.oauthClient.isEmpty))
  Api.get[List[OAuthGrantDto]]("/api/me/oauth").foreach(s.grants := _)
}

def disconnect(s: State, g: OAuthGrantDto): Unit =
  Dialog.confirm(s"「${g.name}」との連携をやめますか？${g.name} からは sruru を使えなくなります（もう一度使うには、${g.name} の画面から連携し直します）。", "連携をやめる") {
    Store.report(Api.delete(s"/api/me/oauth/${Api.enc(g.clientId)}"))(_ => load(s))
  }

def remove(s: State, t: ApiTokenDto): Unit =
  Dialog.confirm(s"API トークン「${t.name}」を削除しますか？使っているプログラムは使えなくなります。", "削除") {
    Store.report(Api.delete(s"/api/me/tokens/${t.id}"))(_ => load(s))
  }
</script>

<template>
  <div class="page narrow">
    <h1>個人設定</h1>
    <MeTabs />
    <section class="panel">
      <h2>API トークン</h2>
      <p class="small muted">プログラムや AI（MCP）から sruru を使うためのトークンです。<code>Authorization: Bearer &lt;トークン&gt;</code> で送ります。
        できることは「あなたの権限」と「トークンのスコープ」の両方を満たす範囲です。</p>
      <TokenCreator url="/api/me/tokens" :allowAdmin="Store.isAdmin.v" :onCreated="_ => load(s)" />
    </section>
    <div class="table-wrap">
      <table class="list">
        <thead><tr><th>用途</th><th>トークン</th><th>スコープ</th><th>有効期限</th><th>最後の使用</th><th></th></tr></thead>
        <tbody>
          <tr v-for="t in s.tokens" :key="t.id">
            <td>{{ t.name }}</td><td><code>{{ t.prefix }}…</code></td><td class="small">{{ t.scopes.mkString(", ") }}</td>
            <td class="small nowrap">{{ t.expiresAt.map(Fmt.date).getOrElse("無期限") }}</td>
            <td class="small nowrap">{{ Fmt.optAgo(t.lastUsedAt, "未使用") }}</td>
            <td><button class="ghost small" @click="remove(s, t)">削除</button></td>
          </tr>
          <tr v-if="s.tokens.mapC(_.isEmpty)"><td colspan="6" class="muted">API トークンはありません</td></tr>
        </tbody>
      </table>
    </div>
    <section class="panel">
      <h2>連携しているサービス</h2>
      <p class="small muted">あなたが許可して、あなたの権限で sruru を使っているサービスです（OAuth. 読み取りだけで、管理の操作はできません）。</p>
      <div class="table-wrap">
        <table class="list">
          <thead><tr><th>サービス</th><th>スコープ</th><th>許可した日時</th><th>最後の使用</th><th></th></tr></thead>
          <tbody>
            <tr v-for="g in s.grants" :key="g.clientId">
              <td>{{ g.name }}</td><td class="small">{{ g.scopes.mkString(", ") }}</td>
              <td class="small nowrap">{{ Fmt.date(g.createdAt) }}</td>
              <td class="small nowrap">{{ Fmt.optAgo(g.lastUsedAt, "未使用") }}</td>
              <td><button class="ghost small" @click="disconnect(s, g)">連携をやめる</button></td>
            </tr>
            <tr v-if="s.grants.mapC(_.isEmpty)"><td colspan="5" class="muted">連携しているサービスはありません</td></tr>
          </tbody>
        </table>
      </div>
    </section>
    <p class="small muted">MCP のエンドポイント: <code>{{ Dom.origin }}/mcp</code>（Streamable HTTP）。REST API の一覧は <a href="/api/endpoints" target="_blank">/api/endpoints</a>。</p>
  </div>
</template>
