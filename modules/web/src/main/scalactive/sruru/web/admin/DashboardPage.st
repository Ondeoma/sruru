<script lang="scala">
import sruru.shared.*
import sruru.web.*
import sruru.web.parts.*

import scala.scalajs.concurrent.JSExecutionContext.Implicits.queue

// 管理: 概要（数・最近のログインの失敗）と、この IdP の接続情報
case class State(d: RV[Option[DashboardDto]] = RV(None), info: RV[Option[IdpInfoDto]] = RV(None))

def initState() = State()

def mounted(s: State): Unit = {
  pageTitle("概要")
  Toasts.report(Api.get[DashboardDto]("/api/admin/dashboard"))(x => s.d := Some(x))
  Api.idpInfo().foreach(x => s.info := Some(x))
}

def dash(s: State) = s.d.mapC(_.toList)
def infos(s: State) = s.info.mapC(_.toList)
</script>

<template>
  <section>
    <h1>概要</h1>
    <template v-for="d in dash(s)">
      <div class="stats">
        <RouterLink to="/admin/users" class="stat"><div class="n">{{ d.users }}</div><div class="l">ユーザー</div></RouterLink>
        <div class="stat"><div class="n">{{ d.disabledUsers }}</div><div class="l">無効のユーザー</div></div>
        <div class="stat"><div class="n">{{ d.lockedUsers }}</div><div class="l">ロック中のユーザー</div></div>
        <div class="stat"><div class="n">{{ d.mfaUsers }}</div><div class="l">2段階認証を使っている人</div></div>
        <RouterLink to="/admin/groups" class="stat"><div class="n">{{ d.groups }}</div><div class="l">グループ</div></RouterLink>
        <RouterLink to="/admin/apps" class="stat"><div class="n">{{ d.apps }}</div><div class="l">アプリケーション</div></RouterLink>
        <div class="stat"><div class="n">{{ d.loginsToday }}</div><div class="l">今日のログイン</div></div>
        <div class="stat"><div :class='if (d.failuresToday > 0) "n error" else "n"'>{{ d.failuresToday }}</div><div class="l">今日のログインの失敗</div></div>
      </div>
      <h2>最近のログインの失敗</h2>
      <div v-if="d.recentFailures.nonEmpty" class="table-wrap">
        <table class="list">
          <thead><tr><th>日時</th><th>ユーザー</th><th>操作</th><th>IP アドレス</th><th>理由</th></tr></thead>
          <tbody>
            <tr v-for="a in d.recentFailures" :key="a.id">
              <td class="small nowrap">{{ Fmt.dateTime(a.at) }}</td>
              <td class="small">{{ a.actorName.orElse(a.targetName).getOrElse("") }}</td>
              <td><code class="small">{{ a.action }}</code></td>
              <td class="small mono">{{ a.ip.getOrElse("") }}</td>
              <td class="small muted">{{ a.detail.hcursor.get[String]("reason").getOrElse(a.detail.noSpaces.take(80)) }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <p v-else class="muted small">最近の失敗はありません。</p>
    </template>
    <template v-for="i in infos(s)">
      <h2>この IdP の接続情報</h2>
      <p class="small muted">アプリケーション（SP・RP）の登録に使います。</p>
      <div class="panel">
        <CopyRow label="発行者（issuer）" :value="i.issuer" />
        <CopyRow label="OIDC ディスカバリー" :value="i.discovery" />
        <CopyRow label="SAML メタデータ" :value="i.samlMetadata" />
        <CopyRow label="SAML エンティティ ID" :value="i.samlEntityId" />
        <CopyRow label="SCIM のベース URL" :value="i.scimBase" />
        <CopyRow label="MCP の URL" :value="i.mcpUrl" />
      </div>
    </template>
  </section>
</template>
