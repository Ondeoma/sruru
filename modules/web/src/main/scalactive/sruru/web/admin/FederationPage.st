<script lang="scala">
import io.circe.Json
import io.circe.syntax.*
import sruru.shared.*
import sruru.web.*
import sruru.web.parts.*

import java.util.UUID
import scala.scalajs.concurrent.JSExecutionContext.Implicits.queue

// 管理: 外部の IdP（Google Workspace・Microsoft Entra ID・汎用の OIDC）でのログインと、ディレクトリの同期
case class State(list: RV[List[FederationDto]] = RV(Nil), groups: RV[List[GroupDto]] = RV(Nil),
                 editing: RV[Option[Option[FederationDto]]] = RV(None),
                 kind: RV[String] = RV("google"), slug: RV[String] = RV(""), name: RV[String] = RV(""), enabled: RV[Boolean] = RV(true),
                 tenant: RV[String] = RV(""), issuer: RV[String] = RV(""), clientId: RV[String] = RV(""), clientSecret: RV[String] = RV(""),
                 scopes: RV[String] = RV("openid profile email"), subject: RV[String] = RV("sub"), jit: RV[Boolean] = RV(true),
                 linkByEmail: RV[Boolean] = RV(false), domains: RV[String] = RV(""), defaultGroups: RV[List[String]] = RV(Nil),
                 trustMfa: RV[Boolean] = RV(false), syncEnabled: RV[Boolean] = RV(false), interval: RV[Int] = RV(60),
                 saJson: RV[String] = RV(""), adminEmail: RV[String] = RV(""), customer: RV[String] = RV("my_customer"),
                 syncTenant: RV[String] = RV(""), syncClientId: RV[String] = RV(""), syncSecret: RV[String] = RV(""), hasKey: RV[Boolean] = RV(false),
                 error: RV[String] = RV(""), busy: RV[Boolean] = RV(false), syncing: RV[Option[UUID]] = RV(None))

def initState() = State()

def mounted(s: State): Unit = {
  pageTitle("外部 IdP・同期")
  load(s)
  Api.groups().foreach(s.groups := _)
}

def load(s: State): Unit = Store.report(Api.get[List[FederationDto]]("/api/admin/federation"))(s.list := _)

private val EntraIssuer = """https://login\.microsoftonline\.com/([^/]+)/v2\.0""".r

def edit(s: State, f: Option[FederationDto]): Unit = {
  val x = f.getOrElse(FederationDto(new UUID(0L, 0L), "", "google", "Google", issuer = "https://accounts.google.com"))
  s.kind := x.kind; s.slug := x.slug; s.name := x.name; s.enabled := x.enabled; s.issuer := x.issuer; s.clientId := x.clientId
  s.clientSecret := ""; s.scopes := x.scopes; s.subject := x.subjectClaim; s.jit := x.jit; s.linkByEmail := x.linkByEmail
  s.domains := x.allowedDomains.mkString("\n"); s.defaultGroups := x.defaultGroups.map(_.toString); s.trustMfa := x.trustMfa
  s.syncEnabled := x.syncEnabled; s.interval := x.syncIntervalMin
  s.tenant := (x.issuer match { case EntraIssuer(t) => t; case _ => "" })
  val c = x.syncConfig.hcursor
  s.saJson := ""; s.syncSecret := ""
  s.adminEmail := c.get[String]("adminEmail").getOrElse(""); s.customer := c.get[String]("customer").getOrElse("my_customer")
  s.syncTenant := c.get[String]("tenantId").getOrElse(s.tenant.v); s.syncClientId := c.get[String]("clientId").getOrElse("")
  s.hasKey := c.get[Boolean]("hasKey").getOrElse(false)
  s.error := ""
  s.editing := Some(f)
}

/** 種類を選んだときの既定値. */
def setKind(s: State, k: String): Unit = {
  s.kind := k
  k match {
    case "google" =>
      s.issuer := "https://accounts.google.com"; s.subject := "sub"
      if (s.name.v.isEmpty || s.name.v == "Microsoft") s.name := "Google"
      if (s.slug.v.isEmpty || s.slug.v == "entra") s.slug := "google"
    case "entra" =>
      s.subject := "oid"; setTenant(s, s.tenant.v)
      if (s.name.v.isEmpty || s.name.v == "Google") s.name := "Microsoft"
      if (s.slug.v.isEmpty || s.slug.v == "google") s.slug := "entra"
    case _ => ()
  }
}

def setTenant(s: State, t: String): Unit = {
  s.tenant := t
  if (s.kind.v == "entra") s.issuer := s"https://login.microsoftonline.com/${if (t.trim.isEmpty) "<テナント>" else t.trim}/v2.0"
  if (s.syncTenant.v.isEmpty || t.startsWith(s.syncTenant.v)) s.syncTenant := t.trim
}

def syncConfig(s: State): Option[Json] =
  if (!s.syncEnabled.v) None
  else s.kind.v match {
    case "google" => Some(Json.obj("serviceAccountJson" -> s.saJson.v.trim.asJson, "adminEmail" -> s.adminEmail.v.trim.asJson,
      "customer" -> s.customer.v.trim.asJson))
    case "entra" => Some(Json.obj("tenantId" -> s.syncTenant.v.trim.asJson, "clientId" -> s.syncClientId.v.trim.asJson,
      "clientSecret" -> s.syncSecret.v.trim.asJson))
    case _ => None
  }

def save(s: State): Unit = {
  val req = FederationReq(s.slug.v.trim, s.kind.v, s.name.v.trim, s.enabled.v, s.issuer.v.trim, s.clientId.v.trim, Fmt.opt(s.clientSecret.v),
    s.scopes.v.trim, s.subject.v.trim, s.jit.v, s.linkByEmail.v, Fmt.lines(s.domains.v), s.defaultGroups.v.map(UUID.fromString), s.trustMfa.v,
    s.syncEnabled.v, syncConfig(s), s.interval.v)
  val f = s.editing.v.flatten match {
    case Some(x) => Api.put[FederationDto](s"/api/admin/federation/${x.id}", Api.json(req))
    case None    => Api.post[FederationDto]("/api/admin/federation", Api.json(req))
  }
  Store.inline(f, s.error, s.busy) { x =>
    Store.toast("保存しました")
    load(s)
    edit(s, Some(x))
  }
}

def remove(s: State, f: FederationDto): Unit =
  Dialog.confirm(s"外部の IdP「${f.name}」を削除しますか？この IdP でのログインはできなくなります。", "削除") {
    Store.report(Api.delete(s"/api/admin/federation/${f.id}")) { _ => s.editing := None; load(s) }
  }

def sync(s: State, f: FederationDto): Unit = {
  s.syncing := Some(f.id)
  Api.post[SyncResultDto](s"/api/admin/federation/${f.id}/sync").onComplete { r =>
    s.syncing := None
    r.fold(Store.error, x => Store.toast(x.message))
    load(s)
  }
}

def kindLabel(k: String): String = k match {
  case "google" => "Google Workspace"
  case "entra"  => "Microsoft Entra ID"
  case _        => "OpenID Connect"
}

def current(s: State) = s.editing.mapC(_.flatten.toList)
def groupRows(s: State) = s.groups.mapC(GroupTree.flatten)
def canSync(s: State) = s.kind.mapC(k => k == "google" || k == "entra")
</script>

<template>
  <section>
    <div class="page-head"><h1>外部 IdP・同期</h1><button class="primary" @click="edit(s, None)">＋ 外部 IdP を追加</button></div>
    <p class="small muted">Google Workspace・Microsoft Entra ID などのアカウントでログインできるようにします。ユーザーとグループを定期的に同期することもできます。</p>
    <div class="table-wrap">
      <table class="list">
        <thead><tr><th>名前</th><th>種類</th><th>状態</th><th class="hide-sp">最後の同期</th><th></th></tr></thead>
        <tbody>
          <tr v-for="f in s.list" :key="f.id">
            <td>{{ f.name }} <span class="muted small mono">{{ f.slug }}</span></td>
            <td class="small">{{ kindLabel(f.kind) }}</td>
            <td><span v-if="!f.enabled" class="badge danger">無効</span><span v-if="f.syncEnabled" class="badge accent">同期</span></td>
            <td class="small hide-sp">{{ Fmt.optDateTime(f.lastSyncAt, "") }}<div class="muted small">{{ f.lastSyncResult.getOrElse("") }}</div></td>
            <td class="nowrap">
              <button v-if="f.syncEnabled" class="small" :disabled="s.syncing.v.contains(f.id)" @click="sync(s, f)">{{ if (s.syncing.v.contains(f.id)) "同期中…" else "今すぐ同期" }}</button>
              <button class="ghost small" @click="edit(s, Some(f))">編集</button>
              <button class="ghost small" @click="remove(s, f)">削除</button>
            </td>
          </tr>
          <tr v-if="s.list.mapC(_.isEmpty)"><td colspan="5" class="muted">外部 IdP はまだありません</td></tr>
        </tbody>
      </table>
    </div>

    <Modal v-if="s.editing.mapC(_.isDefined)" :onClose="_ => s.editing := None" :wide="true">
      <form @submit.prevent="save(s)">
        <h2>{{ if (current(s).v.isEmpty) "外部 IdP を追加" else "外部 IdP を編集" }}</h2>
        <div class="field"><span>種類</span>
          <div class="chips">
            <label class="chip"><input type="radio" name="kind" value="google" :checked='s.kind.v == "google"' @change='setKind(s, "google")'> Google Workspace</label>
            <label class="chip"><input type="radio" name="kind" value="entra" :checked='s.kind.v == "entra"' @change='setKind(s, "entra")'> Microsoft Entra ID</label>
            <label class="chip"><input type="radio" name="kind" value="oidc" :checked='s.kind.v == "oidc"' @change='setKind(s, "oidc")'> そのほかの OpenID Connect</label>
          </div></div>
        <div class="grid2">
          <label class="field"><span>表示名（ログインのボタンに出ます）</span><input type="text" v-model="s.name"></label>
          <label class="field"><span>識別子（英小文字・数字・ハイフン）</span><input type="text" v-model="s.slug" class="mono" autocapitalize="none"></label>
        </div>
        <label v-if='s.kind.v == "entra"' class="field"><span>テナント（ID またはドメイン）</span>
          <input type="text" :value="s.tenant" @input="setTenant(s, Dom.value(event))" class="mono" placeholder="contoso.onmicrosoft.com"></label>
        <label class="field"><span>発行者（issuer）</span><input type="url" v-model="s.issuer" class="mono" :disabled='s.kind.v == "entra"'></label>
        <div class="grid2">
          <label class="field"><span>クライアント ID</span><input type="text" v-model="s.clientId" class="mono"></label>
          <label class="field"><span>クライアントシークレット</span>
            <input type="password" v-model="s.clientSecret" autocomplete="new-password" :placeholder='if (current(s).v.exists(_.hasSecret)) "（設定済み。変えるときだけ入力）" else ""'></label>
          <label class="field"><span>スコープ</span><input type="text" v-model="s.scopes" class="mono"></label>
          <label class="field"><span>ユーザーを識別するクレーム</span><input type="text" v-model="s.subject" class="mono"></label>
        </div>
        <template v-for="f in current(s)">
          <div class="field"><span>上流の IdP に登録するリダイレクト URI</span><CopyRow :value="f.callbackUrl" /></div>
        </template>
        <p v-if="current(s).v.isEmpty" class="small muted">上流の IdP に登録するリダイレクト URI は、保存すると表示されます。</p>
        <label class="field"><span>ログインを許すドメイン（1行に1つ。空なら制限なし。Google は Workspace のドメイン、Entra はテナント ID）</span><textarea class="code" v-model="s.domains" rows="2" placeholder="example.co.jp"></textarea></label>
        <div class="grid2">
          <label class="check"><input type="checkbox" v-model="s.enabled"><span>有効</span></label>
          <label class="check"><input type="checkbox" v-model="s.jit"><span>初めてのログインでユーザーを作る</span></label>
          <label class="check"><input type="checkbox" v-model="s.linkByEmail"><span>メールアドレスが同じ既存のユーザーとつなぐ</span></label>
          <label class="check"><input type="checkbox" v-model="s.trustMfa"><span>上流の IdP での多要素認証を信頼する</span></label>
        </div>
        <div class="field"><span>作ったユーザーを入れるグループ</span>
          <div class="group-list">
            <label v-for="gd in groupRows(s)" class="check" :style="GroupTree.indent(gd._2)">
              <input type="checkbox" :value="gd._1.id.toString" v-model="s.defaultGroups"><span>{{ gd._1.name }}</span></label>
            <p v-if="s.groups.mapC(_.isEmpty)" class="muted small">グループはまだありません。</p>
          </div></div>

        <template v-if="canSync(s)">
          <h3>ディレクトリの同期</h3>
          <label class="check"><input type="checkbox" v-model="s.syncEnabled"><span>ユーザーとグループを定期的に同期する</span></label>
          <template v-if="s.syncEnabled">
            <label class="field narrow-field"><span>同期の間隔（分。5 以上）</span><input type="number" min="5" v-model="s.interval"></label>
            <template v-if='s.kind.v == "google"'>
              <label class="field"><span>サービスアカウントの鍵（JSON）{{ if (s.hasKey.v) "（設定済み。変えるときだけ貼り付け）" else "" }}</span>
                <textarea class="code" v-model="s.saJson" rows="4" placeholder='{"type": "service_account", ...}'></textarea>
                <span class="hint">ドメイン全体の委任で admin.directory.user.readonly・admin.directory.group.readonly を許可してください。</span></label>
              <div class="grid2">
                <label class="field"><span>管理者のメールアドレス（委任で使う）</span><input type="email" v-model="s.adminEmail"></label>
                <label class="field"><span>顧客 ID</span><input type="text" v-model="s.customer" class="mono"></label>
              </div>
            </template>
            <template v-if='s.kind.v == "entra"'>
              <p class="small muted">Microsoft Graph の User.Read.All・GroupMember.Read.All（アプリケーションの許可）が必要です。</p>
              <div class="grid3">
                <label class="field"><span>テナント ID</span><input type="text" v-model="s.syncTenant" class="mono"></label>
                <label class="field"><span>クライアント ID</span><input type="text" v-model="s.syncClientId" class="mono"></label>
                <label class="field"><span>クライアントシークレット</span><input type="password" v-model="s.syncSecret" autocomplete="new-password"
                  :placeholder='if (s.hasKey.v) "（設定済み）" else ""'></label>
              </div>
            </template>
            <template v-for="f in current(s)">
              <p class="small">最後の同期: {{ Fmt.optDateTime(f.lastSyncAt, "まだ") }} <span class="muted">{{ f.lastSyncResult.getOrElse("") }}</span>
                <button v-if="f.syncEnabled" type="button" class="small" :disabled="s.syncing.v.isDefined" @click="sync(s, f)">今すぐ同期</button></p>
            </template>
          </template>
        </template>
        <p v-if="s.error.v.nonEmpty" class="error small">{{ s.error }}</p>
        <div class="actions"><button type="button" @click="s.editing := None">閉じる</button><button type="submit" class="primary" :disabled="s.busy">保存</button></div>
      </form>
    </Modal>
  </section>
</template>

<style scoped>
.group-list { max-height: 200px; overflow-y: auto; border: 1px solid var(--line); border-radius: 8px; padding: .3rem .7rem; }
.narrow-field { max-width: 260px; }
</style>
