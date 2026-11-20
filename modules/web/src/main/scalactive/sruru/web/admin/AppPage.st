<script lang="scala">
import io.circe.Json
import sruru.shared.*
import sruru.web.*
import sruru.web.parts.*

import java.util.UUID
import scala.scalajs.concurrent.JSExecutionContext.Implicits.queue
import scala.util.{Failure, Success}

// 管理: アプリケーションの追加・編集（共通の設定・OIDC/OAuth 2.0 か SAML の設定・渡す情報の対応付け）.
// id が空なら追加（はじめに方式を選ぶ）.
case class Props(id: String)

case class State(app: RV[Option[AppDto]] = RV(None), protocol: RV[String] = RV(""), info: RV[Option[IdpInfoDto]] = RV(None),
                 groups: RV[List[GroupDto]] = RV(Nil),
                 slug: RV[String] = RV(""), name: RV[String] = RV(""), desc: RV[String] = RV(""), launchUrl: RV[String] = RV(""),
                 enabled: RV[Boolean] = RV(true), showInPortal: RV[Boolean] = RV(true), requireMfa: RV[Boolean] = RV(false),
                 ipAllow: RV[String] = RV(""), restrict: RV[Boolean] = RV(false), accessGroups: RV[List[String]] = RV(Nil),
                 mappings: RV[List[MappingRow]] = RV(Nil),
                 // OIDC
                 clientId: RV[String] = RV(""), confidential: RV[Boolean] = RV(true), redirects: RV[String] = RV(""), postLogout: RV[String] = RV(""),
                 grants: RV[List[String]] = RV(List("authorization_code", "refresh_token")), scopes: RV[String] = RV("openid profile email groups offline_access"),
                 consent: RV[String] = RV("implicit"), subMode: RV[String] = RV("id"), alg: RV[String] = RV("RS256"), accessTtl: RV[Int] = RV(3600),
                 idTtl: RV[Int] = RV(3600), refreshTtl: RV[Int] = RV(2592000), includeGroups: RV[Boolean] = RV(true), backchannel: RV[String] = RV(""),
                 includeAppNames: RV[Boolean] = RV(false),
                 // SAML
                 entityId: RV[String] = RV(""), acsUrl: RV[String] = RV(""), acsBinding: RV[String] = RV("post"), sloUrl: RV[String] = RV(""),
                 nameIdFormat: RV[String] = RV("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"), nameIdExpr: RV[String] = RV("{{user.email}}"),
                 signResponse: RV[Boolean] = RV(true), signAssertion: RV[Boolean] = RV(true), spCert: RV[String] = RV(""),
                 wantSigned: RV[Boolean] = RV(false), sessionTtl: RV[Int] = RV(28800), metadata: RV[String] = RV(""), metaOpen: RV[Boolean] = RV(false),
                 // そのほか
                 error: RV[String] = RV(""), busy: RV[Boolean] = RV(false), secret: RV[Option[String]] = RV(None),
                 preview: RV[String] = RV(""))

def initState() = State()

/** 作った直後に表示するシークレット（詳細の画面に移っても出すため）. */
val pendingSecret: RV[Option[(String, String)]] = RV(None)

def isNew(props: Props): Boolean = props.id.isEmpty

def mounted(s: State, props: Props): Unit = {
  pageTitle(if (isNew(props)) "アプリケーションを追加" else "アプリケーション")
  Api.groups().foreach(s.groups := _)
  Api.idpInfo().foreach(i => s.info := Some(i))
  if (isNew(props)) Api.param("protocol").foreach(p => choose(s, p))
  else Toasts.report(Api.get[AppDto](s"/api/admin/apps/${props.id}"))(fill(s, _))
  pendingSecret.v.filter(_._1 == props.id).foreach { x => s.secret := Some(x._2); pendingSecret := None }
}

def choose(s: State, p: String): Unit = {
  s.protocol := p
  if (p == "saml") s.mappings := List(
    Mappings.row(MappingDto("email", "{{user.email}}", friendlyName = Some("mail"))),
    Mappings.row(MappingDto("displayName", "{{user.name}}")),
    Mappings.row(MappingDto("groups", "{{user.groups}}", multi = true)))
}

def fill(s: State, a: AppDto): Unit = {
  pageTitle(a.name)
  s.app := Some(a)
  s.protocol := a.protocol; s.slug := a.slug; s.name := a.name; s.desc := a.description; s.launchUrl := a.launchUrl.getOrElse("")
  s.enabled := a.enabled; s.showInPortal := a.showInPortal; s.requireMfa := a.requireMfa; s.ipAllow := a.ipAllow.mkString("\n")
  s.restrict := a.restrictAccess; s.accessGroups := a.accessGroups.map(_.toString); s.mappings := a.mappings.map(Mappings.row)
  a.oidc.foreach { o =>
    s.clientId := o.clientId; s.confidential := o.confidential; s.redirects := o.redirectUris.mkString("\n")
    s.postLogout := o.postLogoutRedirectUris.mkString("\n"); s.grants := o.grantTypes; s.scopes := o.scopes.mkString(" ")
    s.consent := o.consent; s.subMode := o.subMode; s.alg := o.signingAlg; s.accessTtl := o.accessTokenTtl; s.idTtl := o.idTokenTtl
    s.refreshTtl := o.refreshTokenTtl; s.includeGroups := o.includeGroups; s.backchannel := o.backchannelLogoutUri.getOrElse("")
    s.includeAppNames := o.includeAppNames
  }
  a.saml.foreach(fillSaml(s, _))
}

def fillSaml(s: State, m: SamlDto): Unit = {
  s.entityId := m.entityId; s.acsUrl := m.acsUrl; s.acsBinding := m.acsBinding; s.sloUrl := m.sloUrl.getOrElse("")
  s.nameIdFormat := m.nameIdFormat; s.nameIdExpr := m.nameIdExpr; s.signResponse := m.signResponse; s.signAssertion := m.signAssertion
  s.spCert := m.spCertificate.getOrElse(""); s.wantSigned := m.wantSignedRequests; s.sessionTtl := m.sessionTtl
}

def request(s: State): AppReq = {
  val saml = s.protocol.v == "saml"
  AppReq(
    slug = s.slug.v.trim, name = s.name.v.trim, description = s.desc.v.trim, protocol = s.protocol.v, enabled = s.enabled.v,
    launchUrl = Fmt.opt(s.launchUrl.v), showInPortal = s.showInPortal.v, requireMfa = s.requireMfa.v, ipAllow = Fmt.lines(s.ipAllow.v),
    restrictAccess = s.restrict.v, accessGroups = s.accessGroups.v.map(UUID.fromString),
    mappings = s.mappings.v.map(_.toDto).filter(m => m.name.nonEmpty && m.expression.nonEmpty),
    oidc = Option.when(!saml)(OidcDto(s.clientId.v.trim, s.confidential.v, Fmt.lines(s.redirects.v), Fmt.lines(s.postLogout.v), s.grants.v,
      s.scopes.v.split("[\\s,]+").toList.filter(_.nonEmpty), s.consent.v, s.subMode.v, s.alg.v, s.accessTtl.v, s.idTtl.v, s.refreshTtl.v,
      s.includeGroups.v, Fmt.opt(s.backchannel.v), s.includeAppNames.v)),
    saml = Option.when(saml)(SamlDto(s.entityId.v.trim, s.acsUrl.v.trim, s.acsBinding.v, Fmt.opt(s.sloUrl.v), s.nameIdFormat.v, s.nameIdExpr.v,
      s.signResponse.v, s.signAssertion.v, Fmt.opt(s.spCert.v), s.wantSigned.v, s.sessionTtl.v)))
}

def save(s: State, props: Props): Unit =
  if (isNew(props))
    Store.inline(Api.post[AppCreatedDto]("/api/admin/apps", Api.json(request(s))), s.error, s.busy) { r =>
      Toasts.show("アプリケーションを追加しました")
      r.clientSecret.foreach(x => pendingSecret := Some((r.app.id.toString, x)))
      Router.go(s"/admin/apps/${r.app.id}")
    }
  else
    Store.inline(Api.put[AppDto](s"/api/admin/apps/${props.id}", Api.json(request(s))), s.error, s.busy) { a => fill(s, a); Toasts.show("保存しました") }

def parseMetadata(s: State): Unit =
  Toasts.report(Api.postRaw[SamlDto]("/api/admin/saml/parse-metadata", s.metadata.v, Some("application/xml"))) { m =>
    fillSaml(s, m)
    s.metaOpen := false
    s.metadata := ""
    Toasts.show("メタデータを読み込みました。内容を確かめて保存してください")
  }

def loadMetaFile(s: State, e: org.scalajs.dom.Event): Unit = Dom.takeFiles(e).headOption.foreach { f =>
  f.asInstanceOf[scala.scalajs.js.Dynamic].text().asInstanceOf[scala.scalajs.js.Promise[String]].toFuture.foreach(s.metadata := _)
}

def rotateSecret(s: State, props: Props): Unit =
  Dialog.confirm("クライアントシークレットを作り直しますか？今のシークレットはすぐに使えなくなります。", "作り直す") {
    Toasts.report(Api.post[SecretDto](s"/api/admin/apps/${props.id}/secret"))(r => s.secret := r.clientSecret)
  }

def uploadIcon(s: State, props: Props, e: org.scalajs.dom.Event): Unit = Dom.takeFiles(e).headOption.foreach { f =>
  Img.upload(s"/api/admin/apps/${props.id}/icon", f).onComplete {
    case Success(_) => Toasts.show("アイコンを登録しました"); Api.get[AppDto](s"/api/admin/apps/${props.id}").foreach(a => s.app := Some(a))
    case Failure(x) => Toasts.error(x)
  }
}

/** サイトのアイコン（favicon）を取り直す（起動の URL などのサイトから）. */
def fetchIcon(s: State, props: Props): Unit =
  Toasts.report(Api.post[Option[AppDto]](s"/api/admin/apps/${props.id}/icon/fetch")) { a =>
    Toasts.show("サイトのアイコンを登録しました"); a.foreach(x => s.app := Some(x))
  }

def removeIcon(s: State, props: Props): Unit =
  Toasts.report(Api.delete(s"/api/admin/apps/${props.id}/icon"))(_ => Api.get[AppDto](s"/api/admin/apps/${props.id}").foreach(a => s.app := Some(a)))

def remove(s: State, props: Props): Unit = s.app.v.foreach { a =>
  Dialogs.typeToConfirm(s"アプリケーション「${a.name}」を削除します。このアプリへのログインはできなくなります。", a.slug, "削除する") {
    Toasts.report(Api.delete(s"/api/admin/apps/${props.id}")) { _ => Toasts.show("削除しました"); Router.go("/admin/apps") }
  }
}

def preview(s: State, props: Props, userId: UUID): Unit =
  Toasts.report(Api.post[Json](s"/api/admin/apps/${props.id}/preview", Api.json(PreviewReq(userId))))(j => s.preview := j.spaces2)

def isSaml(s: State) = s.protocol.mapC(_ == "saml")
def isOidc(s: State) = s.protocol.mapC(_ == "oidc")
def chosen(s: State) = s.protocol.mapC(_.nonEmpty)
def appList(s: State) = s.app.mapC(_.toList)
def infoList(s: State) = s.info.mapC(_.toList)
def secretList(s: State) = s.secret.mapC(_.toList)
def groupRows(s: State) = s.groups.mapC(GroupTree.flatten)
def title(s: State, props: Props) = computed {
  if (isNew(props)) (if (s.protocol.v == "saml") "SAML のアプリケーションを追加" else if (s.protocol.v == "oidc") "OIDC のアプリケーションを追加" else "アプリケーションを追加")
  else s.app.v.map(_.name).getOrElse("")
}
val grantTypes = OAuthGrants.labels
val nameIdFormats = List(
  "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" -> "メールアドレス",
  "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" -> "永続的な ID（persistent）",
  "urn:oasis:names:tc:SAML:2.0:nameid-format:transient" -> "一時的な ID（transient）",
  "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified" -> "指定なし（unspecified）")
</script>

<template>
  <section>
    <p class="small"><RouterLink to="/admin/apps">← アプリケーションの一覧</RouterLink></p>
    <div class="page-head">
      <template v-for="a in appList(s)"><AppIcon :name="a.name" :iconUrl="a.iconUrl" :size="40" /></template>
      <h1>{{ title(s, props) }}</h1>
      <template v-for="a in appList(s)">
        <label class="btn small">アイコンを選ぶ<input type="file" accept="image/png,image/jpeg,image/gif,image/webp,image/svg+xml" class="hidden" @change="uploadIcon(s, props, event)"></label>
        <button class="small" title="起動の URL（なければリダイレクト URI・ACS）のサイトのアイコンを取り込みます" @click="fetchIcon(s, props)">サイトのアイコンを取得</button>
        <button v-if="a.iconUrl.isDefined" class="ghost small" @click="removeIcon(s, props)">アイコンを外す</button>
        <button class="danger small" @click="remove(s, props)">削除</button>
      </template>
    </div>

    <!-- 方式を選ぶ -->
    <div v-if="!chosen(s).v" class="choose">
      <button class="pick" @click='choose(s, "oidc")'><b>OpenID Connect・OAuth 2.0</b><span class="small muted">多くの Web サービス・業務アプリ・API で使う方式</span></button>
      <button class="pick" @click='choose(s, "saml")'><b>SAML 2.0</b><span class="small muted">Microsoft 365・Salesforce など、SAML に対応したサービス</span></button>
    </div>

    <!-- 作った直後・作り直した後のシークレット -->
    <div v-for="x in secretList(s)" class="secret">
      <p class="small"><b>クライアントシークレット</b>です。この画面を離れると二度と表示できません。アプリの設定に貼り付けてください。</p>
      <template v-for="a in appList(s)"><CopyRow label="クライアント ID" :value="a.oidc.map(_.clientId).getOrElse(&quot;&quot;)" /></template>
      <CopyRow label="クライアントシークレット" :value="x" />
      <button class="small" @click="s.secret := None">閉じる</button>
    </div>

    <form v-if="chosen(s).v" @submit.prevent="save(s, props)">
      <section class="panel">
        <h2>基本</h2>
        <div class="grid2">
          <label class="field"><span>名前</span><input type="text" v-model="s.name" placeholder="経費精算システム"></label>
          <label class="field"><span>識別子（英小文字・数字・ハイフン）</span><input type="text" v-model="s.slug" class="mono" placeholder="expense" autocapitalize="none"></label>
        </div>
        <label class="field"><span>説明（ポータルに出ます）</span><input type="text" v-model="s.desc"></label>
        <label class="field"><span>開く URL（ポータルのボタンで開く）</span><input type="url" v-model="s.launchUrl" placeholder="https://"></label>
        <div class="grid2">
          <label class="check"><input type="checkbox" v-model="s.enabled"><span>有効</span></label>
          <label class="check"><input type="checkbox" v-model="s.showInPortal"><span>ポータルに出す</span></label>
          <label class="check"><input type="checkbox" v-model="s.requireMfa"><span>2段階認証を必須にする</span></label>
          <label class="check"><input type="checkbox" v-model="s.restrict"><span>使える人をグループで制限する</span></label>
        </div>
        <div v-if="s.restrict" class="group-list">
          <label v-for="gd in groupRows(s)" class="check" :style="GroupTree.indent(gd._2)">
            <input type="checkbox" :value="gd._1.id.toString" v-model="s.accessGroups"><span>{{ gd._1.name }}</span></label>
          <p v-if="s.groups.mapC(_.isEmpty)" class="muted small">グループはまだありません。</p>
        </div>
        <label class="field"><span>接続を許す IP アドレス（1行に1つ。CIDR も可。空ならどこからでも）</span>
          <textarea class="code" v-model="s.ipAllow" rows="3" placeholder="192.168.0.0/16"></textarea></label>
      </section>

      <section v-if="isOidc(s)" class="panel">
        <h2>OpenID Connect・OAuth 2.0</h2>
        <div class="grid2">
          <label class="field"><span>クライアント ID</span><input type="text" v-model="s.clientId" class="mono" placeholder="空なら自動で決めます"></label>
          <div class="field"><span>クライアントの種類</span>
            <label class="check"><input type="checkbox" v-model="s.confidential"><span>シークレットを使う（サーバーで動くアプリ）<span class="hint">ブラウザ・スマートフォン・デスクトップ・CLI だけで動くアプリは外して、PKCE を使います</span></span></label></div>
        </div>
        <label class="field"><span>リダイレクト URI（1行に1つ）</span><textarea class="code" v-model="s.redirects" rows="3" placeholder="https://app.example.com/callback"></textarea>
          <span class="hint">ネイティブアプリは、カスタムスキーム（com.example.app:/callback）か、ループバック（http://127.0.0.1/callback。シークレットを使わないアプリなら、ポートは実行のたびに違ってよい）を登録します。デバイスコードだけを使うアプリは空でかまいません</span></label>
        <label class="field"><span>ログアウト後のリダイレクト URI（1行に1つ・任意）</span><textarea class="code" v-model="s.postLogout" rows="2"></textarea></label>
        <div class="field"><span>使う方式（grant type）</span>
          <div class="chips"><label v-for="g in grantTypes" class="chip"><input type="checkbox" :value="g._1" v-model="s.grants"> {{ g._2 }}</label></div></div>
        <label class="field"><span>スコープ（空白で区切る）</span><input type="text" v-model="s.scopes" class="mono"></label>
        <div class="grid3">
          <label class="field"><span>同意の画面</span><select v-model="s.consent"><option value="implicit">出さない（社内のアプリ）</option><option value="explicit">出す</option></select></label>
          <label class="field"><span>ユーザーの識別子（sub）</span><select v-model="s.subMode"><option value="id">内部の ID（変わらない）</option><option value="username">ユーザー名</option><option value="email">メールアドレス</option></select></label>
          <label class="field"><span>署名のアルゴリズム</span><select v-model="s.alg"><option value="RS256">RS256</option><option value="ES256">ES256</option></select></label>
          <label class="field"><span>アクセストークンの有効期間（秒）</span><input type="number" min="60" v-model="s.accessTtl"></label>
          <label class="field"><span>ID トークンの有効期間（秒）</span><input type="number" min="60" v-model="s.idTtl"></label>
          <label class="field"><span>リフレッシュトークンの有効期間（秒）</span><input type="number" min="0" v-model="s.refreshTtl"></label>
        </div>
        <label class="check"><input type="checkbox" v-model="s.includeGroups"><span>ID トークンにグループ（groups）を入れる</span></label>
        <label class="check"><input type="checkbox" v-model="s.includeAppNames"><span>sbirds のサービス: アプリケーションの表示名を ID トークンに入れる（sbirds_apps・sbirds_app）</span></label>
        <label class="field"><span>バックチャネルログアウトの URI（任意）</span><input type="url" v-model="s.backchannel" placeholder="https://app.example.com/backchannel-logout"></label>
        <template v-for="a in appList(s)">
          <p v-if="a.oidc.exists(_.confidential)"><button type="button" class="small" @click="rotateSecret(s, props)">シークレットを作り直す</button></p>
        </template>
      </section>

      <section v-if="isSaml(s)" class="panel">
        <div class="row"><h2 class="grow">SAML 2.0</h2><button type="button" class="small" @click="s.metaOpen := !s.metaOpen.v">SP のメタデータから読み込む</button></div>
        <div v-if="s.metaOpen" class="meta">
          <label class="field"><span>SP のメタデータ（XML）を貼り付けてください</span><textarea class="code" v-model="s.metadata" rows="6"></textarea></label>
          <div class="row">
            <label class="btn small">ファイルから読む<input type="file" accept=".xml,application/xml,text/xml" class="hidden" @change="loadMetaFile(s, event)"></label>
            <span class="grow"></span>
            <button type="button" class="primary small" @click="parseMetadata(s)">読み込む</button>
          </div>
        </div>
        <label class="field"><span>SP のエンティティ ID</span><input type="text" v-model="s.entityId" class="mono"></label>
        <div class="grid2">
          <label class="field"><span>ACS の URL（応答の送り先）</span><input type="url" v-model="s.acsUrl" class="mono"></label>
          <label class="field"><span>ACS のバインディング</span><select v-model="s.acsBinding"><option value="post">HTTP-POST</option><option value="redirect">HTTP-Redirect</option></select></label>
          <label class="field"><span>シングルログアウトの URL（任意）</span><input type="url" v-model="s.sloUrl" class="mono"></label>
          <label class="field"><span>セッションの長さ（秒）</span><input type="number" min="60" v-model="s.sessionTtl"></label>
          <label class="field"><span>NameID の形式</span><select v-model="s.nameIdFormat"><option v-for="f in nameIdFormats" :value="f._1">{{ f._2 }}</option></select></label>
          <label class="field"><span>NameID の値（式）</span><input type="text" v-model="s.nameIdExpr" class="mono"></label>
        </div>
        <div class="grid2">
          <label class="check"><input type="checkbox" v-model="s.signResponse"><span>応答（Response）に署名する</span></label>
          <label class="check"><input type="checkbox" v-model="s.signAssertion"><span>アサーションに署名する</span></label>
          <label class="check"><input type="checkbox" v-model="s.wantSigned"><span>署名のない要求（AuthnRequest）を受け付けない</span></label>
        </div>
        <label class="field"><span>SP の証明書（PEM・要求の署名を確かめるとき）</span><textarea class="code" v-model="s.spCert" rows="4"></textarea></label>
      </section>

      <section v-if="chosen(s).v" class="panel">
        <h2>{{ if (isSaml(s).v) "渡す属性" else "追加のクレーム" }}</h2>
        <p class="small muted">{{ if (isSaml(s).v) "アサーションに入れる属性です。" else "ID トークン・UserInfo に加えるクレームです。スコープを書くと、そのスコープを要求されたときだけ渡します。" }}</p>
        <MappingEditor :rows="s.mappings" :saml="isSaml(s).v" />
        <ExprHelp />
        <template v-for="a in appList(s)">
          <h3>渡す情報を試す</h3>
          <p class="small muted">保存した設定で、選んだユーザーに渡す情報を表示します。</p>
          <div class="pick-user"><UserPicker :combo="true" :search="UserSearch.search" :hint="UserSearch.hint" :onPick="p => preview(s, props, UserSearch.id(p))" placeholder="ユーザーを選ぶ…" /></div>
          <pre v-if="s.preview.v.nonEmpty" class="json">{{ s.preview }}</pre>
        </template>
      </section>

      <p v-if="s.error.v.nonEmpty" class="error">{{ s.error }}</p>
      <div class="row save"><button type="submit" class="primary" :disabled="s.busy">{{ if (isNew(props)) "追加する" else "保存" }}</button></div>
    </form>

    <template v-for="a in appList(s)"><AppGroupNames :appId="a.id.toString" /></template>

    <section v-for="i in infoList(s)" class="panel">
      <h2>アプリに設定する値</h2>
      <template v-if="isSaml(s)">
        <CopyRow label="IdP のメタデータ" :value="i.samlMetadata" />
        <CopyRow label="IdP のエンティティ ID" :value="i.samlEntityId" />
        <CopyRow label="SSO の URL" :value="i.samlSsoUrl" />
        <CopyRow label="SLO の URL" :value="i.samlSloUrl" />
        <details><summary class="small">署名の証明書</summary><pre class="json">{{ i.samlCertificate }}</pre>
          <button type="button" class="small" @click="Dom.copy(i.samlCertificate)">コピー</button></details>
      </template>
      <template v-else>
        <template v-for="a in appList(s)"><CopyRow label="クライアント ID" :value="a.oidc.map(_.clientId).getOrElse(&quot;&quot;)" /></template>
        <CopyRow label="発行者（issuer）" :value="i.issuer" />
        <CopyRow label="ディスカバリー" :value="i.discovery" />
        <CopyRow label="認可エンドポイント" :value="i.authorizationEndpoint" />
        <CopyRow label="トークンエンドポイント" :value="i.tokenEndpoint" />
        <CopyRow label="UserInfo" :value="i.userinfoEndpoint" />
        <CopyRow label="JWKS" :value="i.jwksUri" />
        <CopyRow label="ログアウト" :value="i.endSessionEndpoint" />
      </template>
    </section>
  </section>
</template>

<style scoped>
.choose { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin: 1rem 0; }
.pick { flex-direction: column; align-items: flex-start; gap: .4rem; padding: 1.2rem; white-space: normal; text-align: left; border-radius: 12px; }
.pick:hover { border-color: var(--accent); }
.group-list { max-height: 260px; overflow-y: auto; border: 1px solid var(--line); border-radius: 8px; padding: .3rem .7rem; margin-bottom: .8rem; }
.meta { border: 1px dashed var(--line); border-radius: 8px; padding: .7rem; margin-bottom: .8rem; }
.pick-user { max-width: 360px; margin-bottom: .6rem; }
.save { margin-bottom: 1.5rem; }
@media (max-width: 720px) { .choose { grid-template-columns: 1fr; } }
</style>
