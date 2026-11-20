<script lang="scala">
import io.circe.syntax.*
import sruru.shared.*
import sruru.web.*
import sruru.web.parts.*

import java.util.UUID
import scala.scalajs.concurrent.JSExecutionContext.Implicits.queue
import scala.util.{Failure, Success}

// 管理: ユーザーの詳細（編集・パスワード・ロック・2段階認証・ログアウト・削除・アイコン・端末・トークン・証明書・外部 IdP・許可）
case class Props(id: String)

case class State(d: RV[Option[UserDetailDto]] = RV(None), groups: RV[List[GroupDto]] = RV(Nil), defs: RV[List[AttributeDefDto]] = RV(Nil),
                 username: RV[String] = RV(""), name: RV[String] = RV(""), email: RV[String] = RV(""), emailVerified: RV[Boolean] = RV(false),
                 givenN: RV[String] = RV(""), family: RV[String] = RV(""), isAdmin: RV[Boolean] = RV(false), isService: RV[Boolean] = RV(false),
                 disabled: RV[Boolean] = RV(false), mustChange: RV[Boolean] = RV(false), phone: RV[String] = RV(""), locale: RV[String] = RV(""),
                 zone: RV[String] = RV(""), groupIds: RV[List[String]] = RV(Nil), attrs: RV[List[AttrField]] = RV(Nil),
                 error: RV[String] = RV(""), busy: RV[Boolean] = RV(false),
                 pwOpen: RV[Boolean] = RV(false), pwMode: RV[String] = RV("generate"), pw: RV[String] = RV(""), pwMust: RV[Boolean] = RV(true),
                 pwMail: RV[Boolean] = RV(false), pwResult: RV[Option[String]] = RV(None), pwError: RV[String] = RV(""),
                 pem: RV[String] = RV(""), addingCert: RV[Boolean] = RV(false))

def initState() = State()

def uid(props: Props): String = props.id
def base(props: Props): String = s"/api/admin/users/${props.id}"

def mounted(s: State, props: Props): Unit = {
  pageTitle("ユーザー")
  Api.groups().foreach(s.groups := _)
  Api.attributeDefs().foreach { ds => s.defs := ds; load(s, props) }
}

def load(s: State, props: Props): Unit = Toasts.report(Api.get[UserDetailDto](base(props))) { d =>
  val u = d.user
  pageTitle(u.name)
  s.username := u.username; s.name := u.name; s.email := u.email.getOrElse(""); s.emailVerified := u.emailVerified
  s.givenN := u.givenName.getOrElse(""); s.family := u.familyName.getOrElse(""); s.isAdmin := u.isAdmin; s.isService := u.isService
  s.disabled := u.disabled; s.mustChange := u.mustChangePassword; s.phone := u.phoneNumber.getOrElse(""); s.locale := u.locale.getOrElse("")
  s.zone := u.zoneinfo.getOrElse(""); s.groupIds := u.directGroups.map(_.toString)
  s.attrs := Attrs.fields(s.defs.v, u.attributes)
  s.d := Some(d)
}

def reload(s: State, props: Props): Unit = Api.get[UserDetailDto](base(props)).foreach(d => s.d := Some(d))

def save(s: State, props: Props): Unit = s.d.v.foreach { d =>
  val req = UserReq(s.username.v.trim, s.name.v.trim, Fmt.opt(s.email.v), s.emailVerified.v, Fmt.opt(s.givenN.v), Fmt.opt(s.family.v),
    s.isAdmin.v, s.isService.v, s.disabled.v, s.mustChange.v, Attrs.build(d.user.attributes, s.attrs.v), None,
    Some(s.groupIds.v.map(UUID.fromString)), Fmt.opt(s.locale.v), Fmt.opt(s.zone.v), Fmt.opt(s.phone.v))
  Store.inline(Api.put[UserDto](base(props), Api.json(req)), s.error, s.busy) { _ => Toasts.show("保存しました"); load(s, props) }
}

// ---------------------------------------------------------------- 操作

def setPassword(s: State, props: Props): Unit = {
  val req = SetPasswordReq(if (s.pwMode.v == "input") Fmt.opt(s.pw.v) else None, s.pwMust.v, s.pwMode.v == "mail")
  Store.inline(Api.post[GeneratedPasswordDto](base(props) + "/password", Api.json(req)), s.pwError) { r =>
    s.pw := ""
    r.password match {
      case Some(p) if s.pwMode.v == "generate" => s.pwResult := Some(p)
      case _ =>
        s.pwOpen := false
        Toasts.show(if (s.pwMode.v == "mail") "再設定のメールを送りました" else "パスワードを設定しました")
    }
    reload(s, props)
  }
}

def openPw(s: State): Unit = { s.pwMode := "generate"; s.pw := ""; s.pwMust := true; s.pwResult := None; s.pwError := ""; s.pwOpen := true }

def act(s: State, props: Props, path: String, msg: String): Unit =
  Toasts.report(Api.postUnit(base(props) + path)) { _ => Toasts.show(msg); reload(s, props) }

def unlock(s: State, props: Props): Unit = act(s, props, "/unlock", "ロックを解除しました")

def resetMfa(s: State, props: Props): Unit =
  Dialog.confirm("2段階認証の登録（認証アプリ・回復コード）を消しますか？次のログインで登録し直しになります。", "消す") {
    act(s, props, "/reset-mfa", "2段階認証の登録を消しました")
  }

def forceLogout(s: State, props: Props): Unit =
  Dialog.confirm("すべての端末からログアウトさせ、発行したトークンを失効させますか？", "ログアウトさせる") {
    act(s, props, "/logout", "ログアウトさせました")
  }

def remove(s: State, props: Props): Unit = s.d.v.foreach { d =>
  Dialogs.typeToConfirm(s"ユーザー「${d.user.name}」を削除します。元に戻せません。", d.user.username, "削除する") {
    Toasts.report(Api.delete(base(props))) { _ => Toasts.show("削除しました"); Router.go("/admin/users") }
  }
}

def upload(s: State, props: Props, e: org.scalajs.dom.Event): Unit = Dom.takeFiles(e).headOption.foreach { f =>
  Img.upload(base(props) + "/avatar", f).onComplete {
    case Success(_) => Toasts.show("アイコンを登録しました"); reload(s, props)
    case Failure(x) => Toasts.error(x)
  }
}

def removeAvatar(s: State, props: Props): Unit =
  Toasts.report(Api.delete(base(props) + "/avatar")) { _ => Toasts.show("アイコンを外しました"); reload(s, props) }

def endSession(s: State, props: Props, x: LoginSessionDto): Unit =
  Toasts.report(Api.delete(base(props) + s"/sessions/${x.id}"))(_ => reload(s, props))

def removeToken(s: State, props: Props, t: ApiTokenDto): Unit =
  Dialog.confirm(s"API トークン「${t.name}」を削除しますか？", "削除") {
    Toasts.report(Api.delete(s"/api/admin/tokens/${t.id}"))(_ => reload(s, props))
  }

def addCert(s: State, props: Props): Unit =
  Toasts.report(Api.post[UserCertDto](base(props) + "/certs", CertReq(s.pem.v.trim).asJson)) { _ =>
    s.pem := ""; s.addingCert := false; Toasts.show("証明書を登録しました"); reload(s, props)
  }

def removeCert(s: State, props: Props, c: UserCertDto): Unit = Dialog.confirm(s"証明書「${c.subject}」を外しますか？", "外す") {
  Toasts.report(Api.delete(base(props) + s"/certs/${c.id}"))(_ => reload(s, props))
}

def revokeConsent(s: State, props: Props, c: ConsentDto): Unit = Dialog.confirm(s"「${c.app.name}」への許可を取り消しますか？（発行済みのトークンも失効します）", "取り消す") {
  Toasts.report(Api.delete(s"${base(props)}/consents/${c.app.id}"))(_ => reload(s, props))
}

def detail(s: State) = s.d.mapC(_.toList)
/** 手動で入れられるグループ（条件で決まるグループ・外部から同期したグループは除く）. */
def manualGroups(s: State) = s.groups.mapC(gs => GroupTree.flatten(gs).filter((g, _) => g.rule.isEmpty))
def dynamicGroups(s: State) = computed {
  s.d.v.toList.flatMap(d => d.user.groups.filterNot(g => d.user.directGroups.contains(g.id)))
}
def isMe(props: Props): Boolean = Store.myId.exists(_.toString == props.id)
</script>

<template>
  <section>
    <p class="small"><RouterLink to="/admin/users">← ユーザーの一覧</RouterLink></p>
    <template v-for="d in detail(s)">
      <div class="head">
        <Avatar :user="Some(Users.person(d.user))" :size="64" />
        <div class="grow">
          <h1>{{ d.user.name }}</h1>
          <div class="muted small mono">{{ d.user.username }}</div>
          <div class="row badges"><span v-for="b in Users.badges(d.user)" :class="b._2">{{ b._1 }}</span>
            <span v-if="d.user.mfaEnabled" class="badge ok">2段階認証</span>
            <span v-if="d.user.mustChangePassword" class="badge warn">パスワードの変更待ち</span></div>
        </div>
        <div class="row av-btns">
          <label class="btn small">アイコンを選ぶ<input type="file" accept="image/png,image/jpeg,image/gif,image/webp" class="hidden" @change="upload(s, props, event)"></label>
          <button v-if="d.user.avatarUrl.isDefined" class="ghost small" @click="removeAvatar(s, props)">外す</button>
        </div>
      </div>
      <div class="row ops">
        <button @click="openPw(s)">パスワードを設定</button>
        <button v-if="d.user.locked" @click="unlock(s, props)">ロックを解除</button>
        <button v-if="d.user.mfaEnabled" @click="resetMfa(s, props)">2段階認証をリセット</button>
        <button @click="forceLogout(s, props)">すべての端末からログアウト</button>
        <span class="grow"></span>
        <button v-if="!isMe(props)" class="danger" @click="remove(s, props)">削除</button>
      </div>
      <p class="small muted">作成 {{ Fmt.optDateTime(d.user.createdAt) }} ・ 最後のログイン {{ Fmt.optDateTime(d.user.lastLoginAt, "なし") }}
        <span v-if="d.user.failedAttempts > 0"> ・ 連続の失敗 {{ d.user.failedAttempts }} 回</span>
        <span v-if="d.user.lockedUntil.isDefined"> ・ ロックの解除 {{ Fmt.optDateTime(d.user.lockedUntil) }}</span>
        <span v-if='d.user.source != "local"'> ・ {{ d.user.source }} から同期（{{ d.user.externalId.getOrElse("") }}）</span></p>

      <form class="panel" @submit.prevent="save(s, props)">
        <h2>プロフィール</h2>
        <div class="grid2">
          <label class="field"><span>ユーザー名</span><input type="text" v-model="s.username" autocapitalize="none"></label>
          <label class="field"><span>表示名</span><input type="text" v-model="s.name"></label>
          <label class="field"><span>姓</span><input type="text" v-model="s.family"></label>
          <label class="field"><span>名</span><input type="text" v-model="s.givenN"></label>
          <label class="field"><span>メールアドレス</span><input type="email" v-model="s.email" @input="s.emailVerified := true"></label>
          <label class="field"><span>電話番号</span><input type="tel" v-model="s.phone"></label>
          <label class="field"><span>言語</span><input type="text" v-model="s.locale" placeholder="ja"></label>
          <label class="field"><span>タイムゾーン</span><input type="text" v-model="s.zone" placeholder="Asia/Tokyo"></label>
        </div>
        <div class="grid2">
          <label class="check"><input type="checkbox" v-model="s.emailVerified"><span>メールアドレスは確認済み（アドレスを書き換えると付きます。本人に確かめさせるときは外してください）<span v-if="d.user.email.isDefined && !d.user.emailVerified" class="hint">各サービスに渡すのは確認済みのアドレスだけです（いま渡している値: {{ d.user.verifiedEmail.getOrElse("なし") }}）</span></span></label>
          <label class="check"><input type="checkbox" v-model="s.isAdmin" :disabled="isMe(props)"><span>管理者<span v-if="d.user.effectiveAdmin && !d.user.isAdmin" class="hint">管理者のグループに入っているため管理者です</span></span></label>
          <label class="check"><input type="checkbox" v-model="s.disabled" :disabled="isMe(props)"><span>無効にする（ログインできなくする）</span></label>
          <label class="check"><input type="checkbox" v-model="s.isService"><span>サービスアカウント</span></label>
          <label class="check"><input type="checkbox" v-model="s.mustChange"><span>次のログインでパスワードを変更させる</span></label>
        </div>
        <template v-if="s.attrs.mapC(_.nonEmpty)">
          <h3>カスタム属性</h3>
          <AttrFields :fields="s.attrs.v" />
        </template>
        <h3>グループ</h3>
        <div class="group-list">
          <label v-for="gd in manualGroups(s)" class="check" :style="GroupTree.indent(gd._2)">
            <input type="checkbox" :value="gd._1.id.toString" v-model="s.groupIds"><span>{{ gd._1.name }}<span v-if="gd._1.isAdmin" class="badge accent">管理者</span></span>
          </label>
          <p v-if="manualGroups(s).mapC(_.isEmpty)" class="muted small">グループはまだありません。</p>
        </div>
        <p v-if="dynamicGroups(s).mapC(_.nonEmpty)" class="small muted">条件・同期で入っているグループ:
          <span v-for="g in dynamicGroups(s)" class="badge">{{ g.name }}</span></p>
        <p v-if="s.error.v.nonEmpty" class="error small">{{ s.error }}</p>
        <button type="submit" class="primary" :disabled="s.busy">保存</button>
      </form>

      <section class="panel">
        <h2>ログインしている端末</h2>
        <div v-if="d.sessions.nonEmpty" class="table-wrap">
          <table class="list">
            <thead><tr><th>ブラウザ</th><th>IP アドレス</th><th>ログイン</th><th>最後の操作</th><th></th></tr></thead>
            <tbody>
              <tr v-for="x in d.sessions" :key="x.id">
                <td>{{ Fmt.browser(x.userAgent) }}<div class="muted small">{{ Fmt.amr(x.amr) }}</div></td>
                <td class="small mono">{{ x.ip.getOrElse("") }}</td>
                <td class="small nowrap">{{ Fmt.dateTime(x.createdAt) }}</td>
                <td class="small nowrap">{{ Fmt.ago(x.lastSeenAt) }}</td>
                <td><button class="ghost small" @click="endSession(s, props, x)">ログアウト</button></td>
              </tr>
            </tbody>
          </table>
        </div>
        <p v-else class="muted small">ログインしている端末はありません。</p>
      </section>

      <section class="panel">
        <h2>API トークン</h2>
        <p class="small muted">このユーザーとして API を使うトークンです（サービスアカウントの連携などに使います）。</p>
        <TokenCreator :url='base(props) + "/tokens"' :allowAdmin="true" :onCreated="_ => reload(s, props)" />
        <div v-if="d.tokens.nonEmpty" class="table-wrap tbl">
          <table class="list">
            <thead><tr><th>用途</th><th>トークン</th><th>スコープ</th><th>有効期限</th><th>最後の使用</th><th></th></tr></thead>
            <tbody>
              <tr v-for="t in d.tokens" :key="t.id">
                <td>{{ t.name }}</td><td><code>{{ t.prefix }}…</code></td><td class="small">{{ t.scopes.mkString(", ") }}</td>
                <td class="small nowrap">{{ t.expiresAt.map(Fmt.date).getOrElse("無期限") }}</td>
                <td class="small nowrap">{{ Fmt.optAgo(t.lastUsedAt, "未使用") }}</td>
                <td><button class="ghost small" @click="removeToken(s, props, t)">削除</button></td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section class="panel">
        <div class="row"><h2 class="grow">クライアント証明書</h2><button class="small" @click="s.addingCert := !s.addingCert.v">＋ 登録</button></div>
        <div v-if="s.addingCert" class="add">
          <label class="field"><span>証明書（PEM 形式）</span><textarea class="code" v-model="s.pem"></textarea></label>
          <button class="primary small" @click="addCert(s, props)">登録する</button>
        </div>
        <div v-if="d.certs.nonEmpty" class="table-wrap">
          <table class="list">
            <thead><tr><th>サブジェクト</th><th>発行者</th><th>有効期限</th><th></th></tr></thead>
            <tbody>
              <tr v-for="c in d.certs" :key="c.id">
                <td class="small break">{{ c.subject }}</td><td class="small break">{{ c.issuer }}</td><td class="small nowrap">{{ Fmt.date(c.notAfter) }}</td>
                <td><button class="ghost small" @click="removeCert(s, props, c)">外す</button></td>
              </tr>
            </tbody>
          </table>
        </div>
        <p v-else class="muted small">登録した証明書はありません。</p>
      </section>

      <section class="panel">
        <h2>外部 IdP のアカウント</h2>
        <div v-if="d.identities.nonEmpty" class="table-wrap">
          <table class="list">
            <thead><tr><th>IdP</th><th>サブジェクト</th><th>メールアドレス</th><th>最後のログイン</th></tr></thead>
            <tbody>
              <tr v-for="i in d.identities">
                <td>{{ i.providerName }}</td><td class="small mono break">{{ i.subject }}</td><td class="small">{{ i.email.getOrElse("") }}</td>
                <td class="small nowrap">{{ Fmt.optDateTime(i.lastLoginAt, "なし") }}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <p v-else class="muted small">つながっている外部 IdP のアカウントはありません。</p>
      </section>

      <section class="panel">
        <h2>許可したアプリケーション</h2>
        <div v-if="d.consents.nonEmpty" class="table-wrap">
          <table class="list">
            <thead><tr><th>アプリケーション</th><th>許可した情報</th><th>日時</th><th></th></tr></thead>
            <tbody>
              <tr v-for="c in d.consents">
                <td>{{ c.app.name }}</td><td class="small">{{ c.scopes.mkString(", ") }}</td><td class="small nowrap">{{ Fmt.date(c.createdAt) }}</td>
                <td><button class="small danger" @click="revokeConsent(s, props, c)">取り消す</button></td>
              </tr>
            </tbody>
          </table>
        </div>
        <p v-else class="muted small">ありません。</p>
      </section>

      <Modal v-if="s.pwOpen" :onClose="_ => s.pwOpen := false">
        <h2>パスワードを設定</h2>
        <template v-if="s.pwResult.mapC(_.isEmpty)">
          <form @submit.prevent="setPassword(s, props)">
            <div class="stack">
              <label class="check"><input type="radio" value="generate" v-model="s.pwMode"><span>生成する（画面に一度だけ表示します）</span></label>
              <label class="check"><input type="radio" value="input" v-model="s.pwMode"><span>入力する</span></label>
              <label class="check"><input type="radio" value="mail" v-model="s.pwMode"><span>本人に再設定のメールを送る</span></label>
            </div>
            <label v-if='s.pwMode.v == "input"' class="field"><span>新しいパスワード</span><input type="text" v-model="s.pw" autocomplete="off"></label>
            <label v-if='s.pwMode.v != "mail"' class="check"><input type="checkbox" v-model="s.pwMust"><span>次のログインで変更させる</span></label>
            <p v-if="s.pwError.v.nonEmpty" class="error small">{{ s.pwError }}</p>
            <div class="actions"><button type="button" @click="s.pwOpen := false">キャンセル</button><button type="submit" class="primary">設定する</button></div>
          </form>
        </template>
        <template v-for="p in s.pwResult.mapC(_.toList)">
          <p class="small">新しいパスワードです。<b>この画面を閉じると二度と表示できません。</b>本人に安全な方法で伝えてください。</p>
          <CopyRow :value="p" />
          <div class="actions"><button class="primary" @click="s.pwOpen := false">閉じる</button></div>
        </template>
      </Modal>
    </template>
  </section>
</template>

<style scoped>
.head { display: flex; gap: 1rem; align-items: center; flex-wrap: wrap; margin-bottom: .8rem; }
.head h1 { margin: 0; }
.badges { margin-top: .3rem; gap: .3rem; }
.ops { margin: .6rem 0; }
.group-list { max-height: 320px; overflow-y: auto; border: 1px solid var(--line); border-radius: 8px; padding: .3rem .7rem; margin-bottom: .6rem; }
.group-list .badge { margin-left: .4rem; }
.tbl { margin-top: 1rem; }
.add { margin-bottom: .8rem; }
</style>
