<script lang="scala">
import io.circe.syntax.*
import sruru.shared.*
import sruru.web.*
import sruru.web.parts.*

import scala.scalajs.concurrent.JSExecutionContext.Implicits.queue

// 個人設定: セキュリティ（パスワード・2段階認証・証明書・通知（プッシュ）・ログインしている端末・許可したアプリ・画面の色）
case class State(current: RV[String] = RV(""), next: RV[String] = RV(""), next2: RV[String] = RV(""), pwError: RV[String] = RV(""),
                 pwBusy: RV[Boolean] = RV(false),
                 totp: RV[Option[TotpSetupDto]] = RV(None), totpName: RV[String] = RV("認証アプリ"), totpCode: RV[String] = RV(""),
                 totpError: RV[String] = RV(""), codes: RV[List[String]] = RV(Nil),
                 certs: RV[List[UserCertDto]] = RV(Nil), pem: RV[String] = RV(""), addingCert: RV[Boolean] = RV(false),
                 sessions: RV[List[LoginSessionDto]] = RV(Nil), consents: RV[List[ConsentDto]] = RV(Nil))

def initState() = State()

def mounted(s: State): Unit = {
  pageTitle("セキュリティ")
  loadCerts(s)
  loadSessions(s)
  Api.get[List[ConsentDto]]("/api/me/consents").foreach(s.consents := _)
}

def loadCerts(s: State): Unit = Api.get[List[UserCertDto]]("/api/me/certs").foreach(s.certs := _)
def loadSessions(s: State): Unit = Api.get[List[LoginSessionDto]]("/api/me/sessions").foreach(s.sessions := _)

// ---------------------------------------------------------------- パスワード

def changePassword(s: State): Unit =
  if (s.next.v != s.next2.v) s.pwError := "確認のパスワードが一致しません"
  else Store.inline(Api.postUnit("/api/me/password", PasswordChangeReq(s.current.v, s.next.v).asJson), s.pwError, s.pwBusy) { _ =>
    s.current := ""; s.next := ""; s.next2 := ""
    Toasts.show("パスワードを変更しました")
    Store.reloadMe()
  }

// ---------------------------------------------------------------- 2段階認証

def startTotp(s: State): Unit = Toasts.report(Api.post[TotpSetupDto]("/api/me/totp")) { t => s.totp := Some(t); s.totpCode := ""; s.totpError := "" }

def verifyTotp(s: State): Unit = s.totp.v.foreach { t =>
  Store.inline(Api.post[RecoveryCodesDto]("/api/me/totp/verify", TotpVerifyReq(t.id, s.totpCode.v.replace(" ", "").trim, s.totpName.v.trim).asJson),
    s.totpError) { r =>
    s.totp := None
    s.codes := r.codes
    Toasts.show("認証アプリを登録しました")
    Store.reloadMe()
  }
}

def removeTotp(t: TotpDto): Unit = Dialog.confirm(s"認証アプリ「${t.name}」を外しますか？", "外す") {
  Toasts.report(Api.delete(s"/api/me/totp/${t.id}")) { _ => Toasts.show("外しました"); Store.reloadMe() }
}

def regenerate(s: State): Unit =
  Dialog.confirm("回復コードを作り直しますか？今までのコードは使えなくなります。", "作り直す") {
    Toasts.report(Api.post[RecoveryCodesDto]("/api/me/recovery-codes")) { r => s.codes := r.codes; Store.reloadMe() }
  }

// ---------------------------------------------------------------- 証明書

def addCert(s: State): Unit = Toasts.report(Api.post[UserCertDto]("/api/me/certs", CertReq(s.pem.v.trim).asJson)) { _ =>
  s.pem := ""; s.addingCert := false; Toasts.show("証明書を登録しました"); loadCerts(s)
}

def removeCert(s: State, c: UserCertDto): Unit = Dialog.confirm(s"証明書「${c.subject}」を外しますか？", "外す") {
  Toasts.report(Api.delete(s"/api/me/certs/${c.id}"))(_ => loadCerts(s))
}

def loadPemFile(s: State, e: org.scalajs.dom.Event): Unit = Dom.takeFiles(e).headOption.foreach { f =>
  f.asInstanceOf[scala.scalajs.js.Dynamic].text().asInstanceOf[scala.scalajs.js.Promise[String]].toFuture.foreach(s.pem := _)
}

// ---------------------------------------------------------------- 端末・許可

def endSession(s: State, x: LoginSessionDto): Unit = Toasts.report(Api.delete(s"/api/me/sessions/${x.id}"))(_ => loadSessions(s))

def endOthers(s: State): Unit = Dialog.confirm("この端末以外のログインをすべて終わらせますか？", "終わらせる") {
  Toasts.report(Api.delete("/api/me/sessions"))(_ => loadSessions(s))
}

def revoke(s: State, c: ConsentDto): Unit =
  Dialog.confirm(s"「${c.app.name}」への許可を取り消しますか？このアプリでは、もう一度ログインと許可が必要になります。", "取り消す") {
    Toasts.report(Api.delete(s"/api/me/consents/${c.app.id}")) { _ => s.consents := s.consents.v.filterNot(_.app.id == c.app.id) }
  }

def me = Store.me.mapC(_.toList)
def canPassword = Store.me.mapC(_.exists(m => m.passwordSet || m.source == "local"))
def rules = Store.me.mapC(_.map(_.passwordRules).getOrElse(Nil))
def setup(s: State) = s.totp.mapC(_.toList)
def showCerts(s: State) = computed { Store.config.v.exists(_.certEnabled) || s.certs.v.nonEmpty }
def others(s: State) = s.sessions.mapC(_.exists(!_.current))
</script>

<template>
  <div class="page narrow">
    <h1>個人設定</h1>
    <MeTabs />
    <template v-for="m in me">
      <form v-if="canPassword" class="panel" @submit.prevent="changePassword(s)">
        <h2>パスワード</h2>
        <div class="grid3">
          <label v-if="m.passwordSet" class="field"><span>今のパスワード</span><input type="password" v-model="s.current" autocomplete="current-password"></label>
          <label class="field"><span>新しいパスワード</span><input type="password" v-model="s.next" autocomplete="new-password"></label>
          <label class="field"><span>新しいパスワード（確認）</span><input type="password" v-model="s.next2" autocomplete="new-password"></label>
        </div>
        <ul v-if="rules.mapC(_.nonEmpty)" class="rules small muted"><li v-for="r in rules">{{ r }}</li></ul>
        <p v-if="s.pwError.v.nonEmpty" class="error small">{{ s.pwError }}</p>
        <button type="submit" class="primary" :disabled="s.pwBusy">{{ if (m.passwordSet) "変更する" else "設定する" }}</button>
      </form>

      <section class="panel">
        <h2>2段階認証</h2>
        <p class="small muted">ログインのときに、パスワードに加えて認証アプリのコードを入力します。
          <span v-if="m.mfa.required" class="badge warn">このアカウントでは必須です</span></p>
        <div v-if="m.mfa.totp.nonEmpty" class="table-wrap">
          <table class="list">
            <thead><tr><th>認証アプリ</th><th>登録した日</th><th></th></tr></thead>
            <tbody>
              <tr v-for="t in m.mfa.totp" :key="t.id">
                <td>{{ t.name }}</td><td class="small">{{ Fmt.date(t.createdAt) }}</td>
                <td class="nowrap right-cell"><button class="ghost small" @click="removeTotp(t)">外す</button></td>
              </tr>
            </tbody>
          </table>
        </div>
        <p v-else class="small">認証アプリはまだ登録していません。</p>
        <template v-if="setup(s).mapC(_.isEmpty)">
          <p><button @click="startTotp(s)">＋ 認証アプリを登録する</button></p>
        </template>
        <div v-for="t in setup(s)" class="enroll">
          <p class="small">スマートフォンの認証アプリ（Google Authenticator・Microsoft Authenticator など）でこの QR コードを読み取り、表示された 6 桁のコードを入力してください。</p>
          <QrCode :uri="t.uri" :secret="t.secret" />
          <form @submit.prevent="verifyTotp(s)">
            <div class="grid2">
              <label class="field"><span>名前（どの端末か分かるように）</span><input type="text" v-model="s.totpName"></label>
              <label class="field"><span>認証アプリのコード</span><input type="text" v-model="s.totpCode" inputmode="numeric" autocomplete="one-time-code" class="otp"></label>
            </div>
            <p v-if="s.totpError.v.nonEmpty" class="error small">{{ s.totpError }}</p>
            <div class="row"><button type="submit" class="primary">登録する</button><button type="button" @click="s.totp := None">やめる</button></div>
          </form>
        </div>
        <template v-if="m.mfa.totp.nonEmpty">
          <h3>回復コード</h3>
          <p class="small">残り {{ m.mfa.recoveryRemaining }} 個。認証アプリを使えなくなったときに使います。</p>
          <p><button class="small" @click="regenerate(s)">回復コードを作り直す</button></p>
        </template>
        <div v-if="s.codes.mapC(_.nonEmpty)" class="secret">
          <RecoveryCodes :codes="s.codes.v" />
          <button class="small" @click="s.codes := Nil">閉じる</button>
        </div>
        <p v-if="m.mfa.emailAvailable" class="small muted">認証アプリが手元にないときは、メールで届くコードでもログインできます。</p>
      </section>

      <section v-if="showCerts(s)" class="panel">
        <div class="row"><h2 class="grow">クライアント証明書</h2><button class="small" @click="s.addingCert := !s.addingCert.v">＋ 登録</button></div>
        <p class="small muted">登録した証明書を使って、パスワードなしでログインできます。</p>
        <div v-if="s.addingCert" class="add-cert">
          <label class="field"><span>証明書（PEM 形式。-----BEGIN CERTIFICATE----- から）</span><textarea class="code" v-model="s.pem"></textarea></label>
          <div class="row">
            <label class="btn small">ファイルから読む<input type="file" accept=".pem,.crt,.cer" class="hidden" @change="loadPemFile(s, event)"></label>
            <span class="grow"></span>
            <button class="primary small" @click="addCert(s)">登録する</button>
          </div>
        </div>
        <div v-if="s.certs.mapC(_.nonEmpty)" class="table-wrap">
          <table class="list">
            <thead><tr><th>サブジェクト</th><th>発行者</th><th>有効期限</th><th></th></tr></thead>
            <tbody>
              <tr v-for="c in s.certs" :key="c.id">
                <td class="small break">{{ c.subject }}</td><td class="small break">{{ c.issuer }}</td><td class="small nowrap">{{ Fmt.date(c.notAfter) }}</td>
                <td><button class="ghost small" @click="removeCert(s, c)">外す</button></td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section class="panel">
        <h2>通知</h2>
        <p class="small muted">パスワードの変更・2段階認証の解除・アカウントのロックなど、アカウントの安全にかかわる出来事を、この端末に通知します。</p>
        <p><PushToggle /></p>
      </section>

      <section class="panel">
        <div class="row"><h2 class="grow">ログインしている端末</h2><button v-if="others(s)" class="small" @click="endOthers(s)">ほかの端末をすべてログアウト</button></div>
        <div class="table-wrap">
          <table class="list">
            <thead><tr><th>ブラウザ</th><th>IP アドレス</th><th>ログイン</th><th>最後の操作</th><th></th></tr></thead>
            <tbody>
              <tr v-for="x in s.sessions" :key="x.id">
                <td>{{ Fmt.browser(x.userAgent) }} <span v-if="x.current" class="badge accent">この端末</span><div class="muted small">{{ Fmt.amr(x.amr) }}</div></td>
                <td class="small mono">{{ x.ip.getOrElse("") }}</td>
                <td class="small nowrap">{{ Fmt.dateTime(x.createdAt) }}</td>
                <td class="small nowrap">{{ Fmt.ago(x.lastSeenAt) }}</td>
                <td><button v-if="!x.current" class="ghost small" @click="endSession(s, x)">ログアウト</button></td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section class="panel">
        <h2>許可したアプリケーション</h2>
        <div v-if="s.consents.mapC(_.nonEmpty)" class="table-wrap">
          <table class="list">
            <thead><tr><th>アプリケーション</th><th>許可した情報</th><th>日時</th><th></th></tr></thead>
            <tbody>
              <tr v-for="c in s.consents" :key="c.app.id">
                <td><div class="row"><AppIcon :name="c.app.name" :iconUrl="c.app.iconUrl" :size="24" />{{ c.app.name }}</div></td>
                <td class="small">{{ c.scopes.mkString(", ") }}</td>
                <td class="small nowrap">{{ Fmt.date(c.createdAt) }}</td>
                <td><button class="ghost small" @click="revoke(s, c)">取り消す</button></td>
              </tr>
            </tbody>
          </table>
        </div>
        <p v-else class="small muted">許可したアプリケーションはありません。</p>
      </section>

      <section class="panel">
        <h2>画面の色</h2>
        <p class="small muted">この端末に記憶します。</p>
        <div class="chips">
          <button v-for="o in Theme.options" :class='if (Theme.current.v == o._1) "chip active" else "chip"' @click="Theme.set(o._1)">{{ o._2 }}</button>
        </div>
      </section>
    </template>
  </div>
</template>

<style scoped>
.rules { margin: 0 0 .8rem; padding-left: 1.2rem; }
.enroll { border: 1px solid var(--line); border-radius: 10px; padding: .8rem 1rem; margin: .8rem 0; }
.add-cert { margin-bottom: .8rem; }
.right-cell { text-align: right; }
</style>
