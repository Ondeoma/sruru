<script lang="scala">
import io.circe.syntax.*
import sruru.shared.*
import sruru.web.*
import sruru.web.parts.*

import java.util.UUID
import scala.concurrent.Future
import scala.util.Try

// ログイン. 段階（FlowDto.stage）ごとに表示を変える:
// identify（ユーザー名とパスワード）→ mfa（2つ目の要素）/ enroll_mfa（認証アプリの登録）→ show_recovery（回復コード）
// → change_password（パスワードの変更）→ done（アプリ・ポータルへ移る）
case class State(flow: RV[Option[FlowDto]] = RV(None),
                 error: RV[String] = RV(""),
                 busy: RV[Boolean] = RV(false),
                 username: RV[String] = RV(""),
                 password: RV[String] = RV(""),
                 method: RV[String] = RV("totp"),
                 code: RV[String] = RV(""),
                 next: RV[String] = RV(""),
                 next2: RV[String] = RV(""),
                 register: RV[Boolean] = RV(false),
                 regName: RV[String] = RV(""),
                 regEmail: RV[String] = RV(""))

def initState() = State()

def mounted(s: State): Unit = {
  pageTitle("ログイン")
  val start: Future[FlowDto] = Api.param("flow") match {
    case Some(f) => Api.get[FlowDto](s"/api/login/flow/${Api.enc(f)}")
    case None =>
      val req = LoginStartReq(
        requestId = Api.param("req").flatMap(r => Try(UUID.fromString(r)).toOption),
        returnTo = Api.param("returnTo").filter(_.startsWith("/")),
        add = Api.param("add").contains("1"),
        stepUp = Api.param("stepup").contains("1"))
      Api.post[FlowDto]("/api/login/start", req.asJson)
  }
  Store.inline(start, s.error, s.busy)(set(s, _))
}

/** 次の段階を表示する（done ならブラウザごと移る. /auth/resume などはサーバーの画面のため）. */
def set(s: State, f: FlowDto): Unit = {
  s.code := ""
  s.error := f.message.filter(_ => f.stage == "error").getOrElse("")
  if (f.stage == "done") f.redirect.foreach(Nav.goto)
  else {
    if (f.stage == "mfa" && !f.mfaMethods.contains(s.method.v)) s.method := f.mfaMethods.headOption.getOrElse("totp")
    if (s.username.v.isEmpty) f.user.map(_.username).orElse(f.request.flatMap(_.loginHint)).foreach(s.username := _)
    s.flow := Some(f)
  }
}

def call(s: State, url: String, body: io.circe.Json): Unit =
  if (!s.busy.v) Store.inline(Api.post[FlowDto](url, body), s.error, s.busy)(set(s, _))

def id(s: State): UUID = s.flow.v.get.id

def login(s: State): Unit = call(s, "/api/login/password", PasswordLoginReq(id(s), s.username.v.trim, s.password.v).asJson)

def doRegister(s: State): Unit =
  call(s, "/api/login/register", RegisterReq(id(s), s.username.v.trim, s.regEmail.v.trim, s.regName.v.trim, s.password.v).asJson)

def mfa(s: State): Unit = call(s, "/api/login/mfa", MfaReq(id(s), s.method.v, s.code.v.replace(" ", "").trim).asJson)

def sendEmail(s: State): Unit = { s.method := "email"; call(s, "/api/login/mfa/email", FlowReq(id(s)).asJson) }

def startEnroll(s: State): Unit = call(s, "/api/login/enroll/totp", FlowReq(id(s)).asJson)

def verifyEnroll(s: State): Unit = s.flow.v.flatMap(_.totpSetup).foreach { t =>
  call(s, "/api/login/enroll/totp/verify", FlowTotpVerifyReq(id(s), t.id, s.code.v.replace(" ", "").trim).asJson)
}

def continue(s: State): Unit = call(s, "/api/login/continue", FlowReq(id(s)).asJson)

def changePassword(s: State): Unit =
  if (s.next.v != s.next2.v) s.error := "確認のパスワードが一致しません"
  else call(s, "/api/login/change-password", FlowPasswordReq(id(s), s.next.v).asJson)

/** 外部の IdP・証明書でのログイン（ブラウザごと移る. 戻ってきたら ?flow= で続ける）. */
def federated(s: State, p: ProviderBriefDto): Unit = Nav.goto(s"/auth/fed/${p.slug}/start?flow=${id(s)}")
def cert(s: State): Unit = Nav.goto(s"/auth/cert?flow=${id(s)}")

/** 最初からやり直す（flow を外す）. */
def restart(): Unit = {
  val keep = List("req", "returnTo", "add", "stepup", "reauth").flatMap(k => Api.param(k).map(k -> _))
  Nav.goto("/login" + Api.query(keep.map((k, v) => k -> Some(v))*))
}

def stage(s: State) = s.flow.mapC(_.map(_.stage).getOrElse(""))
def is(s: State, st: String) = s.flow.mapC(_.exists(_.stage == st))
def app(s: State) = s.flow.mapC(_.flatMap(_.request).map(_.app).toList)
def flowUser(s: State) = s.flow.mapC(_.flatMap(_.user).toList)
def cfg = Store.config.mapC(_.toList)
def methods(s: State) = s.flow.mapC(_.map(_.mfaMethods).getOrElse(Nil))
def hasMethod(s: State, m: String) = s.flow.mapC(_.exists(_.mfaMethods.contains(m)))
def rules(s: State) = s.flow.mapC(_.map(_.passwordRules).filter(_.nonEmpty).orElse(Store.config.v.map(_.passwordRules)).getOrElse(Nil))
def codes(s: State) = s.flow.mapC(_.map(_.recoveryCodes).getOrElse(Nil))
def setup(s: State) = s.flow.mapC(_.flatMap(_.totpSetup).toList)
def emailHint(s: State) = s.flow.mapC(_.flatMap(_.emailHint).getOrElse("登録したメールアドレス"))
def emailSent(s: State) = s.flow.mapC(_.exists(_.emailSent))
def isStepUp: Boolean = Api.param("stepup").contains("1")
def isReauth: Boolean = Api.param("reauth").contains("1")
def isAdd: Boolean = Api.param("add").contains("1")
def codeLabel(s: State) = s.method.mapC {
  case "email"    => "メールで届いたコード"
  case "recovery" => "回復コード"
  case _          => "認証アプリに表示されている 6 桁のコード"
}
</script>

<template>
  <PublicCard>
    <template v-for="a in app(s)">
      <div class="app-head">
        <AppIcon :name="a.name" :iconUrl="a.iconUrl" :size="44" />
        <div class="small muted">「{{ a.name }}」にログインします</div>
      </div>
    </template>
    <template v-for="u in flowUser(s)">
      <div v-if='stage(s).v != "identify"' class="user-chip">
        <Avatar :user="Some(Users.person(UserBrief(id(s), u.username, u.name, u.avatarUrl)))" :size="28" />
        <div class="grow"><div>{{ u.name }}</div><div class="muted small">{{ u.username }}</div></div>
      </div>
    </template>

    <p v-if="s.flow.mapC(_.isEmpty).v && s.busy.v" class="muted center">読み込んでいます…</p>

    <!-- ユーザー名とパスワード -->
    <template v-if='is(s, "identify").v && !s.register.v'>
      <h1>{{ if (isStepUp) "もう一度ログインしてください" else if (isAdd) "別のアカウントでログイン" else "ログイン" }}</h1>
      <template v-for="c in cfg"><p v-if="c.loginMessage.nonEmpty" class="notice small msg">{{ c.loginMessage }}</p></template>
      <p v-if="isReauth" class="notice small msg">大切な設定を変えるため、本人確認としてもう一度ログインしてください。</p>
      <form @submit.prevent="login(s)">
        <label class="field"><span>ユーザー名またはメールアドレス</span><input type="text" v-model="s.username" autocomplete="username" autocapitalize="none" v-focus></label>
        <label class="field"><span>パスワード</span><input type="password" v-model="s.password" autocomplete="current-password"></label>
        <p v-if="s.error.v.nonEmpty" class="error small">{{ s.error }}</p>
        <button type="submit" class="primary block" :disabled="s.busy">ログイン</button>
      </form>
      <div class="links small">
        <RouterLink to="/forgot">パスワードを忘れた場合</RouterLink>
      </div>
      <template v-for="c in cfg">
        <template v-if="c.providers.nonEmpty || c.certEnabled">
          <div class="divider">または</div>
          <div class="stack">
            <button v-for="p in c.providers" type="button" class="block" @click="federated(s, p)">{{ p.name }} でログイン</button>
            <button v-if="c.certEnabled" type="button" class="block" @click="cert(s)">証明書でログイン</button>
          </div>
        </template>
        <p v-if="c.selfRegistration" class="center small reg">アカウントがない場合は <a href="#" @click.prevent="s.register := true; s.error := &quot;&quot;">アカウントを作る</a></p>
      </template>
    </template>

    <!-- アカウントを作る -->
    <template v-if='is(s, "identify").v && s.register.v'>
      <h1>アカウントを作る</h1>
      <form @submit.prevent="doRegister(s)">
        <label class="field"><span>ユーザー名</span><input type="text" v-model="s.username" autocomplete="username" autocapitalize="none"></label>
        <label class="field"><span>名前</span><input type="text" v-model="s.regName" autocomplete="name" placeholder="山田 太郎"></label>
        <label class="field"><span>メールアドレス</span><input type="email" v-model="s.regEmail" autocomplete="email"></label>
        <label class="field"><span>パスワード</span><input type="password" v-model="s.password" autocomplete="new-password"></label>
        <ul v-if="rules(s).mapC(_.nonEmpty)" class="rules small muted"><li v-for="r in rules(s)">{{ r }}</li></ul>
        <p v-if="s.error.v.nonEmpty" class="error small">{{ s.error }}</p>
        <button type="submit" class="primary block" :disabled="s.busy">アカウントを作る</button>
      </form>
      <p class="center small reg"><a href="#" @click.prevent="s.register := false; s.error := &quot;&quot;">ログインに戻る</a></p>
    </template>

    <!-- 2つ目の要素 -->
    <template v-if='is(s, "mfa").v'>
      <h1>2段階認証</h1>
      <p v-if='s.method.v == "email" && emailSent(s).v' class="small notice ok">{{ emailHint(s) }} にコードを送りました。</p>
      <form @submit.prevent="mfa(s)">
        <label class="field"><span>{{ codeLabel(s) }}</span>
          <input type="text" v-model="s.code" :class='if (s.method.v == "recovery") "" else "otp"' inputmode="numeric" autocomplete="one-time-code" v-focus></label>
        <p v-if="s.error.v.nonEmpty" class="error small">{{ s.error }}</p>
        <button type="submit" class="primary block" :disabled="s.busy">確認</button>
      </form>
      <div class="stack alt small">
        <a v-if='hasMethod(s, "totp").v && s.method.v != "totp"' href="#" @click.prevent='s.method := "totp"; s.code := ""'>認証アプリのコードを使う</a>
        <a v-if='hasMethod(s, "email").v' href="#" @click.prevent="sendEmail(s)">{{ if (emailSent(s).v) "メールのコードをもう一度送る" else "メールでコードを受け取る" }}</a>
        <a v-if='hasMethod(s, "recovery").v && s.method.v != "recovery"' href="#" @click.prevent='s.method := "recovery"; s.code := ""'>回復コードを使う</a>
      </div>
    </template>

    <!-- 認証アプリの登録（必須のとき） -->
    <template v-if='is(s, "enroll_mfa").v'>
      <h1>2段階認証の設定</h1>
      <template v-if="setup(s).mapC(_.isEmpty)">
        <p class="small">このアカウントでは 2 段階認証が必要です。スマートフォンの認証アプリ（Google Authenticator・Microsoft Authenticator など）を用意してください。</p>
        <p v-if="s.error.v.nonEmpty" class="error small">{{ s.error }}</p>
        <button class="primary block" :disabled="s.busy" @click="startEnroll(s)">設定を始める</button>
      </template>
      <template v-for="t in setup(s)">
        <p class="small">認証アプリでこの QR コードを読み取り、表示された 6 桁のコードを入力してください。</p>
        <QrCode :uri="t.uri" :secret="t.secret" />
        <form @submit.prevent="verifyEnroll(s)">
          <label class="field"><span>認証アプリのコード</span><input type="text" v-model="s.code" class="otp" inputmode="numeric" autocomplete="one-time-code"></label>
          <p v-if="s.error.v.nonEmpty" class="error small">{{ s.error }}</p>
          <button type="submit" class="primary block" :disabled="s.busy">登録する</button>
        </form>
      </template>
    </template>

    <!-- 回復コード -->
    <template v-if='is(s, "show_recovery").v'>
      <h1>回復コード</h1>
      <RecoveryCodes :codes="codes(s).v" />
      <p v-if="s.error.v.nonEmpty" class="error small">{{ s.error }}</p>
      <button class="primary block" :disabled="s.busy" @click="continue(s)">保存しました。続ける</button>
    </template>

    <!-- パスワードの変更（必須のとき） -->
    <template v-if='is(s, "change_password").v'>
      <h1>パスワードの変更</h1>
      <p class="small">続けるには新しいパスワードを設定してください。</p>
      <form @submit.prevent="changePassword(s)">
        <label class="field"><span>新しいパスワード</span><input type="password" v-model="s.next" autocomplete="new-password" v-focus></label>
        <label class="field"><span>新しいパスワード（確認）</span><input type="password" v-model="s.next2" autocomplete="new-password"></label>
        <ul v-if="rules(s).mapC(_.nonEmpty)" class="rules small muted"><li v-for="r in rules(s)">{{ r }}</li></ul>
        <p v-if="s.error.v.nonEmpty" class="error small">{{ s.error }}</p>
        <button type="submit" class="primary block" :disabled="s.busy">変更して続ける</button>
      </form>
    </template>

    <!-- エラー -->
    <template v-if='is(s, "error").v || (s.flow.v.isEmpty && !s.busy.v && s.error.v.nonEmpty)'>
      <h1>ログインできません</h1>
      <p class="error">{{ s.error }}</p>
      <div class="stack"><button class="block" @click="restart()">最初からやり直す</button></div>
    </template>
    <p v-if='s.flow.v.nonEmpty && !is(s, "identify").v && !is(s, "error").v' class="center small reg"><a href="#" @click.prevent="restart()">最初からやり直す</a></p>
  </PublicCard>
</template>

<style scoped>
.app-head { display: flex; flex-direction: column; align-items: center; gap: .4rem; margin-bottom: 1rem; }
.user-chip { display: flex; gap: .6rem; align-items: center; border: 1px solid var(--line); border-radius: 999px; padding: .3rem .8rem .3rem .35rem; margin: 0 auto 1rem; width: fit-content; max-width: 100%; }
.links { margin-top: .8rem; text-align: center; }
.center { text-align: center; }
.reg { margin-top: 1rem; }
.alt { margin-top: 1rem; align-items: center; }
.msg { white-space: pre-wrap; }
.rules { margin: 0 0 .8rem; padding-left: 1.2rem; }
</style>
