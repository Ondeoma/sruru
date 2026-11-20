<script lang="scala">
import io.circe.syntax.*
import sruru.shared.*
import sruru.web.*
import sruru.web.parts.*

import scala.scalajs.concurrent.JSExecutionContext.Implicits.queue

// デバイスフローの確認（RFC 8628）: 端末（CLI・テレビなど）に表示されたコードを入力し、どのアプリが何を求めているかを確かめて、許可するかを選ぶ.
// コードの入力にはログインが要る（未ログインならログインの画面へ移り、終わるとここへ戻る）.
// コード付きの URL（verification_uri_complete）で開いても、許可／拒否の画面は必ず出す.
case class State(me: RV[Option[MeDto]] = RV(None),
                 code: RV[String] = RV(""),
                 req: RV[Option[AuthRequestDto]] = RV(None),
                 error: RV[String] = RV(""),
                 busy: RV[Boolean] = RV(false))

def initState() = State()

def reqId: Option[String] = Api.param("req")
def done: String = Api.param("done").getOrElse("")
def entering: Boolean = reqId.isEmpty && done.isEmpty

def mounted(s: State): Unit = {
  pageTitle("端末の確認")
  s.code := Api.param("user_code").getOrElse("")
  if (done.isEmpty) {
    // ログインしていなければ、ここでログインの画面へ移る（401）
    Api.me().foreach(m => s.me := Some(m))
    reqId.foreach(id => Store.inline(Api.get[AuthRequestDto](s"/api/auth-requests/${Api.enc(id)}"), s.error)(r => s.req := Some(r)))
  }
}

def verify(s: State): Unit =
  Store.inline(Api.post[RedirectDto]("/api/device/verify", DeviceVerifyReq(s.code.v).asJson), s.error, s.busy)(x => Nav.goto(x.redirect))

def answer(s: State, approve: Boolean): Unit = s.req.v.foreach { r =>
  Store.inline(Api.post[RedirectDto]("/api/device/decide", ConsentReq(r.id, approve).asJson), s.error, s.busy)(x => Nav.goto(x.redirect))
}

def items(s: State) = s.req.mapC(_.toList)
def who(s: State) = s.me.mapC(_.toList)
</script>

<template>
  <PublicCard>
    <!-- 端末に表示されたコードの入力 -->
    <template v-if="entering">
      <h1>端末の確認</h1>
      <p class="small">端末やアプリの画面に表示されているコードを入力してください。</p>
      <form @submit.prevent="verify(s)">
        <label class="field"><span>コード</span>
          <input type="text" v-model="s.code" class="code-input" placeholder="XXXX-XXXX" autocomplete="off" autocapitalize="characters" spellcheck="false" maxlength="20" v-focus></label>
        <p v-if="s.error.v.nonEmpty" class="error small">{{ s.error }}</p>
        <button type="submit" class="primary block" :disabled="s.busy">次へ</button>
      </form>
      <p class="small muted note">自分で操作している端末のコードだけを入力してください。メールやチャットで送られてきたコード・リンクは入力しないでください。</p>
    </template>

    <!-- どのアプリが何を求めているかを確かめて、許可するかを選ぶ -->
    <template v-if="reqId.isDefined">
      <template v-for="r in items(s)">
        <div class="app-head">
          <AppIcon :name="r.app.name" :iconUrl="r.app.iconUrl" :size="52" />
          <h1>「{{ r.app.name }}」を使う端末を許可しますか？</h1>
          <p v-if="r.app.description.nonEmpty" class="small muted">{{ r.app.description }}</p>
        </div>
        <p class="small">端末に表示されているコードが、次と同じことを確かめてください。</p>
        <div class="user-code">{{ r.userCode.getOrElse("") }}</div>
        <template v-if="r.scopes.nonEmpty">
          <p class="small">許可すると、この端末は次の情報を使えるようになります。</p>
          <ul class="scopes">
            <li v-for="sc in r.scopes"><b>{{ sc.description }}</b> <span class="muted small">（{{ sc.name }}）</span></li>
          </ul>
        </template>
        <p class="notice warn small">心当たりがない場合や、ほかの人から送られてきたコード・リンクの場合は「拒否」を選んでください。許可すると、その端末があなたのアカウントで使えるようになります。</p>
        <div class="row btns">
          <button class="grow" :disabled="s.busy" @click="answer(s, false)">拒否</button>
          <button class="primary grow" :disabled="s.busy" @click="answer(s, true)">許可</button>
        </div>
      </template>
      <p v-if="s.error.v.nonEmpty" class="error small">{{ s.error }}</p>
      <p v-if="s.error.v.nonEmpty" class="small center"><a href="/device">コードの入力からやり直す</a></p>
    </template>

    <template v-for="m in who(s)">
      <p class="small muted center who">{{ m.name }}（{{ m.username }}）としてログインしています</p>
    </template>

    <!-- 終わり -->
    <template v-if='done == "approved"'>
      <h1>許可しました</h1>
      <p class="small center">端末に戻ってください。まもなくログインが完了します。この画面は閉じてかまいません。</p>
    </template>
    <template v-if='done == "denied"'>
      <h1>拒否しました</h1>
      <p class="small center">端末は使えるようになっていません。この画面は閉じてかまいません。</p>
    </template>
  </PublicCard>
</template>

<style scoped>
.app-head { display: flex; flex-direction: column; align-items: center; gap: .5rem; margin-bottom: .6rem; text-align: center; }
.app-head h1 { margin: .3rem 0 0; }
.code-input { font-family: var(--mono, monospace); font-size: 1.4rem; letter-spacing: .15em; text-align: center; text-transform: uppercase; }
.user-code { font-family: var(--mono, monospace); font-size: 1.6rem; letter-spacing: .15em; text-align: center; font-weight: 700; margin: .4rem 0 1rem; }
.scopes { padding-left: 1.2rem; margin: .4rem 0 1rem; }
.scopes li { margin: .25rem 0; }
.btns { margin-top: 1rem; }
.note { margin-top: 1rem; }
.who { margin-top: 1rem; }
.center { text-align: center; }
</style>
