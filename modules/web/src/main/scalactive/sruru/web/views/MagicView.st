<script lang="scala">
import io.circe.syntax.*
import org.scalajs.dom
import sruru.shared.*
import sruru.web.*
import sruru.web.parts.*

// マジックリンク（メールのリンクから開く）. 開いただけではログインせず、ボタンで使う（メールのスキャナーの先読みで使われないように）.
// トークンは最初に URL から消す（アドレスバー・履歴・Referer に残さない. サーバーは Referrer-Policy: no-referrer を付ける）.
case class State(token: RV[String] = RV(""), error: RV[String] = RV(""), busy: RV[Boolean] = RV(false))

def initState() = State()

def mounted(s: State): Unit = {
  pageTitle("ログインのリンク")
  s.token := Api.param("token").getOrElse("")
  dom.window.history.replaceState(null, "", "/magic")
}

/** 完了ならアプリ・ポータルへ、2つ目の要素が要るならログインの画面へ（どちらもこの画面を履歴に残さない）. */
def next(s: State, f: FlowDto): Unit =
  if (f.stage == "done") f.redirect.foreach(r => dom.window.location.replace(r))
  else if (f.stage == "error") s.error := f.message.getOrElse("ログインできませんでした")
  else dom.window.location.replace(s"/login?flow=${f.id}")

def use(s: State): Unit =
  if (!s.busy.v) Store.inline(Api.post[FlowDto]("/api/login/magic", MagicLoginReq(s.token.v).asJson), s.error, s.busy) { f =>
    s.token := ""
    next(s, f)
  }
</script>

<template>
  <PublicCard>
    <h1>ログイン</h1>
    <template v-if="s.token.mapC(_.nonEmpty)">
      <p class="small">メールで受け取ったリンクでログインします。続けるには、下のボタンを押してください。</p>
      <p v-if="s.error.v.nonEmpty" class="error small">{{ s.error }}</p>
      <button type="button" class="primary block" :disabled="s.busy" @click="use(s)" v-focus>ログインする</button>
    </template>
    <template v-else>
      <p v-if="s.error.v.nonEmpty" class="error small">{{ s.error }}</p>
      <p v-else class="error small">リンクが正しくないか、すでに使われています。もう一度リンクを受け取ってください。</p>
      <a href="/login" class="btn block">ログインの画面へ</a>
    </template>
  </PublicCard>
</template>
