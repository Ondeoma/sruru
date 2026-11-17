<script lang="scala">
import io.circe.syntax.*
import sruru.shared.*
import sruru.web.*
import sruru.web.parts.*

// パスワードの再設定（メールのリンクから開く）
case class State(next: RV[String] = RV(""), next2: RV[String] = RV(""), done: RV[Boolean] = RV(false), error: RV[String] = RV(""),
                 busy: RV[Boolean] = RV(false))

def initState() = State()

def mounted(): Unit = pageTitle("パスワードの再設定")

def token: String = Api.param("token").getOrElse("")

def save(s: State): Unit =
  if (s.next.v != s.next2.v) s.error := "確認のパスワードが一致しません"
  else Store.inline(Api.postUnit("/api/login/reset", ResetReq(token, s.next.v).asJson), s.error, s.busy)(_ => s.done := true)

def rules = Store.config.mapC(_.map(_.passwordRules).getOrElse(Nil))
</script>

<template>
  <PublicCard>
    <h1>新しいパスワード</h1>
    <template v-if="s.done">
      <p class="notice ok small">パスワードを変更しました。新しいパスワードでログインしてください。</p>
      <a href="/login" class="btn primary block">ログインへ</a>
    </template>
    <template v-else>
      <p v-if="token.isEmpty" class="error small">リンクが正しくありません。メールのリンクをもう一度開いてください。</p>
      <form @submit.prevent="save(s)">
        <label class="field"><span>新しいパスワード</span><input type="password" v-model="s.next" autocomplete="new-password" autofocus></label>
        <label class="field"><span>新しいパスワード（確認）</span><input type="password" v-model="s.next2" autocomplete="new-password"></label>
        <ul v-if="rules.mapC(_.nonEmpty)" class="rules small muted"><li v-for="r in rules">{{ r }}</li></ul>
        <p v-if="s.error.v.nonEmpty" class="error small">{{ s.error }}</p>
        <button type="submit" class="primary block" :disabled="s.busy">変更する</button>
      </form>
    </template>
  </PublicCard>
</template>

<style scoped>
.rules { margin: 0 0 .8rem; padding-left: 1.2rem; }
</style>
