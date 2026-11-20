<script lang="scala">
import io.circe.syntax.*
import sruru.shared.*
import sruru.web.*
import sruru.web.parts.*

// 最初の設定（最初の管理者を作る. 起動時のログに出るトークンが必要）
case class State(token: RV[String] = RV(""), username: RV[String] = RV("admin"), name: RV[String] = RV(""), email: RV[String] = RV(""),
                 password: RV[String] = RV(""), password2: RV[String] = RV(""), error: RV[String] = RV(""), busy: RV[Boolean] = RV(false))

def initState() = State(token = RV(Api.param("token").getOrElse("")))

def mounted(): Unit = pageTitle("最初の設定")

def save(s: State): Unit =
  if (s.password.v != s.password2.v) s.error := "確認のパスワードが一致しません"
  else Store.inline(Api.postUnit("/api/setup", SetupReq(s.token.v.trim, s.username.v.trim, s.name.v.trim, s.email.v.trim, s.password.v).asJson),
    s.error, s.busy) { _ =>
    Store.config := Store.config.v.map(_.copy(setupRequired = false))
    Toasts.show("管理者を作りました。ログインしてください")
    Router.go("/login")
  }

def rules = Store.config.mapC(_.map(_.passwordRules).getOrElse(Nil))
</script>

<template>
  <PublicCard :wide="true">
    <h1>最初の設定</h1>
    <p class="small">最初の管理者のアカウントを作ります。<b>セットアップトークン</b>はサーバーの起動時のログに出ています。</p>
    <form @submit.prevent="save(s)">
      <label class="field"><span>セットアップトークン</span><input type="text" v-model="s.token" autocomplete="off" class="mono"></label>
      <div class="grid2">
        <label class="field"><span>ユーザー名</span><input type="text" v-model="s.username" autocapitalize="none"></label>
        <label class="field"><span>名前</span><input type="text" v-model="s.name" placeholder="山田 太郎"></label>
      </div>
      <label class="field"><span>メールアドレス</span><input type="email" v-model="s.email"></label>
      <div class="grid2">
        <label class="field"><span>パスワード</span><input type="password" v-model="s.password" autocomplete="new-password"></label>
        <label class="field"><span>パスワード（確認）</span><input type="password" v-model="s.password2" autocomplete="new-password"></label>
      </div>
      <ul v-if="rules.mapC(_.nonEmpty)" class="rules small muted"><li v-for="r in rules">{{ r }}</li></ul>
      <p v-if="s.error.v.nonEmpty" class="error small">{{ s.error }}</p>
      <button type="submit" class="primary block" :disabled="s.busy">管理者を作る</button>
    </form>
  </PublicCard>
</template>

<style scoped>
.rules { margin: 0 0 .8rem; padding-left: 1.2rem; }
</style>
