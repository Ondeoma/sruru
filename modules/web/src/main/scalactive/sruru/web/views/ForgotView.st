<script lang="scala">
import io.circe.syntax.*
import sruru.shared.*
import sruru.web.*
import sruru.web.parts.*

// パスワードを忘れたとき（再設定のメールを送る）
case class State(username: RV[String] = RV(""), sent: RV[Boolean] = RV(false), error: RV[String] = RV(""), busy: RV[Boolean] = RV(false))

def initState() = State()

def mounted(): Unit = pageTitle("パスワードの再設定")

def send(s: State): Unit = Store.inline(Api.postUnit("/api/login/forgot", ForgotReq(s.username.v.trim).asJson), s.error, s.busy)(_ => s.sent := true)

def mail = Store.config.mapC(_.forall(_.mailEnabled))
</script>

<template>
  <PublicCard>
    <h1>パスワードの再設定</h1>
    <template v-if="s.sent">
      <p class="notice ok small">登録されているメールアドレスに、再設定の手順を送りました。メールが届かないときは、管理者に連絡してください。</p>
    </template>
    <template v-else>
      <p v-if="mail.mapC(!_)" class="notice warn small">メールを送る設定がないため、再設定のメールは届きません。管理者に連絡してください。</p>
      <p class="small">ユーザー名かメールアドレスを入力してください。再設定のためのリンクをメールで送ります。</p>
      <form @submit.prevent="send(s)">
        <label class="field"><span>ユーザー名またはメールアドレス</span><input type="text" v-model="s.username" autocapitalize="none" v-focus></label>
        <p v-if="s.error.v.nonEmpty" class="error small">{{ s.error }}</p>
        <button type="submit" class="primary block" :disabled="s.busy">送る</button>
      </form>
    </template>
    <p class="center small"><a href="/login">ログインに戻る</a></p>
  </PublicCard>
</template>

<style scoped>
.center { text-align: center; margin-top: 1rem; }
</style>
