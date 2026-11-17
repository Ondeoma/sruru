<script lang="scala">
import io.circe.Json
import io.circe.syntax.*
import sruru.web.*
import sruru.web.parts.*

// メールアドレスの確認（メールのリンクから開く）
case class State(done: RV[Boolean] = RV(false), error: RV[String] = RV(""), busy: RV[Boolean] = RV(true))

def initState() = State()

def mounted(s: State): Unit = {
  pageTitle("メールアドレスの確認")
  val token = Api.param("token").getOrElse("")
  Store.inline(Api.postUnit("/api/me/email/confirm", Json.obj("token" -> token.asJson)), s.error, s.busy)(_ => s.done := true)
}
</script>

<template>
  <PublicCard>
    <h1>メールアドレスの確認</h1>
    <p v-if="s.busy" class="muted small">確認しています…</p>
    <p v-if="s.done" class="notice ok small">メールアドレスを確認しました。</p>
    <p v-if="s.error.v.nonEmpty" class="error small">{{ s.error }}</p>
    <a href="/me" class="btn block">個人設定へ</a>
  </PublicCard>
</template>
