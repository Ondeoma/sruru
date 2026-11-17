<script lang="scala">
import sruru.web.*
import sruru.web.parts.*

// エラー（アプリからの要求が正しくないときなど）
def mounted(): Unit = pageTitle("エラー")

def message: String = Api.param("message").getOrElse("エラーが起きました。")
</script>

<template>
  <PublicCard>
    <h1>エラー</h1>
    <p class="msg">{{ message }}</p>
    <a href="/" class="btn block">ポータルへ</a>
  </PublicCard>
</template>

<style scoped>
.msg { white-space: pre-wrap; }
</style>
