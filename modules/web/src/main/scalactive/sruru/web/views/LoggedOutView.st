<script lang="scala">
import sruru.web.parts.*

// ログアウトした後
def mounted(): Unit = pageTitle("ログアウト")
</script>

<template>
  <PublicCard>
    <h1>ログアウトしました</h1>
    <p class="small muted center">共用のパソコンでは、ブラウザも閉じてください。</p>
    <a href="/login" class="btn primary block">もう一度ログインする</a>
  </PublicCard>
</template>

<style scoped>
.center { text-align: center; }
</style>
