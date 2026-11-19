<script lang="scala">
import sruru.web.*

import scala.scalajs.concurrent.JSExecutionContext.Implicits.queue

// 個人設定のタブ（「ポリシーの管理」は、編集を任されたグループがあるときだけ出す）
case class State(delegated: RV[Boolean] = RV(false))

def initState() = State()

def mounted(s: State): Unit =
  Api.get[List[sruru.shared.DelegatedGroupDto]]("/api/me/policy-groups").foreach(gs => s.delegated := gs.nonEmpty)
</script>

<template>
  <nav class="tabs">
    <RouterLink to="/me">プロフィール</RouterLink>
    <RouterLink to="/me/security">セキュリティ</RouterLink>
    <RouterLink to="/me/tokens">API トークン</RouterLink>
    <RouterLink v-if="s.delegated" to="/me/policies">ポリシーの管理</RouterLink>
  </nav>
</template>
