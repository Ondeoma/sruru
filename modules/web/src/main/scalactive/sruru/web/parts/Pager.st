<script lang="scala">
// 一覧のページ送り（「1–50 件 / 120 件」と前へ・次へ）
case class Props(offset: Int, total: Int, limit: Int, onPage: Int => Unit)

def range(props: Props): String =
  if (props.total == 0) "0 件" else s"${props.offset + 1}–${math.min(props.offset + props.limit, props.total)} 件 / ${props.total} 件"
</script>

<template>
  <span class="muted">{{ range(props) }}</span>
  <button class="small" :disabled="props.offset <= 0" @click="props.onPage(-1)">前へ</button>
  <button class="small" :disabled="props.offset + props.limit >= props.total" @click="props.onPage(1)">次へ</button>
</template>
