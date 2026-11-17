<script lang="scala">
import sruru.web.*

// 値とコピーのボタン（接続情報・トークンなど）
case class Props(value: String, label: String = "")
</script>

<template>
  <div class="copy-row">
    <span v-if="props.label.nonEmpty" class="lbl">{{ props.label }}</span>
    <code class="codebox grow">{{ props.value }}</code>
    <button type="button" class="small" @click="Dom.copy(props.value)">コピー</button>
  </div>
</template>

<style scoped>
.copy-row { display: flex; gap: .5rem; align-items: center; margin: .3rem 0; flex-wrap: wrap; }
.lbl { font-size: .8rem; color: var(--muted); min-width: 11em; }
.grow { flex: 1; min-width: 12rem; }
</style>
