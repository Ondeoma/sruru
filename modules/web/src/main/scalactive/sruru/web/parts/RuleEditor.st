<script lang="scala">
import sruru.web.*

// 動的なグループの条件（すべて・どれかに合う人をメンバーにする）. 行ごとに 項目・比べ方・値.
case class Props(mode: RV[String], rows: RV[List[CondRow]])

def add(props: Props): Unit = props.rows := props.rows.v :+ Rules.row()
def remove(props: Props, r: CondRow): Unit = props.rows := props.rows.v.filterNot(_.id == r.id)
</script>

<template>
  <div class="rows">
    <div class="row mode">
      <span class="small">次の条件の</span>
      <select v-model="props.mode"><option value="all">すべて</option><option value="any">どれか</option></select>
      <span class="small">に合う人をメンバーにする</span>
    </div>
    <div v-for="r in props.rows" :key="r.id" class="rule-row">
      <input type="text" v-model="r.path" list="sruru-rule-paths" placeholder="user.email">
      <select v-model="r.op"><option v-for="o in Rules.ops" :value="o._1">{{ o._2 }}</option></select>
      <input type="text" v-model="r.value" :disabled="!r.needsValue.v" :placeholder='if (r.op.v == "in") "値1, 値2" else "値"'>
      <button type="button" class="ghost small" title="この条件を消す" @click="remove(props, r)">✕</button>
    </div>
    <datalist id="sruru-rule-paths"><option v-for="p in Rules.paths" :value="p"></option></datalist>
    <button type="button" class="small" @click="add(props)">＋ 条件を追加</button>
    <p class="small muted">項目の例: <code>user.email</code>・<code>user.username</code>・<code>user.groups</code>・<code>user.source</code>・<code>user.attributes.department</code>（カスタム属性）</p>
  </div>
</template>

<style scoped>
.mode { margin-bottom: .5rem; }
</style>
