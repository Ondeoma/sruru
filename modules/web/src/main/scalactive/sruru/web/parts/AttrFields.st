<script lang="scala">
import sruru.web.*

// カスタム属性の入力欄（属性の種類ごとに入力の形を変える）. 値は fields の RV に入る.
case class Props(fields: List[AttrField], readonly: Boolean = false)
</script>

<template>
  <div class="grid2">
    <template v-for="f in props.fields">
      <label v-if='f.d.kind == "boolean"' class="check"><input type="checkbox" v-model="f.bool" :disabled="props.readonly">
        <span>{{ f.d.label }}<span v-if="f.d.description.nonEmpty" class="hint">{{ f.d.description }}</span></span></label>
      <label v-else-if='f.d.kind == "list"' class="field"><span>{{ f.d.label }}{{ if (f.d.required) " *" else "" }}（1行に1つ）</span>
        <textarea v-model="f.str" :disabled="props.readonly" rows="3"></textarea>
        <span v-if="f.d.description.nonEmpty" class="hint">{{ f.d.description }}</span></label>
      <label v-else class="field"><span>{{ f.d.label }}{{ if (f.d.required) " *" else "" }}</span>
        <input :type="f.inputType" v-model="f.str" :disabled="props.readonly">
        <span v-if="f.d.description.nonEmpty" class="hint">{{ f.d.description }}</span></label>
    </template>
  </div>
</template>
