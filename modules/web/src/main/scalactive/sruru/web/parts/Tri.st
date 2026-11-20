<script lang="scala">
// 「全体のまま・する・しない」を選ぶ欄（ドメインのポリシーの上書き）. bind は ""・"true"・"false".
case class Props(bind: RV[String], label: String, yes: String = "する", no: String = "しない")
</script>

<template>
  <label class="field"><span>{{ props.label }}</span>
    <select v-model="props.bind"><option value="">（全体のまま）</option><option value="true">{{ props.yes }}</option><option value="false">{{ props.no }}</option></select></label>
</template>
