<script lang="scala">
import sruru.web.*

// ログイン・同意などの画面の枠（中央のカード. 上に画面の名前）
case class Props(wide: Boolean = false, slot: Slot = Slot.empty)

def cls(props: Props): String = if (props.wide) "public-card wide" else "public-card"
</script>

<template>
  <div class="public">
    <div class="public-brand"><img :src="Store.logo.v" alt="" class="public-logo">{{ Store.title }}</div>
    <div :class="cls(props)"><slot></slot></div>
    <div class="public-foot">{{ Store.config.mapC(_.map(c => "sruru " + c.version).getOrElse("")) }}</div>
  </div>
</template>
