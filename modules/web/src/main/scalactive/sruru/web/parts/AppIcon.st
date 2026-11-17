<script lang="scala">
import sruru.web.*

// アプリケーションのアイコン（画像がなければ名前の1文字目のタイル）
case class Props(name: String, iconUrl: Option[String], size: Int = 40)

def style(props: Props): String =
  s"width: ${props.size}px; height: ${props.size}px; font-size: ${props.size * 0.45}px; border-radius: ${props.size * 0.22}px;" +
    (if (props.iconUrl.isEmpty) s" background: hsl(${Fmt.hue(props.name)} 55% 46%)" else "")
</script>

<template>
  <span class="app-icon" :style="style(props)">
    <img v-if="props.iconUrl.isDefined" :src='props.iconUrl.getOrElse("")' alt="">
    <template v-else>{{ Fmt.initials(props.name) }}</template>
  </span>
</template>

<style scoped>
.app-icon { display: inline-flex; align-items: center; justify-content: center; color: #fff; font-weight: 700; overflow: hidden; flex: none; }
.app-icon img { width: 100%; height: 100%; object-fit: cover; }
</style>
