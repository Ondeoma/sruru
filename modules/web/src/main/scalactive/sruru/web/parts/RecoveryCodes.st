<script lang="scala">
import sruru.web.*

// 回復コードの表示（コピー・ファイルに保存）
case class Props(codes: List[String])

def text(props: Props): String = props.codes.mkString("\n") + "\n"
def save(props: Props): Unit = Dom.download("sruru-recovery-codes.txt",
  "回復コード（それぞれ1回だけ使えます）\n" + text(props))
</script>

<template>
  <div>
    <p class="small">認証アプリを使えなくなったときに、ここにあるコードでログインできます。<b>それぞれ1回だけ</b>使えます。
      この画面を離れると二度と表示できません。印刷するか、安全な場所に保存してください。</p>
    <div class="codes"><span v-for="c in props.codes">{{ c }}</span></div>
    <div class="row btns">
      <button type="button" class="small" @click="Dom.copy(text(props))">コピー</button>
      <button type="button" class="small" @click="save(props)">ファイルに保存</button>
    </div>
  </div>
</template>

<style scoped>
.btns { margin: .6rem 0; }
</style>
