<script lang="scala">
import sruru.web.*

import scala.scalajs.concurrent.JSExecutionContext.Implicits.queue

// 認証アプリの登録の QR コード（otpauth:// の URI）と、手で入れるための秘密の値
case class Props(uri: String, secret: String)

case class State(src: RV[String] = RV(""))

def initState() = State()

def mounted(s: State, props: Props): Unit = Qr.dataUrl(props.uri).foreach(s.src := _)

/** 4文字ずつ区切る（読み取りやすく）. */
def grouped(props: Props): String = props.secret.grouped(4).mkString(" ")
</script>

<template>
  <div class="qr">
    <img v-if="s.src.v.nonEmpty" :src="s.src" alt="QR コード" width="200" height="200">
    <p class="small muted">QR コードを読み取れないときは、次の値を手で入力してください。</p>
    <div class="row secret-row"><code class="codebox">{{ grouped(props) }}</code><button type="button" class="small" @click="Dom.copy(props.secret)">コピー</button></div>
  </div>
</template>

<style scoped>
.qr { text-align: center; margin: .6rem 0 1rem; }
.qr img { background: #fff; padding: 8px; border-radius: 10px; border: 1px solid var(--line); }
.secret-row { justify-content: center; }
</style>
