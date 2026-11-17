<script lang="scala">
import io.circe.Json
import sruru.shared.*
import sruru.web.*

import scala.scalajs.concurrent.JSExecutionContext.Implicits.queue
import scala.scalajs.js
import scala.util.{Failure, Success}

// ロゴを選ぶ（画像を上げて ID を bind に入れる. 保存はフォームの保存ボタンで）. 横長の画像もそのまま使う.
case class Props(bind: RV[Option[String]], emptyLabel: String = "既定のロゴ")

case class State(busy: RV[Boolean] = RV(false))

def initState() = State()

def pick(s: State, props: Props, e: org.scalajs.dom.Event): Unit = Dom.file(e).foreach { f =>
  s.busy := true
  val ct = Option(f.`type`).filter(_.nonEmpty).getOrElse("image/png")
  Api.postRaw[Json]("/api/admin/logos", f.asInstanceOf[js.Any], ct).onComplete {
    case Success(j) => s.busy := false; props.bind := j.hcursor.get[String]("id").toOption
    case Failure(x) => s.busy := false; Store.error(x)
  }
}

def url(props: Props) = props.bind.mapC(Branding.logoUrl)
</script>

<template>
  <div class="logo-picker">
    <div class="preview"><img :src="url(props).v" alt="ロゴ"></div>
    <div class="col">
      <div class="row">
        <label class="btn small">{{ if (s.busy.v) "送っています…" else "画像を選ぶ" }}<input type="file" accept="image/png,image/jpeg,image/gif,image/webp,image/svg+xml" class="hidden" @change="pick(s, props, event)"></label>
        <button v-if="props.bind.v.isDefined" type="button" class="ghost small" @click="props.bind := None">外す（{{ props.emptyLabel }}）</button>
      </div>
      <span class="hint">PNG・JPEG・WebP・GIF・SVG、512KB まで。保存すると反映されます。</span>
    </div>
  </div>
</template>

<style scoped>
.logo-picker { display: flex; gap: .9rem; align-items: center; margin: .4rem 0 .8rem; }
.preview { width: 64px; height: 64px; display: flex; align-items: center; justify-content: center; border: 1px solid var(--line); border-radius: 12px; background: var(--side); }
.preview img { max-width: 52px; max-height: 52px; }
.col { display: flex; flex-direction: column; gap: .3rem; }
</style>
