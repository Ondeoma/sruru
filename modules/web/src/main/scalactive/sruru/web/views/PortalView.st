<script lang="scala">
import sruru.shared.*
import sruru.web.*
import sruru.web.parts.*
import io.circe.syntax.*
import org.scalajs.dom

import java.util.UUID

// ポータル（使えるアプリケーションの一覧）. タイルをドラッグして並べ替えられる（本人だけの並び. サーバーに保存する）.
case class State(apps: RV[List[AppBriefDto]] = RV(Nil), loaded: RV[Boolean] = RV(false), q: RV[String] = RV(""),
                 dragging: RV[Option[UUID]] = RV(None), before: RV[List[UUID]] = RV(Nil))

def initState() = State()

def mounted(s: State): Unit = {
  pageTitle("ポータル")
  Store.report(Api.get[List[AppBriefDto]]("/api/me/apps")) { a => s.apps := a; s.loaded := true }
}

def shown(s: State) = computed {
  val q = s.q.v.trim.toLowerCase
  s.apps.v.filter(a => q.isEmpty || a.name.toLowerCase.contains(q) || a.description.toLowerCase.contains(q))
}

def open(a: AppBriefDto): Unit = a.launchUrl.foreach(Dom.goto)
def key(a: AppBriefDto, e: dom.Event): Unit = if (e.asInstanceOf[dom.KeyboardEvent].key == "Enter") open(a)
def cls(s: State, a: AppBriefDto): String =
  "tile" + (if (a.launchUrl.isEmpty) " disabled" else "") + (if (s.dragging.v.contains(a.id)) " dragging" else "")

// ---------------------------------------------------------------- 並べ替え（絞り込んでいる間はしない）

def canDrag(s: State): String = if (s.q.v.trim.isEmpty && s.apps.v.size > 1) "true" else "false"

def start(s: State, a: AppBriefDto, e: dom.Event): Unit = {
  val dt = e.asInstanceOf[dom.DragEvent].dataTransfer
  dt.effectAllowed = dom.DataTransferEffectAllowedKind.move
  dt.setData("text/plain", a.id.toString)   // Firefox はデータがないとドラッグを始めない
  s.before := s.apps.v.map(_.id)
  s.dragging := Some(a.id)
}

/** ドラッグ中のタイルを、上に重なったタイルの位置へ動かす（離す前から並びが変わって見える）. */
def over(s: State, target: AppBriefDto): Unit = s.dragging.v.filter(_ != target.id).foreach { id =>
  val list = s.apps.v
  list.find(_.id == id).foreach { moving =>
    val rest = list.filterNot(_.id == id)
    val to   = list.indexWhere(_.id == target.id)
    s.apps := rest.patch(to, List(moving), 0)
  }
}

/** 離したら保存する（並びが変わったときだけ）. */
def end(s: State): Unit = if (s.dragging.v.isDefined) {
  s.dragging := None
  val now = s.apps.v.map(_.id)
  if (now != s.before.v)
    Store.report(Api.putUnit("/api/me/apps/order", AppOrderReq(now).asJson))(_ => Store.toast("並び順を保存しました"))
}

/** 名前の順に戻す. */
def reset(s: State): Unit = Store.report(Api.delete("/api/me/apps/order")) { _ =>
  Store.report(Api.get[List[AppBriefDto]]("/api/me/apps")) { a => s.apps := a; Store.toast("名前の順に戻しました") }
}
def greeting = Store.me.mapC(_.map(m => s"${m.name} さん").getOrElse(""))
</script>

<template>
  <div class="page">
    <div class="row head">
      <h1 class="grow">アプリケーション</h1>
      <input v-if="s.apps.mapC(_.size > 8)" type="search" v-model="s.q" placeholder="絞り込み">
    </div>
    <p class="muted small">{{ greeting }}が使えるアプリケーションです。クリックすると開きます。ドラッグで並べ替えられます。
      <a v-if="s.apps.mapC(_.size > 1)" href="#" @click.prevent="reset(s)">名前の順に戻す</a></p>
    <div class="grid">
      <div v-for="a in shown(s)" :key="a.id" :class="cls(s, a)" role="button" tabindex="0" :title="a.description" :draggable="canDrag(s)"
           @click="open(a)" @keydown="key(a, event)" @dragstart="start(s, a, event)" @dragover.prevent="over(s, a)" @drop.prevent="end(s)" @dragend="end(s)">
        <AppIcon :name="a.name" :iconUrl="a.iconUrl" :size="52" />
        <span class="nm">{{ a.name }}</span>
        <span v-if="a.description.nonEmpty" class="desc">{{ a.description }}</span>
      </div>
    </div>
    <p v-if="s.loaded.v && s.apps.v.isEmpty" class="empty">使えるアプリケーションはまだありません。</p>
  </div>
</template>

<style scoped>
.head h1 { margin-bottom: .2rem; }
.grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(170px, 1fr)); gap: .9rem; margin-top: 1rem; }
.tile { display: flex; flex-direction: column; align-items: center; gap: .5rem; padding: 1.2rem .8rem 1rem; border-radius: 12px; background: var(--card);
  border: 1px solid var(--line); white-space: normal; text-align: center; transition: transform .12s, box-shadow .12s; cursor: pointer; user-select: none; }
.tile.dragging { opacity: .4; border-style: dashed; }
.tile:hover { transform: translateY(-2px); box-shadow: var(--shadow); background: var(--card); }
.tile.disabled { opacity: .55; cursor: default; }
.nm { font-weight: 600; font-size: .95rem; }
.desc { font-size: .78rem; color: var(--muted); display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; }
@media (max-width: 720px) { .grid { grid-template-columns: repeat(auto-fill, minmax(130px, 1fr)); gap: .6rem; } }
</style>
