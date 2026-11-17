<script lang="scala">
import sruru.shared.*
import sruru.web.*
import sruru.web.parts.*


// ポータル（使えるアプリケーションの一覧）
case class State(apps: RV[List[AppBriefDto]] = RV(Nil), loaded: RV[Boolean] = RV(false), q: RV[String] = RV(""))

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
def cls(a: AppBriefDto): String = if (a.launchUrl.isDefined) "tile" else "tile disabled"
def greeting = Store.me.mapC(_.map(m => s"${m.name} さん").getOrElse(""))
</script>

<template>
  <div class="page">
    <div class="row head">
      <h1 class="grow">アプリケーション</h1>
      <input v-if="s.apps.mapC(_.size > 8)" type="search" v-model="s.q" placeholder="絞り込み">
    </div>
    <p class="muted small">{{ greeting }}が使えるアプリケーションです。クリックすると開きます。</p>
    <div class="grid">
      <button v-for="a in shown(s)" :key="a.id" :class="cls(a)" :title="a.description" @click="open(a)">
        <AppIcon :name="a.name" :iconUrl="a.iconUrl" :size="52" />
        <span class="nm">{{ a.name }}</span>
        <span v-if="a.description.nonEmpty" class="desc">{{ a.description }}</span>
      </button>
    </div>
    <p v-if="s.loaded.v && s.apps.v.isEmpty" class="empty">使えるアプリケーションはまだありません。</p>
  </div>
</template>

<style scoped>
.head h1 { margin-bottom: .2rem; }
.grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(170px, 1fr)); gap: .9rem; margin-top: 1rem; }
.tile { display: flex; flex-direction: column; align-items: center; gap: .5rem; padding: 1.2rem .8rem 1rem; border-radius: 12px; background: var(--card);
  border: 1px solid var(--line); white-space: normal; text-align: center; transition: transform .12s, box-shadow .12s; }
.tile:hover { transform: translateY(-2px); box-shadow: var(--shadow); background: var(--card); }
.tile.disabled { opacity: .55; cursor: default; }
.nm { font-weight: 600; font-size: .95rem; }
.desc { font-size: .78rem; color: var(--muted); display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; }
@media (max-width: 720px) { .grid { grid-template-columns: repeat(auto-fill, minmax(130px, 1fr)); gap: .6rem; } }
</style>
