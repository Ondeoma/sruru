<script lang="scala">
import sruru.shared.*
import sruru.web.*
import sruru.web.parts.*

// 管理: アプリケーションの一覧
case class State(apps: RV[List[AppDto]] = RV(Nil), q: RV[String] = RV(""))

def initState() = State()

def mounted(s: State): Unit = {
  pageTitle("アプリケーション")
  Store.report(Api.get[List[AppDto]]("/api/admin/apps"))(s.apps := _)
}

def shown(s: State) = computed {
  val q = s.q.v.trim.toLowerCase
  s.apps.v.filter(a => q.isEmpty || a.name.toLowerCase.contains(q) || a.slug.toLowerCase.contains(q)).sortBy(_.name)
}

def proto(a: AppDto): String = if (a.protocol == "saml") "SAML" else "OIDC"
</script>

<template>
  <section>
    <div class="page-head"><h1>アプリケーション</h1><RouterLink to="/admin/apps/new" class="btn primary">＋ アプリケーションを追加</RouterLink></div>
    <div class="filters"><input type="search" v-model="s.q" placeholder="名前で絞り込み" class="grow"></div>
    <div class="table-wrap">
      <table class="list">
        <thead><tr><th></th><th>名前</th><th class="hide-sp">識別子</th><th>方式</th><th>状態</th></tr></thead>
        <tbody>
          <tr v-for="a in shown(s)" :key="a.id" class="clickable" @click='Router.go("/admin/apps/" + a.id)'>
            <td class="ic"><AppIcon :name="a.name" :iconUrl="a.iconUrl" :size="28" /></td>
            <td>{{ a.name }}<div v-if="a.description.nonEmpty" class="muted small">{{ a.description }}</div></td>
            <td class="small mono hide-sp">{{ a.slug }}</td>
            <td><span :class='if (a.protocol == "saml") "badge warn" else "badge accent"'>{{ proto(a) }}</span></td>
            <td>
              <span v-if="!a.enabled" class="badge danger">無効</span>
              <span v-if="a.requireMfa" class="badge">2段階認証が必須</span>
              <span v-if="a.restrictAccess" class="badge">グループで制限</span>
              <span v-if="!a.showInPortal" class="badge">ポータルに出さない</span>
            </td>
          </tr>
          <tr v-if="s.apps.mapC(_.isEmpty)"><td colspan="5" class="muted">アプリケーションはまだありません</td></tr>
        </tbody>
      </table>
    </div>
  </section>
</template>

<style scoped>
.ic { width: 40px; }
.badge { margin-right: .25rem; }
</style>
