<script lang="scala">
import io.github.ondeoma.scalactive.components.routes.RouterComponent
import org.scalajs.dom
import sruru.web.*

// 管理の画面の枠（左のメニューと、ページごとのルート）
val routes: PathPatternRoutes = List(
  ("dashboard", _ => DashboardPage()),
  ("users", _ => UsersPage()),
  ("users/:id", r => UserPage(id = r.pathname.groups("id"))),
  ("groups", _ => GroupsPage()),
  ("groups/:id", r => GroupPage(id = r.pathname.groups("id"))),
  ("apps", _ => AppsPage()),
  ("apps/new", _ => AppPage(id = "")),
  ("apps/:id", r => AppPage(id = r.pathname.groups("id"))),
  ("attributes", _ => AttributesPage()),
  ("policies", _ => PoliciesPage()),
  ("domains", _ => DomainsPage()),
  ("federation", _ => FederationPage()),
  ("certs", _ => CertsPage()),
  ("tokens", _ => TokensPage()),
  ("keys", _ => KeysPage()),
  ("audit", _ => AuditPage()),
)

/** /admin だけのときは概要を出す. */
def isTop = Router.href.mapC { h => val p = new dom.URL(h).pathname; p == "/admin" || p == "/admin/" }

def mounted(): Unit = pageTitle("管理")
</script>

<template>
  <div class="page admin">
    <nav class="side-nav">
      <RouterLink to="/admin/dashboard" :class='if (isTop.v) "router-link-active" else ""'>概要</RouterLink>
      <RouterLink to="/admin/users">ユーザー</RouterLink>
      <RouterLink to="/admin/groups">グループ</RouterLink>
      <RouterLink to="/admin/apps">アプリケーション</RouterLink>
      <RouterLink to="/admin/attributes">カスタム属性</RouterLink>
      <RouterLink to="/admin/policies">ポリシー</RouterLink>
      <RouterLink to="/admin/domains">ドメイン</RouterLink>
      <RouterLink to="/admin/federation">外部 IdP・同期</RouterLink>
      <RouterLink to="/admin/certs">証明書の認証局</RouterLink>
      <RouterLink to="/admin/tokens">API トークン</RouterLink>
      <RouterLink to="/admin/keys">署名鍵</RouterLink>
      <RouterLink to="/admin/audit">監査ログ</RouterLink>
    </nav>
    <div class="content">
      <p v-if="Store.isAdmin.mapC(!_).v" class="notice danger">管理の画面は管理者だけが使えます。</p>
      <DashboardPage v-else-if="isTop.v" />
      <RouterComponent v-else :routes="routes" prefix="/admin" />
    </div>
  </div>
</template>
