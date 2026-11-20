<script lang="scala">
import io.circe.syntax.*
import io.github.ondeoma.scalactive.components.routes.RouterComponent
import org.scalajs.dom
import sruru.shared.*
import sruru.web.parts.*
import sruru.web.views.*
import sruru.web.admin.AdminLayout

import scala.scalajs.concurrent.JSExecutionContext.Implicits.queue

// 画面全体の枠: ヘッダー（ポータル・個人設定・管理・アカウントの切り替え）と、ルートごとの画面.
// ログイン・同意などの画面はヘッダーを出さず、各画面が中央のカード（PublicCard）で表示する.
case class State(ready: RV[Boolean] = RV(false),
                 menu: RV[Boolean] = RV(false))

def initState() = State()

val routes: PathPatternRoutes = List(
  ("/", _ => PortalView()),
  ("/login", _ => LoginView()),
  ("/choose", _ => ChooseView()),
  ("/consent", _ => ConsentView()),
  ("/device", _ => DeviceView()),
  ("/forgot", _ => ForgotView()),
  ("/reset-password", _ => ResetPasswordView()),
  ("/setup", _ => SetupView()),
  ("/error", _ => ErrorView()),
  ("/logged-out", _ => LoggedOutView()),
  ("/verify-email", _ => VerifyEmailView()),
  ("/me", _ => ProfileView()),
  ("/me/security", _ => SecurityView()),
  ("/me/tokens", _ => TokensView()),
  ("/me/policies", _ => PolicyGroupsView()),
  ("/admin", _ => AdminLayout()),
  ("/admin/*", _ => AdminLayout()),
)

/** ヘッダーを出さない画面（ログイン前でも開く）. */
def publicPath(href: String): Boolean = Pages.isPublic(new dom.URL(href).pathname)

def isPublic = Router.href.mapC(publicPath)

def loadMe(s: State): Unit = Toasts.report(Store.reloadMe()) { me =>
  Observe.setUser(me.id.toString)
  Store.loadAccounts()
  s.ready := true
}

def mounted(s: State): Unit = {
  Fallback.install(routes)
  Api.clientConfig().foreach { c =>
    Store.config := Some(c)
    if (c.setupRequired && dom.window.location.pathname != "/setup") Router.go("/setup")
  }
  if (isPublic.v) s.ready := true else loadMe(s)
  // ログインの画面から（画面の中で）移ってきたとき
  watch(Router.href, false)((_, h) => if (!publicPath(h) && Store.me.v.isEmpty) loadMe(s))
}

def switchTo(a: AccountDto): Unit =
  if (!a.active) Toasts.report(Api.postUnit("/api/accounts/switch", SwitchReq(a.userId).asJson))(_ => Nav.goto("/"))

def logout(): Unit = Store.myId.foreach { id =>
  Toasts.report(Api.postUnit("/api/accounts/logout", AccountLogoutReq(Some(id)).asJson)) { _ =>
    if (Store.accounts.v.exists(a => a.userId != id)) Nav.goto("/") else Nav.goto("/logged-out")
  }
}

def logoutAll(): Unit = Toasts.report(Api.postUnit("/api/accounts/logout", AccountLogoutReq(None).asJson))(_ => Nav.goto("/logged-out"))

def addAccount(): Unit = Nav.goto("/login?add=1&returnTo=" + Api.enc("/"))

def meBrief = Store.me.mapC(_.map(Users.person))
def userName = Store.me.mapC(_.map(_.name).getOrElse(""))
def userId = Store.me.mapC(_.map(_.username).getOrElse(""))
def showHeader(s: State) = computed { !isPublic.v && Store.me.v.isDefined }
def others = Store.accounts.mapC(_.filterNot(_.active))
</script>

<template>
  <header v-if="showHeader(s)" class="top">
    <RouterLink to="/" class="logo"><span class="brand"><img :src="Store.logo.v" alt="" class="brand-logo">{{ Store.title }}</span></RouterLink>
    <nav class="nav hide-sp">
      <RouterLink to="/me">個人設定</RouterLink>
      <RouterLink v-if="Store.isAdmin" to="/admin">管理</RouterLink>
    </nav>
    <div class="spacer"></div>
    <div class="me">
      <button class="ghost me-btn" @click="s.menu := !s.menu.v"><Avatar :user="meBrief.v" :size="26" /><span class="hide-sp">{{ userName }}</span> ▾</button>
      <div v-if="s.menu" class="menu-bg" @click="s.menu := false"></div>
      <div v-if="s.menu" class="menu" @click="s.menu := false">
        <div class="cur">
          <Avatar :user="meBrief.v" :size="36" />
          <div class="grow"><div class="nm">{{ userName }}</div><div class="muted small">{{ userId }}</div></div>
        </div>
        <RouterLink to="/">ポータル</RouterLink>
        <RouterLink to="/me">個人設定</RouterLink>
        <RouterLink to="/me/security">セキュリティ</RouterLink>
        <RouterLink to="/me/tokens">API トークン</RouterLink>
        <RouterLink v-if="Store.isAdmin" to="/admin">管理</RouterLink>
        <div class="sep"></div>
        <div v-if="others.mapC(_.nonEmpty)" class="muted small hd">ほかのアカウントに切り替える</div>
        <a v-for="a in others" :key="a.userId" href="#" class="acct" @click.prevent="switchTo(a)">
          <Avatar :user="Some(Users.person(a))" :size="24" /><span class="grow">{{ a.name }}<span class="muted small"> {{ a.username }}</span></span>
        </a>
        <a href="#" @click.prevent="addAccount()">＋ 別のアカウントを追加</a>
        <div class="sep"></div>
        <a href="#" @click.prevent="logout()">ログアウト</a>
        <a v-if="others.mapC(_.nonEmpty)" href="#" @click.prevent="logoutAll()">すべてのアカウントからログアウト</a>
      </div>
    </div>
  </header>
  <main>
    <RouterComponent v-if="s.ready" :routes="routes" />
  </main>
  <DialogHost />
  <ToastHost />
</template>

<style scoped>
.top { position: sticky; top: 0; z-index: 100; height: var(--header); display: flex; align-items: center; gap: .8rem; padding: 0 .9rem;
  background: var(--bg); border-bottom: 1px solid var(--line); }
.brand { font-weight: 800; font-size: 1.1rem; color: var(--fg); letter-spacing: .02em; display: inline-flex; align-items: center; gap: .45rem; white-space: nowrap; }
.brand img { display: block; height: 28px; width: auto; max-width: 120px; object-fit: contain; }
.nav { display: flex; gap: .2rem; }
.spacer { flex: 1; }
.me { position: relative; }
.me-btn { gap: .45rem; }
.menu-bg { position: fixed; inset: 0; z-index: 140; }
.menu { position: absolute; right: 0; top: 2.6rem; z-index: 150; background: var(--surface); border: 1px solid var(--line); border-radius: 10px; box-shadow: var(--shadow);
  width: 290px; max-width: calc(100vw - 1.5rem); padding: .35rem; display: flex; flex-direction: column; }
.cur { display: flex; gap: .6rem; align-items: center; padding: .5rem .6rem .6rem; }
.nm { font-weight: 600; }
.hd { padding: .3rem .7rem 0; }
.sep { border-top: 1px solid var(--line); margin: .3rem 0; }
.acct { display: flex; gap: .5rem; align-items: center; }
</style>
