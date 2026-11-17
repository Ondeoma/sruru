<script lang="scala">
import io.circe.syntax.*
import sruru.shared.*
import sruru.web.*
import sruru.web.parts.*

import scala.scalajs.concurrent.JSExecutionContext.Implicits.queue

// アカウントの選択（このブラウザでログインしているアカウントから、アプリで使うものを選ぶ）
case class State(req: RV[Option[AuthRequestDto]] = RV(None),
                 accounts: RV[List[AccountDto]] = RV(Nil),
                 error: RV[String] = RV(""),
                 busy: RV[Boolean] = RV(false))

def initState() = State()

def reqId: String = Api.param("req").getOrElse("")

def mounted(s: State): Unit = {
  pageTitle("アカウントの選択")
  Store.inline(Api.get[AuthRequestDto](s"/api/auth-requests/${Api.enc(reqId)}"), s.error)(r => s.req := Some(r))
  Api.accounts().foreach(s.accounts := _)
}

def pick(s: State, a: AccountDto): Unit =
  Store.inline(Api.post[RedirectDto](s"/api/auth-requests/${Api.enc(reqId)}/select", SwitchReq(a.userId).asJson), s.error, s.busy)(r => Dom.goto(r.redirect))

def another(): Unit = Dom.goto("/login?req=" + Api.enc(reqId) + "&add=1")

def app(s: State) = s.req.mapC(_.map(_.app).toList)
</script>

<template>
  <PublicCard>
    <template v-for="a in app(s)">
      <div class="app-head">
        <AppIcon :name="a.name" :iconUrl="a.iconUrl" :size="44" />
        <div class="small muted">「{{ a.name }}」で使うアカウントを選んでください</div>
      </div>
    </template>
    <h1>アカウントの選択</h1>
    <div class="stack">
      <button v-for="a in s.accounts" :key="a.userId" class="acct" :disabled="s.busy" @click="pick(s, a)">
        <Avatar :user="Some(Users.brief(a))" :size="34" />
        <span class="grow left"><span class="nm">{{ a.name }}</span><br><span class="muted small">{{ a.username }}</span></span>
        <span v-if="a.active" class="badge accent">使用中</span>
      </button>
      <button class="acct" @click="another()"><span class="plus">＋</span><span class="grow left">別のアカウントを使う</span></button>
    </div>
    <p v-if="s.error.v.nonEmpty" class="error small">{{ s.error }}</p>
  </PublicCard>
</template>

<style scoped>
.app-head { display: flex; flex-direction: column; align-items: center; gap: .4rem; margin-bottom: 1rem; }
.acct { justify-content: flex-start; gap: .7rem; padding: .55rem .8rem; width: 100%; white-space: normal; }
.left { text-align: left; }
.nm { font-weight: 600; }
.plus { width: 34px; height: 34px; border-radius: 50%; border: 1px dashed var(--line); display: inline-flex; align-items: center; justify-content: center; }
</style>
