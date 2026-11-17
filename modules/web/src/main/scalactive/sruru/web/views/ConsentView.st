<script lang="scala">
import io.circe.syntax.*
import sruru.shared.*
import sruru.web.*
import sruru.web.parts.*


// 同意（アプリに渡す情報を確かめて、許可するかを選ぶ）
case class State(req: RV[Option[AuthRequestDto]] = RV(None),
                 error: RV[String] = RV(""),
                 busy: RV[Boolean] = RV(false))

def initState() = State()

def reqId: String = Api.param("req").getOrElse("")

def mounted(s: State): Unit = {
  pageTitle("アクセスの許可")
  Store.inline(Api.get[AuthRequestDto](s"/api/auth-requests/${Api.enc(reqId)}"), s.error)(r => s.req := Some(r))
}

def answer(s: State, approve: Boolean): Unit = s.req.v.foreach { r =>
  Store.inline(Api.post[RedirectDto]("/api/consent", ConsentReq(r.id, approve).asJson), s.error, s.busy)(x => Dom.goto(x.redirect))
}

def items(s: State) = s.req.mapC(_.toList)
</script>

<template>
  <PublicCard>
    <template v-for="r in items(s)">
      <div class="app-head">
        <AppIcon :name="r.app.name" :iconUrl="r.app.iconUrl" :size="52" />
        <h1>「{{ r.app.name }}」へのアクセスを許可しますか？</h1>
        <p v-if="r.app.description.nonEmpty" class="small muted">{{ r.app.description }}</p>
      </div>
      <template v-if="r.scopes.nonEmpty">
        <p class="small">このアプリは次の情報を使います。</p>
        <ul class="scopes">
          <li v-for="sc in r.scopes"><b>{{ sc.description }}</b> <span class="muted small">（{{ sc.name }}）</span></li>
        </ul>
      </template>
      <p class="small muted">許可はあとで「個人設定 → セキュリティ」から取り消せます。</p>
      <div class="row btns">
        <button class="grow" :disabled="s.busy" @click="answer(s, false)">拒否</button>
        <button class="primary grow" :disabled="s.busy" @click="answer(s, true)">許可</button>
      </div>
    </template>
    <p v-if="s.error.v.nonEmpty" class="error small">{{ s.error }}</p>
  </PublicCard>
</template>

<style scoped>
.app-head { display: flex; flex-direction: column; align-items: center; gap: .5rem; margin-bottom: .6rem; text-align: center; }
.app-head h1 { margin: .3rem 0 0; }
.scopes { padding-left: 1.2rem; margin: .4rem 0 1rem; }
.scopes li { margin: .25rem 0; }
.btns { margin-top: 1rem; }
</style>
