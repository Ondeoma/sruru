<script lang="scala">
import io.circe.syntax.*
import sruru.shared.*
import sruru.web.*
import sruru.web.parts.*

import scala.scalajs.concurrent.JSExecutionContext.Implicits.queue

// 個人設定: ポリシーの編集を任されたグループ（管理者が、本人か所属するグループに付与したもの）.
// 任されたグループのポリシーの上書きだけを編集できる（名前・メンバーなどは管理者だけ）.
case class Edit(g: DelegatedGroupDto, e: PolicyEdit, err: RV[String] = RV(""), busy: RV[Boolean] = RV(false))

case class State(items: RV[List[Edit]] = RV(Nil), loaded: RV[Boolean] = RV(false))

def initState() = State()

def mounted(s: State): Unit = {
  pageTitle("ポリシーの管理")
  Store.report(Api.get[List[DelegatedGroupDto]]("/api/me/policy-groups")) { gs =>
    s.items := gs.map(g => Edit(g, PolicyEdit.from(g.policy))); s.loaded := true
  }
}

def save(x: Edit): Unit = x.e.build match {
  case Left(e) => x.err := e
  case Right(pol) =>
    x.err := ""; x.busy := true
    Api.put[DelegatedGroupDto](s"/api/me/policy-groups/${x.g.id}", DelegatedPolicyReq(pol).asJson).onComplete { r =>
      x.busy := false
      r.fold(e => x.err := e.getMessage, _ => Store.toast(s"「${x.g.name}」のポリシーを保存しました"))
    }
}

def list(s: State) = s.items.mapC(identity)
</script>

<template>
  <div class="page narrow">
    <h1>個人設定</h1>
    <MeTabs />
    <p v-if="s.loaded.v && s.items.v.isEmpty" class="muted">ポリシーの編集を任されたグループはありません。</p>
    <section v-for="x in list(s)" :key="x.g.id.toString" class="panel">
      <h2>{{ x.g.name }}</h2>
      <p v-if="x.g.description.nonEmpty" class="small muted">{{ x.g.description }}</p>
      <form @submit.prevent="save(x)">
        <GroupPolicyFields :e="x.e" :logoUpload='s"/api/me/policy-groups/${x.g.id}/logos"' />
        <p v-if="x.err.v.nonEmpty" class="error">{{ x.err }}</p>
        <div class="row"><button type="submit" class="primary" :disabled="x.busy">保存</button></div>
      </form>
    </section>
  </div>
</template>
