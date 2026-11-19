<script lang="scala">
import io.circe.syntax.*
import sruru.shared.*
import sruru.web.*

import java.util.UUID
import scala.scalajs.concurrent.JSExecutionContext.Implicits.queue

// 管理: グループのポリシーを編集できる人（ユーザー・グループ）. 付与された人は、個人設定の「ポリシーの管理」で
// このグループのポリシーの上書きだけを編集できる. 変えるとすぐ保存する.
case class Props(groupId: String)

case class State(d: RV[PolicyEditorsDto] = RV(PolicyEditorsDto()), groups: RV[List[GroupDto]] = RV(Nil), pick: RV[String] = RV(""))

def initState() = State()

def url(props: Props): String = s"/api/admin/groups/${props.groupId}/policy-editors"

def mounted(s: State, props: Props): Unit = {
  Api.groups().foreach(gs => s.groups := gs.sortBy(_.name))
  Store.report(Api.get[PolicyEditorsDto](url(props)))(s.d := _)
}

def save(s: State, props: Props, users: List[UUID], groups: List[UUID]): Unit =
  Store.report(Api.put[PolicyEditorsDto](url(props), PolicyEditorsReq(users.distinct, groups.distinct).asJson))(s.d := _)

def addUser(s: State, props: Props, id: UUID): Unit = save(s, props, s.d.v.users.map(_.id) :+ id, s.d.v.groups.map(_.id))

def addGroup(s: State, props: Props): Unit = if (s.pick.v.nonEmpty) {
  save(s, props, s.d.v.users.map(_.id), s.d.v.groups.map(_.id) :+ UUID.fromString(s.pick.v)); s.pick := ""
}

def removeUser(s: State, props: Props, u: UserBrief): Unit = save(s, props, s.d.v.users.map(_.id).filterNot(_ == u.id), s.d.v.groups.map(_.id))
def removeGroup(s: State, props: Props, g: GroupBrief): Unit = save(s, props, s.d.v.users.map(_.id), s.d.v.groups.map(_.id).filterNot(_ == g.id))

def users(s: State) = s.d.mapC(_.users)
def editorGroups(s: State) = s.d.mapC(_.groups)
def candidates(s: State) = s.groups.mapC(identity)
</script>

<template>
  <section class="panel">
    <h2>ポリシーを編集できる人</h2>
    <p class="small muted">ここに加えたユーザーと、加えたグループのメンバーは、個人設定の「ポリシーの管理」で、このグループのポリシーの上書きだけを編集できます（管理者の権限は付きません）。</p>
    <div class="chips">
      <span v-for="u in users(s)" :key="u.id.toString" class="chip"><Avatar :user="Some(u)" :size="18" />{{ u.name }}
        <button type="button" class="ghost small" @click="removeUser(s, props, u)">×</button></span>
      <span v-for="g in editorGroups(s)" :key="g.id.toString" class="chip">グループ: {{ g.name }}
        <button type="button" class="ghost small" @click="removeGroup(s, props, g)">×</button></span>
    </div>
    <p v-if="s.d.v.users.isEmpty && s.d.v.groups.isEmpty" class="muted small">まだいません（管理者だけが編集できます）。</p>
    <div class="row add">
      <div class="picker"><UserPicker :onPick="id => addUser(s, props, id)" placeholder="ユーザーを検索して加える…" /></div>
      <label class="field"><select v-model="s.pick"><option value="">（グループを選ぶ）</option><option v-for="g in candidates(s)" :value="g.id.toString">{{ g.name }}</option></select></label>
      <button type="button" class="small" @click="addGroup(s, props)">グループを加える</button>
    </div>
  </section>
</template>

<style scoped>
.add { align-items: center; gap: .6rem; margin-top: .6rem; }
.picker { min-width: 260px; }
</style>
