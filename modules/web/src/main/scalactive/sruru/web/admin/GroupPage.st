<script lang="scala">
import io.circe.syntax.*
import sruru.shared.*
import sruru.web.*
import sruru.web.parts.*

import java.util.UUID
import scala.scalajs.concurrent.JSExecutionContext.Implicits.queue

// 管理: グループの詳細. 設定（基本・ポリシーの上書き）はこの画面で直接編集して保存する.
// メンバー（手動は加える・外す. 条件で入ったメンバーは表示だけ）は、その場で反映する.
case class Props(id: String)

case class State(g: RV[Option[GroupDto]] = RV(None), groups: RV[List[GroupDto]] = RV(Nil), members: RV[Option[GroupMembersDto]] = RV(None),
)

def initState() = State()

def base(props: Props): String = s"/api/admin/groups/${props.id}"

def mounted(s: State, props: Props): Unit = { pageTitle("グループ"); load(s, props) }

def load(s: State, props: Props): Unit = {
  Store.report(Api.get[GroupDto](base(props))) { g => s.g := Some(g); pageTitle(g.name) }
  Api.groups().foreach(s.groups := _)
  loadMembers(s, props)
}

def loadMembers(s: State, props: Props): Unit = Api.get[GroupMembersDto](base(props) + "/members").foreach(m => s.members := Some(m))

def add(s: State, props: Props, id: UUID): Unit =
  Store.report(Api.postUnit(base(props) + "/members", MembersReq(List(id)).asJson))(_ => loadMembers(s, props))

def remove(s: State, props: Props, u: UserBrief): Unit = Dialog.confirm(s"「${u.name}」をこのグループから外しますか？", "外す") {
  Store.report(Api.delete(base(props) + s"/members/${u.id}"))(_ => loadMembers(s, props))
}

/** 保存した後: 見出しと一覧を新しくする（入力の欄はそのまま）. */
def saved(s: State, props: Props, g: GroupDto): Unit = {
  s.g := Some(g); pageTitle(g.name); Store.toast("保存しました")
  Api.groups().foreach(s.groups := _); loadMembers(s, props)
}

def remove(s: State, g: GroupDto): Unit = Dialog.confirm(s"グループ「${g.name}」を削除しますか？メンバーはグループから外れます。", "削除") {
  Store.report(Api.delete(s"/api/admin/groups/${g.id}"))(_ => Router.go("/admin/groups"))
}

/** 編集の欄は、グループを読み込んだ最初の1回だけ作る（保存の後に作り直して入力を失わないように）. */
def first(s: State) = s.g.mapC(_.toList.take(1))

def group(s: State) = s.g.mapC(_.toList)
def mem(s: State) = s.members.mapC(_.toList)
def parentName(s: State, g: GroupDto): String = g.parentId.flatMap(p => s.groups.v.find(_.id == p)).map(_.name).getOrElse("")
def children(s: State, g: GroupDto) = s.groups.mapC(_.filter(_.parentId.contains(g.id)))
</script>

<template>
  <section>
    <p class="small"><RouterLink to="/admin/groups">← グループの一覧</RouterLink></p>
    <template v-for="g in group(s)">
      <div class="page-head">
        <h1>{{ g.name }}</h1>
        <button class="ghost" @click="remove(s, g)">削除</button>
      </div>
      <div class="row small meta">
        <span v-if="g.isAdmin" class="badge accent">管理者のグループ</span>
        <span v-if="g.parentId.isDefined">親: <RouterLink :to='"/admin/groups/" + g.parentId.get'>{{ parentName(s, g) }}</RouterLink></span>
        <span v-if='g.source != "local"' class="badge">{{ g.source }} から同期</span>
        <span v-for="c in children(s, g)">子: <RouterLink :to='"/admin/groups/" + c.id'>{{ c.name }}</RouterLink></span>
      </div>
    </template>
    <template v-for="m in mem(s)">
      <section class="panel">
        <div class="row"><h2 class="grow">手動のメンバー（{{ m.direct.size }}）</h2>
          <div class="picker"><UserPicker :onPick="id => add(s, props, id)" placeholder="ユーザーを検索して加える…" /></div></div>
        <div v-if="m.direct.nonEmpty" class="table-wrap">
          <table class="list">
            <tbody>
              <tr v-for="u in m.direct" :key="u.id">
                <td class="av"><Avatar :user="Some(u)" :size="24" /></td>
                <td><RouterLink :to='"/admin/users/" + u.id'>{{ u.name }}</RouterLink> <span class="muted small mono">{{ u.username }}</span></td>
                <td class="right-cell"><button class="ghost small" @click="remove(s, props, u)">外す</button></td>
              </tr>
            </tbody>
          </table>
        </div>
        <p v-else class="muted small">手動のメンバーはいません。</p>
      </section>
      <section v-if="m.dynamic.nonEmpty" class="panel">
        <h2>条件で入ったメンバー（{{ m.dynamic.size }}）</h2>
        <div class="chips">
          <RouterLink v-for="u in m.dynamic" :key="u.id" :to='"/admin/users/" + u.id' class="chip"><Avatar :user="Some(u)" :size="18" />{{ u.name }}</RouterLink>
        </div>
      </section>
      <p class="small muted">子のグループも含めたメンバーの数: {{ m.effective }}</p>
    </template>
    <template v-for="g in first(s)">
      <GroupEditor :group="Some(g)" :groups="s.groups.v" :onSaved="x => saved(s, props, x)" />
    </template>
  </section>
</template>

<style scoped>
.meta { gap: .8rem; margin-bottom: .8rem; }
.picker { min-width: 260px; }
.av { width: 34px; }
.right-cell { text-align: right; }
</style>
