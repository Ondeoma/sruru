<script lang="scala">
import sruru.shared.*
import sruru.web.*
import sruru.web.parts.*


// 管理: グループ（親子の木・メンバーの数）
case class State(groups: RV[List[GroupDto]] = RV(Nil), creating: RV[Boolean] = RV(false), q: RV[String] = RV(""))

def initState() = State()

def mounted(s: State): Unit = { pageTitle("グループ"); load(s) }

def load(s: State): Unit = Store.report(Api.groups())(s.groups := _)

def rows(s: State) = computed {
  val q = s.q.v.trim.toLowerCase
  val all = GroupTree.flatten(s.groups.v)
  if (q.isEmpty) all else all.filter((g, _) => g.name.toLowerCase.contains(q) || g.description.toLowerCase.contains(q))
}

/** 作ったら、そのグループの画面へ（メンバー・ポリシーの上書きはそこで設定する）. */
def created(s: State, g: GroupDto): Unit = { s.creating := false; Store.toast("グループを作りました"); Router.go("/admin/groups/" + g.id) }

def remove(s: State, g: GroupDto): Unit = Dialog.confirm(s"グループ「${g.name}」を削除しますか？メンバーはグループから外れます。", "削除") {
  Store.report(Api.delete(s"/api/admin/groups/${g.id}"))(_ => load(s))
}

</script>

<template>
  <section>
    <div class="page-head"><h1>グループ</h1><button class="primary" @click="s.creating := true">＋ グループを作る</button></div>
    <div class="filters"><input type="search" v-model="s.q" placeholder="名前で絞り込み" class="grow"></div>
    <div class="table-wrap">
      <table class="list">
        <thead><tr><th>名前</th><th class="hide-sp">説明</th><th>メンバー</th><th>種類</th><th></th></tr></thead>
        <tbody>
          <tr v-for="gd in rows(s)" :key="gd._1.id" class="clickable" @click='Router.go("/admin/groups/" + gd._1.id)'>
            <td :style="GroupTree.indent(gd._2)"><span v-if="gd._2 > 0" class="muted">└ </span>{{ gd._1.name }}</td>
            <td class="small muted hide-sp">{{ gd._1.description }}</td>
            <td>{{ gd._1.memberCount }}</td>
            <td><span v-if="gd._1.isAdmin" class="badge accent">管理者</span> <span v-if="gd._1.rule.isDefined" class="badge">動的</span>
              <span v-if='gd._1.source != "local"' class="badge">{{ gd._1.source }}</span></td>
            <td class="nowrap" @click.stop="()">
              <button class="ghost small" @click='Router.go("/admin/groups/" + gd._1.id)'>編集</button>
              <button class="ghost small" @click="remove(s, gd._1)">削除</button>
            </td>
          </tr>
          <tr v-if="s.groups.mapC(_.isEmpty)"><td colspan="5" class="muted">グループはまだありません</td></tr>
        </tbody>
      </table>
    </div>
    <GroupForm v-if="s.creating" :groups="s.groups.v" :onSaved="g => created(s, g)" :onClose="_ => s.creating := false" />
  </section>
</template>
