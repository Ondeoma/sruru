<script lang="scala">
import io.circe.Json
import io.circe.parser.parse
import sruru.shared.*
import sruru.web.*

import java.util.UUID

// グループの設定の入力（詳細の画面にそのまま置く. 作るときはモーダルの中で基本だけ）.
// 基本: 名前・説明・親・管理者・属性（JSON）・動的なメンバーの条件. ポリシーの上書き: 優先度と上書き. 保存ボタンは1つ.
case class Props(group: Option[GroupDto], groups: List[GroupDto], onSaved: GroupDto => Unit, withPolicy: Boolean = true,
                 onCancel: Option[Unit => Unit] = None)

case class State(name: RV[String], desc: RV[String], parent: RV[String], isAdmin: RV[Boolean], attrs: RV[String], dynamic: RV[Boolean],
                 mode: RV[String], rows: RV[List[CondRow]], priority: RV[String], pol: PolicyEdit,
                 error: RV[String] = RV(""), busy: RV[Boolean] = RV(false))

def initState(props: Props) = {
  val g = props.group
  val (m, rows) = Rules.parse(g.flatMap(_.rule))
  State(RV(g.map(_.name).getOrElse("")), RV(g.map(_.description).getOrElse("")), RV(g.flatMap(_.parentId).map(_.toString).getOrElse("")),
    RV(g.exists(_.isAdmin)), RV(g.map(x => if (x.attributes.asObject.exists(_.isEmpty)) "" else x.attributes.spaces2).getOrElse("")),
    RV(g.exists(_.rule.isDefined)), RV(m), RV(if (rows.isEmpty) List(Rules.row()) else rows),
    RV(g.map(_.priority).getOrElse(0).toString), PolicyEdit.from(g.map(_.policy).getOrElse(GroupPolicy())))
}

def save(s: State, props: Props): Unit = {
  val attrs: Either[String, Json] =
    if (s.attrs.v.trim.isEmpty) Right(Json.obj()) else parse(s.attrs.v).left.map(e => "属性の JSON を読めません: " + e.message)
  val all = for {
    a   <- attrs
    pri <- s.priority.v.trim.toIntOption.toRight("優先度は数で入力してください")
    pol <- s.pol.build
  } yield (a, pri, pol)
  all match {
    case Left(e) => s.error := e
    case Right((a, pri, pol)) =>
      val req = GroupReq(s.name.v.trim, s.desc.v.trim, Fmt.opt(s.parent.v).map(UUID.fromString), a, s.isAdmin.v,
        if (s.dynamic.v) Rules.build(s.mode.v, s.rows.v) else None, pri, pol)
      val f = props.group match {
        case Some(g) => Api.put[GroupDto](s"/api/admin/groups/${g.id}", Api.json(req))
        case None    => Api.post[GroupDto]("/api/admin/groups", Api.json(req))
      }
      Store.inline(f, s.error, s.busy)(props.onSaved)
  }
}

def parents(props: Props): List[Opt] =
  GroupTree.flatten(props.groups).filterNot((g, _) => props.group.exists(_.id == g.id)).map((g, _) => Opt(g.id.toString, GroupTree.path(props.groups, g)))
</script>

<template>
  <form @submit.prevent="save(s, props)">
    <section :class='if (props.withPolicy) "panel" else ""'>
      <h2 v-if="props.withPolicy">基本</h2>
      <div class="grid2">
        <label class="field"><span>名前</span><input type="text" v-model="s.name" autofocus></label>
        <div class="field"><span>親のグループ</span><Combo :bind="Some(s.parent)" :options="parents(props)" clearLabel="（なし・最上位）" placeholder="（なし・最上位）" /></div>
      </div>
      <label class="field"><span>説明</span><input type="text" v-model="s.desc"></label>
      <label class="check"><input type="checkbox" v-model="s.isAdmin"><span>管理者のグループ<span class="hint">メンバーは sruru の管理者になります</span></span></label>
      <label class="field"><span>属性（JSON・任意）</span><textarea class="code" v-model="s.attrs" rows="4" placeholder='{"department": "営業部"}'></textarea>
        <span class="hint">アプリに渡す情報の式で <code>group.attributes</code> として使えます。</span></label>
      <label class="check"><input type="checkbox" v-model="s.dynamic"><span>条件でメンバーを自動で決める（動的なグループ）<span class="hint">条件に合うユーザーは自動でメンバーになります。手動のメンバーも加えられます。</span></span></label>
      <RuleEditor v-if="s.dynamic" :mode="s.mode" :rows="s.rows" />
    </section>
    <section v-if="props.withPolicy" class="panel">
      <h2>ポリシーの上書き</h2>
      <label class="field narrow"><span>優先度（大きいほど優先. サービス名・ロゴが重なったとき）</span><input type="text" inputmode="numeric" v-model="s.priority"></label>
      <GroupPolicyFields :e="s.pol" />
    </section>
    <p v-if="!props.withPolicy" class="small muted">ポリシーの上書きは、作った後のグループの画面で設定できます。</p>
    <div :class='if (props.withPolicy) "savebar" else "actions"'>
      <p v-if="s.error.v.nonEmpty" class="error small">{{ s.error }}</p>
      <template v-for="c in props.onCancel.toList"><button type="button" @click="c(())">キャンセル</button></template>
      <button type="submit" class="primary" :disabled="s.busy">{{ if (props.group.isDefined) "保存" else "作る" }}</button>
    </div>
  </form>
</template>

<style scoped>
.narrow { max-width: 360px; }
.savebar { position: sticky; bottom: 0; background: var(--bg); border-top: 1px solid var(--line); padding: .7rem 0; display: flex; gap: 1rem; align-items: center; justify-content: flex-end; }
</style>
