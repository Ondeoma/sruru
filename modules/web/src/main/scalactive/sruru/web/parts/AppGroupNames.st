<script lang="scala">
import io.circe.syntax.*
import sruru.shared.*
import sruru.web.*

import java.util.UUID
import scala.scalajs.concurrent.JSExecutionContext.Implicits.queue

// 管理: グループごとのアプリケーションの表示名・ロゴの上書き（アプリケーションの詳細の画面）.
// 所属するグループのうち優先度の大きいものの名前・ロゴが、ポータルと sbirds のサービス（ID トークンの sbirds_apps・sbirds_logos）に出る.
// 名前だけ・ロゴだけの上書きもできる.
case class Props(appId: String)

case class State(items: RV[List[AppGroupNameDto]] = RV(Nil), groups: RV[List[GroupDto]] = RV(Nil),
                 group: RV[String] = RV(""), name: RV[String] = RV(""), logo: RV[Option[String]] = RV(None))

def initState() = State()

def url(props: Props): String = s"/api/admin/apps/${props.appId}/group-names"

def mounted(s: State, props: Props): Unit = {
  Api.groups().foreach(gs => s.groups := gs.sortBy(_.name))
  Toasts.report(Api.get[List[AppGroupNameDto]](url(props)))(s.items := _)
}

def save(s: State, props: Props, items: List[AppGroupNameDto]): Unit =
  Toasts.report(Api.put[List[AppGroupNameDto]](url(props), AppGroupNamesReq(items).asJson)) { xs => s.items := xs; Toasts.show("保存しました") }

def add(s: State, props: Props): Unit =
  if (s.group.v.nonEmpty && (s.name.v.trim.nonEmpty || s.logo.v.isDefined)) {
    val gid = UUID.fromString(s.group.v)
    save(s, props, s.items.v.filterNot(_.groupId == gid) :+ AppGroupNameDto(gid, "", s.name.v.trim, s.logo.v))
    s.group := ""; s.name := ""; s.logo := None
  }

def remove(s: State, props: Props, x: AppGroupNameDto): Unit = save(s, props, s.items.v.filterNot(_.groupId == x.groupId))

def rows(s: State) = s.items.mapC(identity)
def candidates(s: State) = s.groups.mapC(identity)
</script>

<template>
  <section class="panel">
    <h2>グループごとの表示名・ロゴ</h2>
    <p class="small muted">そのグループのメンバーには、アプリケーションの名前・アイコンの代わりにこの名前・ロゴが出ます（ポータルと、sbirds のサービスのヘッダーなど）。
      複数のグループに上書きがあるときは、グループの優先度の大きい方が使われます。名前だけ・ロゴだけの上書きもできます。</p>
    <table v-if="rows(s).v.nonEmpty" class="list">
      <tbody>
        <tr v-for="x in rows(s)" :key="x.groupId.toString">
          <td>{{ x.groupName }}</td>
          <td><strong>{{ x.name }}</strong></td>
          <td class="logo-cell"><img v-if="x.logo.isDefined" :src="Branding.logoUrl(x.logo)" alt="ロゴ"></td>
          <td class="right-cell"><button type="button" class="ghost small" @click="remove(s, props, x)">外す</button></td>
        </tr>
      </tbody>
    </table>
    <div class="row add">
      <label class="field"><span>グループ</span>
        <select v-model="s.group"><option value="">（選ぶ）</option><option v-for="g in candidates(s)" :value="g.id.toString">{{ g.name }}</option></select></label>
      <label class="field grow"><span>表示名</span><input type="text" v-model="s.name" maxlength="100"></label>
      <button type="button" class="small" @click="add(s, props)">追加</button>
    </div>
    <div class="field"><span>ロゴ（任意）</span><LogoPicker :bind="s.logo" emptyLabel="アプリケーションのアイコン" /></div>
  </section>
</template>

<style scoped>
.add { align-items: flex-end; gap: .6rem; }
.right-cell { text-align: right; }
.logo-cell img { max-height: 24px; max-width: 60px; }
</style>
