<script lang="scala">
import sruru.shared.*
import sruru.web.*
import sruru.web.parts.*

// 管理: カスタム属性の定義（部署・社員番号など. アプリに渡す情報の式・SCIM でも使える）
case class State(defs: RV[List[AttributeDefDto]] = RV(Nil), editing: RV[Option[Boolean]] = RV(None),
                 key: RV[String] = RV(""), label: RV[String] = RV(""), kind: RV[String] = RV("string"), desc: RV[String] = RV(""),
                 userEditable: RV[Boolean] = RV(false), required: RV[Boolean] = RV(false), scimPath: RV[String] = RV(""), sort: RV[Int] = RV(0),
                 error: RV[String] = RV(""), busy: RV[Boolean] = RV(false))

def initState() = State()

def mounted(s: State): Unit = { pageTitle("カスタム属性"); load(s) }

def load(s: State): Unit = Toasts.report(Api.attributeDefs())(ds => s.defs := ds.sortBy(d => (d.sort, d.key)))

/** 編集を始める（None なら新しく作る）. */
def edit(s: State, d: Option[AttributeDefDto]): Unit = {
  val x = d.getOrElse(AttributeDefDto("", "", sort = s.defs.v.map(_.sort).maxOption.map(_ + 10).getOrElse(10)))
  s.key := x.key; s.label := x.label; s.kind := x.kind; s.desc := x.description; s.userEditable := x.userEditable; s.required := x.required
  s.scimPath := x.scimPath.getOrElse(""); s.sort := x.sort; s.error := ""
  s.editing := Some(d.isEmpty)
}

def save(s: State): Unit = {
  val d = AttributeDefDto(s.key.v.trim, s.label.v.trim, s.kind.v, s.desc.v.trim, s.userEditable.v, s.required.v, Fmt.opt(s.scimPath.v), s.sort.v)
  if (d.key.isEmpty) s.error := "キーを入力してください"
  else Store.inline(Api.putUnit(s"/api/admin/attributes/${Api.enc(d.key)}", Api.json(d)), s.error, s.busy) { _ =>
    s.editing := None; Toasts.show("保存しました"); load(s)
  }
}

def remove(s: State, d: AttributeDefDto): Unit =
  Dialog.confirm(s"属性「${d.label}」の定義を削除しますか？ユーザーに入っている値は残ります。", "削除") {
    Toasts.report(Api.delete(s"/api/admin/attributes/${Api.enc(d.key)}"))(_ => load(s))
  }

def kindLabel(k: String): String = AttrKinds.all.toMap.getOrElse(k, k)
def isNew(s: State) = s.editing.mapC(_.contains(true))
</script>

<template>
  <section>
    <div class="page-head"><h1>カスタム属性</h1><button class="primary" @click="edit(s, None)">＋ 属性を追加</button></div>
    <p class="small muted">ユーザーに持たせる情報（部署・社員番号など）を定義します。アプリに渡す情報の式では
      <code>&#123;&#123;user.attributes.キー&#125;&#125;</code> で使えます。</p>
    <div class="table-wrap">
      <table class="list">
        <thead><tr><th>キー</th><th>表示名</th><th>種類</th><th class="hide-sp">SCIM</th><th>本人が変更</th><th>必須</th><th></th></tr></thead>
        <tbody>
          <tr v-for="d in s.defs" :key="d.key">
            <td class="mono small">{{ d.key }}</td>
            <td>{{ d.label }}<div v-if="d.description.nonEmpty" class="muted small">{{ d.description }}</div></td>
            <td class="small">{{ kindLabel(d.kind) }}</td>
            <td class="small mono hide-sp">{{ d.scimPath.getOrElse("") }}</td>
            <td>{{ if (d.userEditable) "できる" else "" }}</td>
            <td>{{ if (d.required) "必須" else "" }}</td>
            <td class="nowrap"><button class="ghost small" @click="edit(s, Some(d))">編集</button><button class="ghost small" @click="remove(s, d)">削除</button></td>
          </tr>
          <tr v-if="s.defs.mapC(_.isEmpty)"><td colspan="7" class="muted">カスタム属性はまだありません</td></tr>
        </tbody>
      </table>
    </div>
    <Modal v-if="s.editing.mapC(_.isDefined)" :onClose="_ => s.editing := None">
      <form @submit.prevent="save(s)">
        <h2>{{ if (isNew(s).v) "属性を追加" else "属性を編集" }}</h2>
        <div class="grid2">
          <label class="field"><span>キー（英数字・アンダースコア）</span><input type="text" v-model="s.key" class="mono" :disabled="!isNew(s).v" placeholder="department"></label>
          <label class="field"><span>表示名</span><input type="text" v-model="s.label" placeholder="部署"></label>
          <label class="field"><span>種類</span><select v-model="s.kind"><option v-for="k in AttrKinds.all" :value="k._1">{{ k._2 }}</option></select></label>
          <label class="field"><span>並び順</span><input type="number" v-model="s.sort"></label>
        </div>
        <label class="field"><span>説明（入力欄の下に出ます）</span><input type="text" v-model="s.desc"></label>
        <label class="field"><span>SCIM の項目（任意）</span><input type="text" v-model="s.scimPath" class="mono" placeholder="urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department"></label>
        <label class="check"><input type="checkbox" v-model="s.userEditable"><span>本人が個人設定で変更できる</span></label>
        <label class="check"><input type="checkbox" v-model="s.required"><span>必須</span></label>
        <p v-if="s.error.v.nonEmpty" class="error small">{{ s.error }}</p>
        <div class="actions"><button type="button" @click="s.editing := None">キャンセル</button><button type="submit" class="primary" :disabled="s.busy">保存</button></div>
      </form>
    </Modal>
  </section>
</template>
