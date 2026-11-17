<script lang="scala">
import sruru.shared.*
import sruru.web.*
import sruru.web.parts.*

import scala.scalajs.concurrent.JSExecutionContext.Implicits.queue

// 管理: ユーザーの一覧（検索・状態での絞り込み・ページ送り）と、ユーザーの作成
case class State(users: RV[List[UserDto]] = RV(Nil), total: RV[Int] = RV(0), q: RV[String] = RV(""), status: RV[String] = RV(""),
                 groupId: RV[String] = RV(""), groups: RV[List[GroupDto]] = RV(Nil), offset: RV[Int] = RV(0), loading: RV[Boolean] = RV(false),
                 creating: RV[Boolean] = RV(false), username: RV[String] = RV(""), name: RV[String] = RV(""), email: RV[String] = RV(""),
                 isAdmin: RV[Boolean] = RV(false), isService: RV[Boolean] = RV(false), pwMode: RV[String] = RV("generate"),
                 password: RV[String] = RV(""), mustChange: RV[Boolean] = RV(true), error: RV[String] = RV(""), busy: RV[Boolean] = RV(false),
                 generated: RV[Option[(UserDto, String)]] = RV(None))

def initState() = State()

val limit = 50

def mounted(s: State): Unit = {
  pageTitle("ユーザー")
  load(s)
  Api.groups().foreach(s.groups := _)
}

def load(s: State): Unit = {
  s.loading := true
  val url = "/api/admin/users" + Api.query("q" -> Some(s.q.v.trim), "status" -> Some(s.status.v), "groupId" -> Some(s.groupId.v),
    "limit" -> Some(limit.toString), "offset" -> Some(s.offset.v.toString))
  Store.report(Api.get[UserListDto](url)) { r => s.users := r.users; s.total := r.total; s.loading := false }
}

def search(s: State): Unit = { s.offset := 0; load(s) }
def page(s: State, d: Int): Unit = { s.offset := math.max(0, s.offset.v + d * limit); load(s) }

def openCreate(s: State): Unit = {
  s.username := ""; s.name := ""; s.email := ""; s.isAdmin := false; s.isService := false; s.pwMode := "generate"; s.password := ""
  s.mustChange := true; s.error := ""; s.creating := true
}

def create(s: State): Unit = {
  val pw = if (s.pwMode.v == "input") Fmt.opt(s.password.v) else None
  val req = UserReq(s.username.v.trim, s.name.v.trim, Fmt.opt(s.email.v), isAdmin = s.isAdmin.v, isService = s.isService.v,
    mustChangePassword = s.mustChange.v && !s.isService.v, password = pw)
  val f = Api.post[UserDto]("/api/admin/users", Api.json(req)).flatMap { u =>
    if (s.pwMode.v == "generate")
      Api.post[GeneratedPasswordDto](s"/api/admin/users/${u.id}/password", Api.json(SetPasswordReq(None, s.mustChange.v && !s.isService.v)))
        .map(g => (u, g.password))
    else scala.concurrent.Future.successful((u, None))
  }
  Store.inline(f, s.error, s.busy) { (u, gen) =>
    s.creating := false
    Store.toast(s"ユーザー「${u.name}」を作りました")
    gen match {
      case Some(p) => s.generated := Some((u, p))
      case None    => Router.go(s"/admin/users/${u.id}")
    }
    load(s)
  }
}

def open(u: UserDto): Unit = Router.go(s"/admin/users/${u.id}")
def generatedList(s: State) = s.generated.mapC(_.toList)
def groupOpts(s: State) = s.groups.mapC(gs => GroupTree.flatten(gs).map((g, _) => Opt(g.id.toString, GroupTree.path(gs, g))))
</script>

<template>
  <section>
    <div class="page-head"><h1>ユーザー</h1><button class="primary" @click="openCreate(s)">＋ ユーザーを作る</button></div>
    <form class="filters" @submit.prevent="search(s)">
      <input type="search" v-model="s.q" placeholder="ユーザー名・名前・メールで検索" class="grow">
      <select v-model="s.status" @change="search(s)">
        <option value="">すべての状態</option>
        <option value="active">有効</option>
        <option value="disabled">無効</option>
        <option value="locked">ロック中</option>
        <option value="admin">管理者</option>
        <option value="service">サービスアカウント</option>
      </select>
      <Combo :bind="Some(s.groupId)" :live="Some(groupOpts(s))" clearLabel="すべてのグループ" placeholder="グループ" :onChange="_ => search(s)" />
      <button type="submit">検索</button>
    </form>
    <div class="table-wrap">
      <table class="list">
        <thead><tr><th></th><th>ユーザー名</th><th>名前</th><th class="hide-sp">メールアドレス</th><th class="hide-sp">グループ</th><th>状態</th><th class="hide-sp">最後のログイン</th></tr></thead>
        <tbody>
          <tr v-for="u in s.users" :key="u.id" class="clickable" @click="open(u)">
            <td><Avatar :user="Some(Users.brief(u))" :size="26" /></td>
            <td class="mono small">{{ u.username }}</td>
            <td>{{ u.name }}</td>
            <td class="small hide-sp">{{ u.email.getOrElse("") }}</td>
            <td class="small hide-sp">{{ u.groups.map(_.name).take(4).mkString(", ") + (if (u.groups.size > 4) " …" else "") }}</td>
            <td><span v-for="b in Users.badges(u)" :class="b._2">{{ b._1 }}</span></td>
            <td class="small nowrap hide-sp">{{ Fmt.optAgo(u.lastLoginAt, "なし") }}</td>
          </tr>
          <tr v-if="s.users.v.isEmpty && !s.loading.v"><td colspan="7" class="muted">該当するユーザーはいません</td></tr>
        </tbody>
      </table>
    </div>
    <div class="pager">
      <Pager :offset="s.offset.v" :total="s.total.v" :limit="limit" :onPage="d => page(s, d)" />
    </div>

    <Modal v-if="s.creating" :onClose="_ => s.creating := false">
      <form @submit.prevent="create(s)">
        <h2>ユーザーを作る</h2>
        <div class="grid2">
          <label class="field"><span>ユーザー名</span><input type="text" v-model="s.username" autocapitalize="none" autofocus></label>
          <label class="field"><span>名前</span><input type="text" v-model="s.name" placeholder="山田 太郎"></label>
        </div>
        <label class="field"><span>メールアドレス</span><input type="email" v-model="s.email"></label>
        <label class="check"><input type="checkbox" v-model="s.isAdmin"><span>管理者</span></label>
        <label class="check"><input type="checkbox" v-model="s.isService"><span>サービスアカウント<span class="hint">人ではなくプログラムが使うアカウント（API トークンで使う）</span></span></label>
        <h3>最初のパスワード</h3>
        <div class="chips">
          <label class="chip"><input type="radio" value="generate" v-model="s.pwMode"> 生成する</label>
          <label class="chip"><input type="radio" value="input" v-model="s.pwMode"> 入力する</label>
          <label class="chip"><input type="radio" value="none" v-model="s.pwMode"> 設定しない</label>
        </div>
        <label v-if='s.pwMode.v == "input"' class="field pw"><span>パスワード</span><input type="text" v-model="s.password" autocomplete="off"></label>
        <label v-if='s.pwMode.v != "none" && !s.isService.v' class="check"><input type="checkbox" v-model="s.mustChange"><span>次のログインで変更させる</span></label>
        <p v-if="s.error.v.nonEmpty" class="error small">{{ s.error }}</p>
        <div class="actions"><button type="button" @click="s.creating := false">キャンセル</button><button type="submit" class="primary" :disabled="s.busy">作る</button></div>
      </form>
    </Modal>

    <Modal v-for="g in generatedList(s)" :onClose="_ => s.generated := None">
      <h2>ユーザーを作りました</h2>
      <p class="small">「{{ g._1.name }}」（{{ g._1.username }}）の最初のパスワードです。<b>この画面を閉じると二度と表示できません。</b>本人に安全な方法で伝えてください。</p>
      <CopyRow :value="g._2" />
      <div class="actions"><button @click="s.generated := None">閉じる</button><button class="primary" @click="s.generated := None; open(g._1)">ユーザーの詳細へ</button></div>
    </Modal>
  </section>
</template>

<style scoped>
.pw { margin-top: .6rem; }
.badge { margin-right: .25rem; }
</style>
