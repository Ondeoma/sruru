<script lang="scala">
import sruru.shared.*
import sruru.web.*
import sruru.web.parts.*


// 個人設定: プロフィール（名前・メールアドレス・電話番号・カスタム属性・アイコン）
case class State(name: RV[String], givenN: RV[String], family: RV[String], email: RV[String], phone: RV[String], locale: RV[String],
                 zone: RV[String], attrs: RV[List[AttrField]], error: RV[String] = RV(""), busy: RV[Boolean] = RV(false),
                 upload: ActionState = useAction())

def initState() = {
  val m = Store.me.v
  def f(g: MeDto => Option[String]) = RV(m.flatMap(g).getOrElse(""))
  State(RV(m.map(_.name).getOrElse("")), f(_.givenName), f(_.familyName), f(_.email), f(_.phoneNumber), f(_.locale), f(_.zoneinfo),
    RV(m.map(x => Attrs.fields(x.attributeDefs, x.attributes)).getOrElse(Nil)))
}

def mounted(): Unit = pageTitle("プロフィール")

def editable(s: State) = s.attrs.mapC(_.filter(_.d.userEditable))
def readonlyAttrs(s: State) = s.attrs.mapC(_.filter(f => !f.d.userEditable && (f.str.v.nonEmpty || f.d.kind == "boolean")))

def save(s: State): Unit = Store.me.v.foreach { m =>
  val req = MeUpdateReq(s.name.v.trim, Fmt.opt(s.givenN.v), Fmt.opt(s.family.v), Fmt.opt(s.email.v), Attrs.build(m.attributes, editable(s).v),
    Fmt.opt(s.locale.v), Fmt.opt(s.zone.v), Fmt.opt(s.phone.v))
  Store.inline(Api.put[MeDto]("/api/me", Api.json(req)), s.error, s.busy) { x => Store.me := Some(x); Toasts.show("保存しました") }
}

def sendVerify(): Unit = Toasts.report(Api.postUnit("/api/me/email/verify"))(_ => Toasts.show("確認のメールを送りました"))

def upload(s: State, e: org.scalajs.dom.Event): Unit = Dom.takeFiles(e).headOption.foreach { file =>
  Toasts.report(s.upload.run(Img.upload("/api/me/avatar", file))) { _ => Toasts.show("アイコンを登録しました"); Store.reloadMe() }
}

def removeAvatar(): Unit = Dialog.confirm("アイコンの画像を外しますか？", "外す") {
  Toasts.report(Api.delete("/api/me/avatar")) { _ => Toasts.show("アイコンを外しました"); Store.reloadMe() }
}

def me = Store.me.mapC(_.toList)
def brief = Store.me.mapC(_.map(Users.person))
def mail = Store.config.mapC(_.exists(_.mailEnabled))
val zones = List("Asia/Tokyo", "UTC", "Asia/Seoul", "Asia/Shanghai", "Asia/Singapore", "America/Los_Angeles", "America/New_York", "Europe/London")
</script>

<template>
  <div class="page narrow">
    <h1>個人設定</h1>
    <MeTabs />
    <template v-for="m in me">
      <section class="panel">
        <div class="row av">
          <Avatar :user="brief.v" :size="72" />
          <div>
            <div class="nm">{{ m.name }}</div>
            <div class="muted small">{{ m.username }}<span v-if='m.source != "local"'> ・ {{ m.source }} から同期</span></div>
            <div class="row btns">
              <label class="btn small">画像を選ぶ<input type="file" accept="image/png,image/jpeg,image/gif,image/webp" class="hidden" @change="upload(s, event)"></label>
              <button v-if="m.hasOwnAvatar" class="ghost small" @click="removeAvatar()">外す</button>
              <span v-if="s.upload.busy" class="muted small">アップロード中…</span>
            </div>
          </div>
        </div>
      </section>

      <form class="panel" @submit.prevent="save(s)">
        <h2>プロフィール</h2>
        <p v-if='m.source != "local"' class="notice small">このアカウントは {{ m.source }} から同期しています。名前やメールアドレスは次の同期で上書きされることがあります。</p>
        <label class="field"><span>表示名</span><input type="text" v-model="s.name" autocomplete="name"></label>
        <div class="grid2">
          <label class="field"><span>姓</span><input type="text" v-model="s.family" autocomplete="family-name"></label>
          <label class="field"><span>名</span><input type="text" v-model="s.givenN" autocomplete="given-name"></label>
        </div>
        <label class="field"><span>メールアドレス
          <span v-if="m.email.isDefined && m.emailVerified" class="badge ok">確認済み</span>
          <span v-if="m.email.isDefined && !m.emailVerified" class="badge warn">未確認</span></span>
          <input type="email" v-model="s.email" autocomplete="email">
          <span v-if="m.email.isDefined && !m.emailVerified && mail.v" class="hint"><a href="#" @click.prevent="sendVerify()">確認のメールを送る</a></span>
          <span v-if="m.email.isDefined && !m.emailVerified && m.verifiedEmail.isDefined" class="hint">確認が済むまで、各サービスには以前のアドレス（{{ m.verifiedEmail.getOrElse("") }}）を渡します</span>
          <span v-if="m.email.isDefined && !m.emailVerified && !m.verifiedEmail.isDefined" class="hint">確認が済むまで、各サービスにはメールアドレスを渡しません</span>
        </label>
        <div class="grid3">
          <label class="field"><span>電話番号</span><input type="tel" v-model="s.phone" autocomplete="tel"></label>
          <label class="field"><span>言語</span>
            <select v-model="s.locale"><option value="">（指定なし）</option><option value="ja">日本語</option><option value="en">English</option></select></label>
          <label class="field"><span>タイムゾーン</span>
            <select v-model="s.zone"><option value="">（指定なし）</option><option v-for="z in zones" :value="z">{{ z }}</option></select></label>
        </div>
        <template v-if="editable(s).mapC(_.nonEmpty)">
          <h3>そのほかの情報</h3>
          <AttrFields :fields="editable(s).v" />
        </template>
        <p v-if="s.error.v.nonEmpty" class="error small">{{ s.error }}</p>
        <button type="submit" class="primary" :disabled="s.busy">保存</button>
      </form>

      <section v-if="readonlyAttrs(s).mapC(_.nonEmpty)" class="panel">
        <h2>管理者が設定した情報</h2>
        <AttrFields :fields="readonlyAttrs(s).v" :readonly="true" />
      </section>

      <section class="panel">
        <h2>所属しているグループ</h2>
        <div v-if="m.groups.nonEmpty" class="chips"><span v-for="g in m.groups" class="badge">{{ g }}</span></div>
        <p v-else class="muted small">どのグループにも入っていません。</p>
        <p v-if="m.isAdmin" class="small"><span class="badge accent">管理者</span> このアカウントは管理者です。</p>
      </section>
    </template>
  </div>
</template>

<style scoped>
.av { gap: 1rem; align-items: center; }
.nm { font-weight: 700; font-size: 1.1rem; }
.btns { margin-top: .4rem; }
</style>
