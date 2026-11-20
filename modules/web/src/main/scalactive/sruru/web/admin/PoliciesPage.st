<script lang="scala">
import sruru.shared.*
import sruru.web.*
import sruru.web.parts.*

import scala.scalajs.concurrent.JSExecutionContext.Implicits.queue

// 管理: ポリシー（パスワード・ロック・2段階認証・セッション・IP 制限・クライアント証明書・表示・監査ログ）. 1つの保存ボタンでまとめて保存する.
case class State(loaded: RV[Boolean] = RV(false), groups: RV[List[GroupDto]] = RV(Nil),
                 // パスワード
                 minLength: RV[Int] = RV(10), maxLength: RV[Int] = RV(256), upper: RV[Boolean] = RV(false), lower: RV[Boolean] = RV(false),
                 digit: RV[Boolean] = RV(false), symbol: RV[Boolean] = RV(false), minClasses: RV[Int] = RV(2), history: RV[Int] = RV(5),
                 maxAge: RV[Int] = RV(0), userInfo: RV[Boolean] = RV(true), common: RV[Boolean] = RV(true),
                 // ロック
                 lockEnabled: RV[Boolean] = RV(true), maxFailures: RV[Int] = RV(5), lockMinutes: RV[Int] = RV(15), ipMaxFailures: RV[Int] = RV(30),
                 ipWindow: RV[Int] = RV(15),
                 // 2段階認証
                 mfaMode: RV[String] = RV("optional"), mfaGroups: RV[List[String]] = RV(Nil), mfaAdmins: RV[Boolean] = RV(false),
                 allowTotp: RV[Boolean] = RV(true), allowEmail: RV[Boolean] = RV(true), emailMinutes: RV[Int] = RV(10),
                 // セッション
                 lifetime: RV[Int] = RV(336), idle: RV[Int] = RV(0), maxAccounts: RV[Int] = RV(5),
                 // IP
                 allow: RV[String] = RV(""), deny: RV[String] = RV(""), adminAllow: RV[String] = RV(""), proxies: RV[String] = RV(""),
                 clientIpHeader: RV[String] = RV(""),
                 // 証明書
                 certEnabled: RV[Boolean] = RV(false), certHeader: RV[String] = RV("X-SSL-Client-Cert"), certMapping: RV[String] = RV("registered"),
                 certMfa: RV[Boolean] = RV(true),
                 // 表示・監査
                 title: RV[String] = RV("sruru"), loginMessage: RV[String] = RV(""), selfReg: RV[Boolean] = RV(false), gravatar: RV[Boolean] = RV(false),
                 logo: RV[Option[String]] = RV(None),
                 retention: RV[Int] = RV(365),
                 error: RV[String] = RV(""), busy: RV[Boolean] = RV(false))

def initState() = State()

def mounted(s: State): Unit = {
  pageTitle("ポリシー")
  Api.groups().foreach(s.groups := _)
  Toasts.report(Api.get[PoliciesDto]("/api/admin/policies"))(fill(s, _))
}

def fill(s: State, p: PoliciesDto): Unit = {
  val pw = p.password
  s.minLength := pw.minLength; s.maxLength := pw.maxLength; s.upper := pw.requireUpper; s.lower := pw.requireLower; s.digit := pw.requireDigit
  s.symbol := pw.requireSymbol; s.minClasses := pw.minClasses; s.history := pw.historyCount; s.maxAge := pw.maxAgeDays
  s.userInfo := pw.disallowUserInfo; s.common := pw.disallowCommon
  val l = p.lockout
  s.lockEnabled := l.enabled; s.maxFailures := l.maxFailures; s.lockMinutes := l.lockMinutes; s.ipMaxFailures := l.ipMaxFailures; s.ipWindow := l.ipWindowMinutes
  val m = p.mfa
  s.mfaMode := m.mode; s.mfaGroups := m.requiredGroups; s.mfaAdmins := m.requiredForAdmins; s.allowTotp := m.allowTotp; s.allowEmail := m.allowEmail
  s.emailMinutes := m.emailCodeMinutes
  s.lifetime := p.session.lifetimeHours; s.idle := p.session.idleMinutes; s.maxAccounts := p.session.maxAccounts
  s.allow := p.ip.allow.mkString("\n"); s.deny := p.ip.deny.mkString("\n"); s.adminAllow := p.ip.adminAllow.mkString("\n")
  s.proxies := p.ip.trustedProxies.mkString("\n"); s.clientIpHeader := p.ip.clientIpHeader
  s.certEnabled := p.cert.enabled; s.certHeader := p.cert.header; s.certMapping := p.cert.mapping; s.certMfa := p.cert.countsAsMfa
  s.title := p.branding.title; s.loginMessage := p.branding.loginMessage; s.selfReg := p.branding.selfRegistration; s.gravatar := p.branding.gravatar
  s.logo := p.branding.logo
  s.retention := p.audit.retentionDays
  s.loaded := true
}

def build(s: State): PoliciesDto = PoliciesDto(
  PasswordPolicy(s.minLength.v, s.maxLength.v, s.upper.v, s.lower.v, s.digit.v, s.symbol.v, s.minClasses.v, s.history.v, s.maxAge.v, s.userInfo.v, s.common.v),
  LockoutPolicy(s.lockEnabled.v, s.maxFailures.v, s.lockMinutes.v, s.ipMaxFailures.v, s.ipWindow.v),
  MfaPolicy(s.mfaMode.v, s.mfaGroups.v, s.mfaAdmins.v, s.allowTotp.v, s.allowEmail.v, s.emailMinutes.v),
  SessionPolicy(s.lifetime.v, s.idle.v, s.maxAccounts.v),
  IpPolicy(Fmt.lines(s.allow.v), Fmt.lines(s.deny.v), Fmt.lines(s.adminAllow.v), Fmt.lines(s.proxies.v),
    clientIpHeader = s.clientIpHeader.v.trim),
  CertAuthPolicy(s.certEnabled.v, s.certHeader.v.trim, s.certMapping.v, s.certMfa.v),
  Branding(s.title.v.trim, s.loginMessage.v, s.selfReg.v, s.gravatar.v, s.logo.v),
  AuditPolicy(s.retention.v))

def save(s: State): Unit = Store.inline(Api.putUnit("/api/admin/policies", Api.json(build(s))), s.error, s.busy) { _ =>
  Toasts.show("ポリシーを保存しました")
  Api.clientConfig().foreach(c => Store.config := Some(c))
}

def groupNames(s: State) = s.groups.mapC(gs => GroupTree.flatten(gs).map(_._1.name).distinct)
</script>

<template>
  <section>
    <div class="page-head"><h1>ポリシー</h1></div>
    <form v-if="s.loaded" @submit.prevent="save(s)">
      <section class="panel">
        <h2>パスワード</h2>
        <div class="grid3">
          <label class="field"><span>最小の長さ</span><input type="number" min="1" v-model="s.minLength"></label>
          <label class="field"><span>最大の長さ</span><input type="number" min="8" v-model="s.maxLength"></label>
          <label class="field"><span>使う文字の種類の数（大文字・小文字・数字・記号のうち）</span><input type="number" min="0" max="4" v-model="s.minClasses"></label>
          <label class="field"><span>再利用を禁じる過去のパスワードの数（0 で制限なし）</span><input type="number" min="0" v-model="s.history"></label>
          <label class="field"><span>有効期限（日。0 で無期限）</span><input type="number" min="0" v-model="s.maxAge"></label>
        </div>
        <div class="grid2">
          <label class="check"><input type="checkbox" v-model="s.upper"><span>大文字を必ず使う</span></label>
          <label class="check"><input type="checkbox" v-model="s.lower"><span>小文字を必ず使う</span></label>
          <label class="check"><input type="checkbox" v-model="s.digit"><span>数字を必ず使う</span></label>
          <label class="check"><input type="checkbox" v-model="s.symbol"><span>記号を必ず使う</span></label>
          <label class="check"><input type="checkbox" v-model="s.userInfo"><span>ユーザー名・メールアドレス・名前を含むものを禁じる</span></label>
          <label class="check"><input type="checkbox" v-model="s.common"><span>よく使われるパスワードを禁じる</span></label>
        </div>
      </section>

      <section class="panel">
        <h2>アカウントのロック</h2>
        <label class="check"><input type="checkbox" v-model="s.lockEnabled"><span>続けて失敗したらロックする</span></label>
        <div class="grid2">
          <label class="field"><span>ロックするまでの失敗の回数</span><input type="number" min="1" v-model="s.maxFailures" :disabled="!s.lockEnabled.v"></label>
          <label class="field"><span>ロックする時間（分。0 で管理者が解除するまで）</span><input type="number" min="0" v-model="s.lockMinutes" :disabled="!s.lockEnabled.v"></label>
          <label class="field"><span>同じ IP アドレスからの失敗の上限</span><input type="number" min="1" v-model="s.ipMaxFailures"></label>
          <label class="field"><span>その数える時間（分）</span><input type="number" min="1" v-model="s.ipWindow"></label>
        </div>
      </section>

      <section class="panel">
        <h2>2段階認証</h2>
        <label class="field"><span>使い方</span>
          <select v-model="s.mfaMode"><option value="off">使わない</option><option value="optional">本人が選ぶ（任意）</option><option value="required">全員に必須</option></select></label>
        <template v-if='s.mfaMode.v == "optional"'>
          <label class="check"><input type="checkbox" v-model="s.mfaAdmins"><span>管理者には必須にする</span></label>
          <div class="field"><span>このグループのメンバーには必須にする</span>
            <div class="chips"><label v-for="n in groupNames(s)" class="chip"><input type="checkbox" :value="n" v-model="s.mfaGroups"> {{ n }}</label></div>
            <span v-if="groupNames(s).mapC(_.isEmpty)" class="hint">グループはまだありません。</span></div>
        </template>
        <div class="grid2">
          <label class="check"><input type="checkbox" v-model="s.allowTotp"><span>認証アプリ（TOTP）を使える</span></label>
          <label class="check"><input type="checkbox" v-model="s.allowEmail"><span>メールで届くコードを使える</span></label>
        </div>
        <label class="field narrow-field"><span>メールのコードの有効期間（分）</span><input type="number" min="1" v-model="s.emailMinutes"></label>
      </section>

      <section class="panel">
        <h2>セッション</h2>
        <div class="grid3">
          <label class="field"><span>ログインの有効期間（時間）</span><input type="number" min="1" v-model="s.lifetime"></label>
          <label class="field"><span>操作がなければ切れるまで（分。0 で切れない）</span><input type="number" min="0" v-model="s.idle"></label>
          <label class="field"><span>1つのブラウザで同時に使えるアカウントの数</span><input type="number" min="1" v-model="s.maxAccounts"></label>
        </div>
      </section>

      <section class="panel">
        <h2>IP アドレスの制限</h2>
        <p class="small muted">1行に1つ。<code>192.168.0.0/16</code> のような CIDR か、単独のアドレスを書きます。</p>
        <div class="grid2">
          <label class="field"><span>ログインを許すアドレス（空ならどこからでも）</span><textarea class="code" v-model="s.allow" rows="4"></textarea></label>
          <label class="field"><span>ログインを拒むアドレス</span><textarea class="code" v-model="s.deny" rows="4"></textarea></label>
          <label class="field"><span>管理の画面・管理 API を使えるアドレス（空ならどこからでも）</span><textarea class="code" v-model="s.adminAllow" rows="4"></textarea></label>
          <label class="field"><span>信頼するプロキシ（X-Forwarded-For を使う）</span><textarea class="code" v-model="s.proxies" rows="4"></textarea></label>
          <label class="field"><span>利用者のアドレスのヘッダー（空なら X-Forwarded-For だけを使う）</span><input type="text" v-model="s.clientIpHeader" class="mono" placeholder="CloudFront-Viewer-Address">
            <span class="hint">信頼するプロキシからの要求のときだけ使います。CloudFront なら CloudFront-Viewer-Address（オリジンリクエストポリシーで転送するヘッダーに加えてください）。末尾のポートは取り除きます。無い・読めないときは X-Forwarded-For を使います。</span></label>
        </div>
        <p class="notice warn small">管理の画面を使えるアドレスを制限するときは、今使っているアドレスを含めてください。含めないと、保存した後に管理の画面を開けなくなります。</p>
      </section>

      <section class="panel">
        <h2>クライアント証明書でのログイン</h2>
        <label class="check"><input type="checkbox" v-model="s.certEnabled"><span>証明書でのログインを使う</span></label>
        <div class="grid2">
          <label class="field"><span>証明書を渡すリバースプロキシのヘッダー</span><input type="text" v-model="s.certHeader" class="mono"></label>
          <label class="field"><span>ユーザーの見つけ方</span>
            <select v-model="s.certMapping">
              <option value="registered">登録済みの証明書</option>
              <option value="email">証明書のメールアドレス（SAN）</option>
              <option value="upn">証明書の UPN（SAN）</option>
              <option value="cn">サブジェクトの CN（= ユーザー名）</option>
            </select></label>
        </div>
        <label class="check"><input type="checkbox" v-model="s.certMfa"><span>証明書でのログインを2段階認証とみなす</span></label>
        <p class="small muted">認証局は「証明書の認証局」で登録します。</p>
      </section>

      <section class="panel">
        <h2>表示</h2>
        <label class="field"><span>画面の名前（サービス名）</span><input type="text" v-model="s.title"></label>
        <div class="field"><span>ロゴ</span><LogoPicker :bind="s.logo" /></div>
        <p class="small muted">グループごとに、サービス名・ロゴやセキュリティの設定を上書きできます（グループの画面の「ポリシーの上書き」）。</p>
        <label class="field"><span>ログインの画面に出すお知らせ（任意）</span><textarea v-model="s.loginMessage" rows="3"></textarea></label>
        <label class="check"><input type="checkbox" v-model="s.selfReg"><span>利用者が自分でアカウントを作れる</span></label>
        <label class="check"><input type="checkbox" v-model="s.gravatar"><span>アイコンがないとき Gravatar の画像を使う</span></label>
      </section>

      <section class="panel">
        <h2>監査ログ</h2>
        <label class="field narrow-field"><span>保存期間（日。30 以上。0 で消さない）</span><input type="number" min="0" v-model="s.retention"></label>
      </section>

      <div class="savebar">
        <p v-if="s.error.v.nonEmpty" class="error small">{{ s.error }}</p>
        <button type="submit" class="primary" :disabled="s.busy">保存</button>
      </div>
    </form>
  </section>
</template>

<style scoped>
.narrow-field { max-width: 320px; }
.savebar { position: sticky; bottom: 0; background: var(--bg); border-top: 1px solid var(--line); padding: .7rem 0; display: flex; gap: 1rem; align-items: center; justify-content: flex-end; }
</style>
