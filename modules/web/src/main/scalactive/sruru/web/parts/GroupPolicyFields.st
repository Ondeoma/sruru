<script lang="scala">
import sruru.web.*

// グループのポリシーの上書きの入力欄（グループの編集フォームの「ポリシーの上書き」タブ）.
// logoUpload: ロゴの画像を上げる先（LogoPicker の uploadUrl）.
case class Props(e: PolicyEdit, logoUpload: String = "/api/admin/logos")
</script>

<template>
  <div>
    <p class="small muted">空欄・チェックなしの項目は全体のポリシーのままです。セキュリティの項目は、全体と所属するすべてのグループのうち<strong>より厳しい方</strong>が効きます。
      サービス名・ロゴは、ログインした後の画面で、上書きしているグループのうち<strong>優先度の大きい方</strong>が使われます。</p>

    <h3>表示</h3>
    <label class="field"><span>サービス名</span><input type="text" v-model="props.e.title" placeholder="（全体のまま）"></label>
    <div class="field"><span>ロゴ</span><LogoPicker :bind="props.e.logo" emptyLabel="全体のロゴ" :uploadUrl="props.logoUpload" /></div>

    <h3>パスワード</h3>
    <div class="grid2">
      <label class="field"><span>最小の長さ</span><input type="text" inputmode="numeric" v-model="props.e.minLength" placeholder="（全体のまま）"></label>
      <label class="field"><span>使う文字の種類の数（1〜4）</span><input type="text" inputmode="numeric" v-model="props.e.minClasses" placeholder="（全体のまま）"></label>
      <label class="field"><span>再利用を禁じる過去のパスワードの数</span><input type="text" inputmode="numeric" v-model="props.e.history" placeholder="（全体のまま）"></label>
      <label class="field"><span>有効期限（日）</span><input type="text" inputmode="numeric" v-model="props.e.maxAge" placeholder="（全体のまま）"></label>
    </div>
    <div class="grid2">
      <label class="check"><input type="checkbox" v-model="props.e.upper"><span>大文字を必ず使う</span></label>
      <label class="check"><input type="checkbox" v-model="props.e.lower"><span>小文字を必ず使う</span></label>
      <label class="check"><input type="checkbox" v-model="props.e.digit"><span>数字を必ず使う</span></label>
      <label class="check"><input type="checkbox" v-model="props.e.symbol"><span>記号を必ず使う</span></label>
      <label class="check"><input type="checkbox" v-model="props.e.userInfo"><span>ユーザー名などを含むものを禁じる</span></label>
      <label class="check"><input type="checkbox" v-model="props.e.common"><span>よく使われるパスワードを禁じる</span></label>
    </div>

    <h3>アカウントのロック</h3>
    <label class="check"><input type="checkbox" v-model="props.e.lockEnabled"><span>続けて失敗したらロックする</span></label>
    <div class="grid2">
      <label class="field"><span>ロックするまでの失敗の回数</span><input type="text" inputmode="numeric" v-model="props.e.maxFailures" placeholder="（全体のまま）"></label>
      <label class="field"><span>ロックする時間（分。0 で管理者が解除するまで）</span><input type="text" inputmode="numeric" v-model="props.e.lockMinutes" placeholder="（全体のまま）"></label>
    </div>

    <h3>2段階認証</h3>
    <label class="field narrow"><span>使い方</span>
      <select v-model="props.e.mfaMode"><option value="">（全体のまま）</option><option value="optional">本人が選ぶ（任意）</option><option value="required">必須</option></select></label>
    <div class="grid2">
      <label class="check"><input type="checkbox" v-model="props.e.noTotp"><span>認証アプリを使わせない</span></label>
      <label class="check"><input type="checkbox" v-model="props.e.noEmail"><span>メールのコードを使わせない</span></label>
    </div>
    <label class="field narrow"><span>メールのコードの有効期間（分）</span><input type="text" inputmode="numeric" v-model="props.e.emailMinutes" placeholder="（全体のまま）"></label>

    <h3>セッション</h3>
    <div class="grid3">
      <label class="field"><span>ログインの有効期間（時間）</span><input type="text" inputmode="numeric" v-model="props.e.lifetime" placeholder="（全体のまま）"></label>
      <label class="field"><span>操作がなければ切れるまで（分）</span><input type="text" inputmode="numeric" v-model="props.e.idle" placeholder="（全体のまま）"></label>
      <label class="field"><span>同時に使えるアカウントの数</span><input type="text" inputmode="numeric" v-model="props.e.maxAccounts" placeholder="（全体のまま）"></label>
    </div>

    <h3>IP アドレスの制限</h3>
    <div class="grid2">
      <label class="field"><span>ログインを許すアドレス（全体の許可にも含まれること）</span><textarea class="code" v-model="props.e.allow" rows="3"></textarea></label>
      <label class="field"><span>ログインを拒むアドレス（全体に加える）</span><textarea class="code" v-model="props.e.deny" rows="3"></textarea></label>
    </div>
  </div>
</template>

<style scoped>
h3 { margin: 1.1rem 0 .4rem; font-size: .95rem; }
.narrow { max-width: 320px; }
</style>
