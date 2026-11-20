<script lang="scala">
import sruru.shared.*
import sruru.web.*

// ドメイン（アクセスするホスト名）のポリシーの上書きの入力欄. グループの上書き（GroupPolicyFields）と同じ並び.
// providers: 選べる外部の IdP.
case class Props(e: DomainEdit, providers: RV[List[FederationDto]])
</script>

<template>
  <div>
    <p class="small muted">空欄・「（全体のまま）」の項目は全体のポリシーのままです。指定した項目は、このホスト名では全体の値を<strong>置き換えます</strong>（全体より緩めることもできます）。
      その上に、ユーザーが所属するグループの上書き（より厳しい方）が重なります。ログインの前の画面にも効きます。</p>

    <h3>表示</h3>
    <label class="field"><span>サービス名</span><input type="text" v-model="props.e.title" placeholder="（全体のまま）"></label>
    <div class="field"><span>ロゴ</span><LogoPicker :bind="props.e.logo" emptyLabel="全体のロゴ" /></div>
    <label class="check"><input type="checkbox" v-model="props.e.messageOn"><span>ログインの画面の案内を上書きする</span></label>
    <label v-if="props.e.messageOn" class="field"><span>ログインの画面の案内（空にすると、このホスト名では案内を出しません）</span><textarea v-model="props.e.message" rows="2"></textarea></label>

    <h3>ログインの方法</h3>
    <div class="grid2">
      <Tri :bind="props.e.selfReg" label="利用者が自分でアカウントを作る" yes="許す" no="許さない" />
      <Tri :bind="props.e.cert" label="クライアント証明書でのログイン" yes="使う" no="使わない" />
    </div>
    <label class="check"><input type="checkbox" v-model="props.e.providersOn"><span>使える外部の IdP を絞る</span></label>
    <div v-if="props.e.providersOn" class="idp-list">
      <label v-for="f in props.providers" class="check" :key="f.id">
        <input type="checkbox" :value="f.slug" v-model="props.e.providers"><span>{{ f.name }} <span class="muted small mono">{{ f.slug }}</span></span></label>
      <p v-if="props.providers.mapC(_.isEmpty)" class="muted small">外部の IdP はまだありません（このホスト名では外部の IdP を使わせません）。</p>
      <p class="hint">どれも選ばなければ、このホスト名では外部の IdP を使わせません。</p>
    </div>

    <h3>管理機能</h3>
    <label class="check"><input type="checkbox" v-model="props.e.admin"><span>このホスト名で管理の画面・管理の API を使える</span></label>

    <h3>パスワード</h3>
    <div class="grid2">
      <label class="field"><span>最小の長さ</span><input type="text" inputmode="numeric" v-model="props.e.minLength" placeholder="（全体のまま）"></label>
      <label class="field"><span>使う文字の種類の数（1〜4）</span><input type="text" inputmode="numeric" v-model="props.e.minClasses" placeholder="（全体のまま）"></label>
      <label class="field"><span>再利用を禁じる過去のパスワードの数</span><input type="text" inputmode="numeric" v-model="props.e.history" placeholder="（全体のまま）"></label>
      <label class="field"><span>有効期限（日。0 で無期限）</span><input type="text" inputmode="numeric" v-model="props.e.maxAge" placeholder="（全体のまま）"></label>
    </div>
    <div class="grid3">
      <Tri :bind="props.e.upper" label="大文字" yes="必ず使う" no="求めない" />
      <Tri :bind="props.e.lower" label="小文字" yes="必ず使う" no="求めない" />
      <Tri :bind="props.e.digit" label="数字" yes="必ず使う" no="求めない" />
      <Tri :bind="props.e.symbol" label="記号" yes="必ず使う" no="求めない" />
      <Tri :bind="props.e.userInfo" label="ユーザー名などを含むもの" yes="禁じる" no="禁じない" />
      <Tri :bind="props.e.common" label="よく使われるパスワード" yes="禁じる" no="禁じない" />
    </div>

    <h3>アカウントのロック</h3>
    <div class="grid3">
      <Tri :bind="props.e.lockEnabled" label="続けて失敗したとき" yes="ロックする" no="ロックしない" />
      <label class="field"><span>ロックするまでの失敗の回数</span><input type="text" inputmode="numeric" v-model="props.e.maxFailures" placeholder="（全体のまま）"></label>
      <label class="field"><span>ロックする時間（分。0 で管理者が解除するまで）</span><input type="text" inputmode="numeric" v-model="props.e.lockMinutes" placeholder="（全体のまま）"></label>
    </div>

    <h3>2段階認証</h3>
    <div class="grid2">
      <label class="field"><span>使い方</span>
        <select v-model="props.e.mfaMode"><option value="">（全体のまま）</option><option value="off">使わない</option><option value="optional">本人が選ぶ（任意）</option><option value="required">必須</option></select></label>
      <label class="field"><span>メールのコードの有効期間（分）</span><input type="text" inputmode="numeric" v-model="props.e.emailMinutes" placeholder="（全体のまま）"></label>
      <Tri :bind="props.e.totp" label="認証アプリ" yes="使える" no="使わせない" />
      <Tri :bind="props.e.email" label="メールのコード" yes="使える" no="使わせない" />
    </div>

    <h3>セッション</h3>
    <div class="grid3">
      <label class="field"><span>ログインの有効期間（時間）</span><input type="text" inputmode="numeric" v-model="props.e.lifetime" placeholder="（全体のまま）"></label>
      <label class="field"><span>操作がなければ切れるまで（分。0 で切れない）</span><input type="text" inputmode="numeric" v-model="props.e.idle" placeholder="（全体のまま）"></label>
      <label class="field"><span>同時に使えるアカウントの数</span><input type="text" inputmode="numeric" v-model="props.e.maxAccounts" placeholder="（全体のまま）"></label>
    </div>

    <h3>IP アドレスの制限</h3>
    <label class="check"><input type="checkbox" v-model="props.e.ipOn"><span>IP アドレスの許可・拒否を上書きする（全体の許可・拒否の代わりに、下の内容を使う）</span></label>
    <div v-if="props.e.ipOn" class="grid2">
      <label class="field"><span>ログインを許すアドレス（空なら制限なし）</span><textarea class="code" v-model="props.e.allow" rows="3"></textarea></label>
      <label class="field"><span>ログインを拒むアドレス</span><textarea class="code" v-model="props.e.deny" rows="3"></textarea></label>
    </div>
  </div>
</template>

<style scoped>
h3 { margin: 1.1rem 0 .4rem; font-size: .95rem; }
.idp-list { border: 1px solid var(--line); border-radius: 8px; padding: .3rem .7rem; margin: .3rem 0; }
</style>
