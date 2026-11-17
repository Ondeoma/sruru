<script lang="scala">
import sruru.web.*

// アプリに渡す情報（OIDC のクレーム・SAML の属性）の対応付け. 行ごとに 名前・式・（OIDC）スコープ・（SAML）表示名・複数の値.
case class Props(rows: RV[List[MappingRow]], saml: Boolean)

def add(props: Props): Unit = props.rows := props.rows.v :+ Mappings.empty()
def remove(props: Props, r: MappingRow): Unit = props.rows := props.rows.v.filterNot(_.id == r.id)
</script>

<template>
  <div class="rows">
    <div v-for="r in props.rows" :key="r.id" class="map-row">
      <input type="text" v-model="r.name" :placeholder='if (props.saml) "属性の名前" else "クレームの名前"'>
      <input type="text" v-model="r.expression" class="mono" placeholder="&#123;&#123;user.email&#125;&#125;">
      <input v-if="props.saml" type="text" v-model="r.friendlyName" placeholder="表示名（任意）">
      <input v-else type="text" v-model="r.scope" placeholder="スコープ（任意）">
      <label class="small nowrap"><input type="checkbox" v-model="r.multi"> 複数の値</label>
      <button type="button" class="ghost small" title="この行を消す" @click="remove(props, r)">✕</button>
    </div>
    <p v-if="props.rows.mapC(_.isEmpty)" class="muted small">標準の情報だけを渡します。</p>
    <button type="button" class="small" @click="add(props)">＋ 追加</button>
  </div>
</template>
