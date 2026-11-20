<script lang="scala">
import io.circe.Json
import io.circe.syntax.*
import sruru.web.*

import java.util.UUID

// 式の書き方の説明と、ユーザーを選んで式を試す欄
case class State(expr: RV[String] = RV("{{user.email}}"), user: RV[Option[UUID]] = RV(None), userName: RV[String] = RV(""),
                 result: RV[String] = RV(""), open: RV[Boolean] = RV(false))

def initState() = State()

def pick(s: State, id: UUID): Unit = {
  s.user := Some(id)
  run(s)
}

def run(s: State): Unit = s.user.v.foreach { id =>
  Toasts.report(Api.post[Json]("/api/admin/expr/test", Json.obj("expression" -> s.expr.v.asJson, "userId" -> id.asJson))) { j =>
    val c = j.hcursor
    s.result := c.get[String]("error").map("エラー: " + _).getOrElse(c.downField("value").focus.map(_.spaces2).getOrElse(j.spaces2))
  }
}
</script>

<template>
  <div class="help">
    <div class="row"><b class="grow">式の書き方</b><a href="#" @click.prevent="s.open := !s.open.v">{{ if (s.open.v) "閉じる" else "開く" }}</a></div>
    <template v-if="s.open">
      <ul>
        <li><code>&#123;&#123;user.email&#125;&#125;</code>・<code>&#123;&#123;user.username&#125;&#125;</code>・<code>&#123;&#123;user.name&#125;&#125;</code>・<code>&#123;&#123;user.id&#125;&#125;</code>: ユーザーの情報</li>
        <li><code>&#123;&#123;user.attributes.department&#125;&#125;</code>: カスタム属性（department の部分は属性のキー）</li>
        <li><code>&#123;&#123;user.groups&#125;&#125;</code>: 入っているグループの名前のリスト</li>
        <li><code>&#123;&#123;user.groups | filter_prefix:"app-" | strip_prefix:"app-"&#125;&#125;</code>: 「app-」で始まるグループだけを、先頭の「app-」を除いて渡す</li>
        <li>文字と組み合わせられます: <code>&#123;&#123;user.family_name&#125;&#125; &#123;&#123;user.given_name&#125;&#125;</code></li>
      </ul>
      <p class="small">フィルター（<code>|</code> の後に書く）:</p>
      <ul class="filters-list">
        <li v-for="f in Mappings.filters"><code>{{ f._1 }}</code> {{ f._2 }}</li>
      </ul>
      <p class="small">試す:</p>
      <div class="row">
        <input type="text" v-model="s.expr" class="mono grow">
        <div class="pick"><UserPicker :combo="true" :search="UserSearch.search" :hint="UserSearch.hint" :onPick="p => pick(s, UserSearch.id(p))" placeholder="ユーザーを選んで試す…" :small="true" /></div>
        <button type="button" class="small" :disabled="s.user.v.isEmpty" @click="run(s)">試す</button>
      </div>
      <pre v-if="s.result.v.nonEmpty" class="json res">{{ s.result }}</pre>
    </template>
  </div>
</template>

<style scoped>
.filters-list { columns: 2; font-size: .8rem; }
.pick { min-width: 220px; }
.res { margin-top: .5rem; }
@media (max-width: 720px) { .filters-list { columns: 1; } }
</style>
