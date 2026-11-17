<script lang="scala">
import sruru.web.*

import java.util.UUID
import scala.scalajs.concurrent.JSExecutionContext.Implicits.queue

// ユーザーを検索して選ぶ（管理者用. 入力した文字でサーバーを検索する）. 選ぶと onPick を呼び、欄を空にする.
case class Props(onPick: UUID => Unit, placeholder: String = "ユーザーを検索…", small: Boolean = false)

case class State(opts: RV[List[Opt]] = RV(Nil), timer: RV[Option[Int]] = RV(None))

def initState() = State()

def query(s: State, q: String): Unit = {
  s.timer.v.foreach(org.scalajs.dom.window.clearTimeout)
  s.timer := Some(org.scalajs.dom.window.setTimeout(() => Api.searchUsers(q.trim).foreach(us => s.opts := Opt.users(us)), 200))
}

def live(s: State) = s.opts.mapC(identity)
</script>

<template>
  <Combo :live="Some(live(s))" :keep="false" :filter="false" :small="props.small" :placeholder="props.placeholder" :onQuery="q => query(s, q)"
    :onChange="v => props.onPick(UUID.fromString(v))" />
</template>
