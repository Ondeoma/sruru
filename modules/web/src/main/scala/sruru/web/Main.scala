package sruru.web

import io.github.ondeoma.scalactive.ScalactiveConfig
import io.github.ondeoma.scalactive.components.ComponentManager.*
import org.scalajs.dom

/**
 * 画面の入口.
 * `@main def main()` にすると生成される `main` クラスと `Main` が、大文字小文字を区別しないファイルシステム（macOS）で
 * 同じファイル名になり差分コンパイルが壊れるため、通常の main(args) にする.
 */
object Main {

  def main(args: Array[String]): Unit = {
    ScalactiveConfig.titleTemplate = "%s | sruru"
    ScalactiveConfig.defaultTitle = Some("sruru")
    Theme.apply()
    // お知らせは 5 秒（エラーは 9 秒）で消す
    Toasts.duration = 5000
    // 共通部品（PWA の購読など）の更新の要求にも CSRF 対策のヘッダーを付ける
    Fetch.extraHeaders = Map("X-Sruru" -> "1")
    // skorimako のブラウザの観測（IdP なので、ログイン・同意などの画面では読み込まず、ログインした人が決まってから読み込む）と、
    // PWA（ホーム画面に追加・オフラインで開く・プッシュ通知）
    Observe.start(enabled = !sruru.shared.Pages.isPublic(dom.window.location.pathname), deferUntilUser = true)
    Pwa.register()
    App()(using dom.document.body, AddMethod.appendS(IdSelector("app"))).init()
  }

}
