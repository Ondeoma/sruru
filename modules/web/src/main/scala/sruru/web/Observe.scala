package sruru.web

import org.scalajs.dom
import sruru.shared.Pages

import scala.concurrent.Future
import scala.scalajs.concurrent.JSExecutionContext.Implicits.queue
import scala.scalajs.js

/**
 * skorimako のブラウザの観測（RUM）. サーバーに設定（SKORIMAKO_RUM_TOKEN）があれば `{endpoint}/rum.js` を読み込む.
 * 表示の速さ（Web Vitals）・JavaScript のエラー・API の失敗が skorimako に届く.
 * （rum.js は skorimako が配る SDK なので JS のまま. 読み込みと利用者の紐付けだけここで行う）
 *
 * IdP なので、ログイン・同意・パスワードの再設定などの画面（URL に秘密の値が入ることがある・外部のスクリプトを読ませたくない）では読み込まない.
 * ログインした人が決まった（/api/me を読めた）ときに setUser から読み込む. ログインの画面で開いたページでは、
 * 画面の中でログインした後も読み込まない（サーバーもその画面の CSP では RUM の読み込み先を許していない）.
 */
object Observe {

  private var enabled = false
  private var loaded = false
  private var user: Option[String] = None

  // 読み込む前は無い（js.Dynamic.global で読むと ReferenceError になるので window のプロパティとして読む）
  private def sdk: js.UndefOr[js.Dynamic] = dom.window.asInstanceOf[js.Dynamic].skorimako.asInstanceOf[js.UndefOr[js.Dynamic]]

  /** 画面の起動時に1度呼ぶ. 開いたページがログインの前の画面なら、このページでは使わない. */
  def start(): Unit = enabled = !Pages.isPublic(dom.window.location.pathname)

  /** ログインした人（ユーザーの ID）. /api/me を読んだ後に呼ぶ. 初めて呼ばれたときに RUM を読み込む. */
  def setUser(id: String): Unit = {
    user = Some(id)
    if (enabled && !loaded) { loaded = true; load() } else push(id)
  }

  /** 設定がなければ（204）何もしない. */
  private def load(): Unit = {
    val init = new dom.RequestInit {}
    init.credentials = dom.RequestCredentials.`same-origin`
    dom.fetch("/api/observe/rum", init).toFuture
      .flatMap(r => if (r.status == 200) r.json().toFuture.map(j => Option(j.asInstanceOf[js.Dynamic])) else Future.successful(None))
      .foreach {
        case Some(c) if !js.isUndefined(c.token) && !js.isUndefined(c.endpoint) =>
          val s = dom.document.createElement("script").asInstanceOf[dom.HTMLScriptElement]
          s.src = s"${c.endpoint}/rum.js"
          s.defer = true
          s.setAttribute("data-token", c.token.toString)
          s.setAttribute("data-endpoint", c.endpoint.toString)
          if (!js.isUndefined(c.sampleRate) && c.sampleRate != null) s.setAttribute("data-sample-rate", c.sampleRate.toString)
          s.onload = (_: dom.Event) => user.foreach(push)
          dom.document.head.appendChild(s)
        case _ => ()
      }
  }

  private def push(id: String): Unit = sdk.foreach(_.setUser(id))

}
