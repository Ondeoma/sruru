package sruru.web

import io.circe.*
import io.circe.syntax.*
import io.github.ondeoma.scalactive.routes.Router
import org.scalajs.dom
import sruru.shared.*

import scala.concurrent.Future
import scala.scalajs.concurrent.JSExecutionContext.Implicits.queue

/**
 * バックエンドの REST API（共通部分は sbirds-lib の ApiBase. CSRF 対策のヘッダー X-Sruru: 1 は Fetch.extraHeaders で付く）.
 * 401 はログイン画面へ移る（ログインの画面にいるときを除く）.
 */
object Api extends sbirds.web.ApiBase {

  /** ログイン前でも開く画面にいるか（401 でもログイン画面へ移らない）. */
  def onLoginPage: Boolean = Pages.isLogin(dom.window.location.pathname)

  override protected def stayOnUnauthorized: Boolean = onLoginPage

  override protected def handle(res: dom.Response): Future[Option[Json]] =
    if (res.status == 401 && !onLoginPage) {
      val back = dom.window.location.pathname + dom.window.location.search
      // 直近のログインが必要な操作なら、その旨をログインの画面に出す
      val reauth = Option(res.headers.get("X-Sruru-Reauth")).contains("1")
      dom.window.location.href = "/login?" + (if (reauth) "reauth=1&" else "") + "returnTo=" + enc(back)
      Future.failed(ApiError(401, "ログインしてください"))
    } else super.handle(res)

  /** URL の検索パラメータ（空は None）. */
  def param(name: String): Option[String] = Router.query.v.get(name).filter(_.nonEmpty)

  // ---------------------------------------------------------------- よく使うもの

  def clientConfig(): Future[ClientConfigDto] = get[ClientConfigDto]("/api/client-config")
  def me(): Future[MeDto] = get[MeDto]("/api/me")
  def accounts(): Future[List[AccountDto]] = get[List[AccountDto]]("/api/accounts")
  def idpInfo(): Future[IdpInfoDto] = get[IdpInfoDto]("/api/admin/idp-info")
  def groups(): Future[List[GroupDto]] = get[List[GroupDto]]("/api/admin/groups")
  def attributeDefs(): Future[List[AttributeDefDto]] = get[List[AttributeDefDto]]("/api/admin/attributes")

  def searchUsers(q: String, limit: Int = 20): Future[List[UserDto]] =
    get[UserListDto]("/api/admin/users" + query("q" -> Some(q), "limit" -> Some(limit.toString))).map(_.users)

  /** JSON にする（null の項目を省く）. */
  def json[A: Encoder](a: A): Json = a.asJson.dropNullValues

}
