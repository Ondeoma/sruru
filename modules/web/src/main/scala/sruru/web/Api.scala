package sruru.web

import io.circe.*
import io.circe.parser.parse
import io.circe.syntax.*
import org.scalajs.dom
import sruru.shared.*

import scala.concurrent.Future
import scala.scalajs.concurrent.JSExecutionContext.Implicits.queue
import scala.scalajs.js

/** API の呼び出しのエラー. */
final case class ApiError(status: Int, message: String) extends Exception(message)

/**
 * バックエンドの REST API.
 * GET 以外は CSRF 対策のヘッダー（X-Sruru: 1）を付ける. 401 はログイン画面へ移る（ログインの画面にいるときを除く）.
 * エラーは {"error": ...} の文言にする.
 */
object Api {

  /** ログイン前でも開く画面にいるか（401 でもログイン画面へ移らない）. */
  def onLoginPage: Boolean = Pages.isLogin(dom.window.location.pathname)

  /** 本文: JSON か、そのままのデータ（画像・XML）と Content-Type. */
  private enum Body {
    case JsonBody(j: Json)
    case Raw(data: js.Any, contentType: String)
  }

  private def request(method: dom.HttpMethod, url: String, body: Option[Body] = None): Future[Option[Json]] = {
    val init = new dom.RequestInit {}
    init.method = method
    init.credentials = dom.RequestCredentials.`same-origin`
    val headers = js.Dictionary[String]("Accept" -> "application/json")
    if (method != dom.HttpMethod.GET) headers("X-Sruru") = "1"
    body.foreach {
      case Body.JsonBody(j) =>
        headers("Content-Type") = "application/json"
        init.body = j.noSpaces
      case Body.Raw(d, ct) =>
        headers("Content-Type") = ct
        init.body = d.asInstanceOf[dom.BodyInit]
    }
    init.headers = headers
    dom.fetch(url, init).toFuture.flatMap { res =>
      if (res.status == 401 && !onLoginPage) {
        val back = dom.window.location.pathname + dom.window.location.search
        // 直近のログインが必要な操作なら、その旨をログインの画面に出す
        val reauth = Option(res.headers.get("X-Sruru-Reauth")).contains("1")
        dom.window.location.href = "/login?" + (if (reauth) "reauth=1&" else "") + "returnTo=" + enc(back)
        Future.failed(ApiError(401, "ログインしてください"))
      } else if (!res.ok) {
        res.text().toFuture.recover(_ => "").flatMap { t =>
          val msg = parse(t).toOption.flatMap(_.hcursor.get[String]("error").toOption).getOrElse(s"${res.status} ${res.statusText}")
          Future.failed(ApiError(res.status, msg))
        }
      } else if (res.status == 204) Future.successful(None)
      else res.text().toFuture.map(t => if (t.isEmpty) None else Some(parse(t).fold(e => throw ApiError(0, e.getMessage), identity)))
    }
  }

  private def as[A: Decoder](j: Option[Json]): A = j.getOrElse(Json.Null).as[A].fold(e => throw ApiError(0, "応答を読めません: " + e.getMessage), identity)

  def get[A: Decoder](url: String): Future[A] = request(dom.HttpMethod.GET, url).map(as[A])
  def post[A: Decoder](url: String, body: Json = Json.obj()): Future[A] = request(dom.HttpMethod.POST, url, Some(Body.JsonBody(body))).map(as[A])
  def put[A: Decoder](url: String, body: Json): Future[A] = request(dom.HttpMethod.PUT, url, Some(Body.JsonBody(body))).map(as[A])
  def delete(url: String): Future[Unit] = request(dom.HttpMethod.DELETE, url).map(_ => ())
  def deleteJson(url: String, body: Json): Future[Unit] = request(dom.HttpMethod.DELETE, url, Some(Body.JsonBody(body))).map(_ => ())
  def postUnit(url: String, body: Json = Json.obj()): Future[Unit] = request(dom.HttpMethod.POST, url, Some(Body.JsonBody(body))).map(_ => ())
  def putUnit(url: String, body: Json): Future[Unit] = request(dom.HttpMethod.PUT, url, Some(Body.JsonBody(body))).map(_ => ())

  /** そのままのデータ（画像・XML）を本文にして POST する. */
  def postRaw[A: Decoder](url: String, data: js.Any, contentType: String): Future[A] =
    request(dom.HttpMethod.POST, url, Some(Body.Raw(data, contentType))).map(as[A])

  def postRawUnit(url: String, data: js.Any, contentType: String): Future[Unit] =
    request(dom.HttpMethod.POST, url, Some(Body.Raw(data, contentType))).map(_ => ())

  def enc(s: String): String = js.URIUtils.encodeURIComponent(s)

  def query(params: (String, Option[String])*): String = {
    val q = params.collect { case (k, Some(v)) if v.nonEmpty => s"$k=${enc(v)}" }
    if (q.isEmpty) "" else q.mkString("?", "&", "")
  }

  /** URL の検索パラメータ. */
  def param(name: String): Option[String] =
    Option(new dom.URL(dom.window.location.href).searchParams.get(name)).filter(_.nonEmpty)

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
