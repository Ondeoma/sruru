package sruru.api

import cats.effect.*
import io.circe.Json
import io.circe.syntax.*
import org.http4s.*
import org.http4s.circe.CirceEntityCodec.*
import org.http4s.headers.Authorization
import sruru.core.*
import sruru.db.*
import sruru.security.*

import java.net.URLDecoder
import java.nio.charset.StandardCharsets

/** OAuth 2.0 のエラー. */
final case class OAuthError(error: String, description: String, status: Status = Status.BadRequest)

/** 処理の途中で OAuth のエラーの応答に切り替えるための例外（Main の handler が OAuthEndpoint.response で返す）. */
final case class OAuthFailure(error: OAuthError, cause: Throwable) extends RuntimeException(error.description, cause)

object OAuthEndpoint {

  val BodyUnreadable: OAuthError =
    OAuthError("invalid_request", "本文を application/x-www-form-urlencoded として読めません")

  /** OAuth のエラーの応答（RFC 6749 §5.2. キャッシュさせない）. */
  def response(e: OAuthError): Response[IO] =
    Response[IO](e.status).withEntity(Json.obj(
      "error" -> e.error.asJson,
      "error_description" -> e.description.asJson
    )).putHeaders("Cache-Control" -> "no-store", "Pragma" -> "no-cache")
}

/** OAuth 2.0 のエンドポイント（OidcRoutes・DeviceRoutes）に共通の補助: issuer・エラーの応答・パラメータ・クライアントの認証・CORS. */
trait OAuthEndpoint {
  protected def apps: AppStore
  protected def cfg: ApiConfig

  /** この要求のホスト名の issuer・ドメインを決めてから処理する（issuer はホスト名ごと）. */
  protected def here[A](f: Here ?=> IO[A]): IO[A] = cfg.here.flatMap(h => f(using h))
  protected def iss(using h: Here): String = h.url

  protected def oauthErr(e: OAuthError): IO[Response[IO]] = IO.pure(OAuthEndpoint.response(e))

  /** JSON の応答（キャッシュさせない）. */
  protected def json(j: Json): IO[Response[IO]] =
    IO.pure(Response[IO](Status.Ok).withEntity(j).putHeaders("Cache-Control" -> "no-store", "Pragma" -> "no-cache"))

  protected def params(req: Request[IO]): IO[Map[String, String]] =
    // POST は本文だけを使う（クライアントのシークレットやトークンを URL に載せさせない）
    if req.method == Method.POST then
      req.as[UrlForm].map(f => f.values.collect { case (k, v) if v.nonEmpty => k -> v.toList.head })
        // 読めない本文（URL エンコードされていない など）は 500 にせず、OAuth の invalid_request で返す
        .adaptError { case e: MessageFailure => OAuthFailure(OAuthEndpoint.BodyUnreadable, e) }
    else IO.pure(req.params)

  /** スコープの並び（空白区切り）. */
  protected def scopeList(s: String): List[String] = s.split(' ').filter(_.nonEmpty).toList.distinct

  /** クライアントの認証（client_secret_basic・client_secret_post・公開クライアント）. */
  protected def clientAuth(req: Request[IO],
                           form: Map[String, String]): IO[Either[OAuthError, (Application, OidcClientConfig)]] = {
    val basic = req.headers.get[Authorization].collect { case Authorization(BasicCredentials(u, p)) =>
      (URLDecoder.decode(u, StandardCharsets.UTF_8), URLDecoder.decode(p, StandardCharsets.UTF_8))
    }
    val (id, secret) =
      basic.map((u, p) => (Some(u), Some(p))).getOrElse((form.get("client_id"), form.get("client_secret")))
    id match {
      case None => IO.pure(Left(OAuthError("invalid_client", "client_id がありません", Status.Unauthorized)))
      case Some(cid) =>
        apps.byClientId(cid).map {
          case Some((a, c)) if a.enabled =>
            c.secretHash match {
              case None => Either.cond(
                  secret.isEmpty,
                  (a, c),
                  OAuthError("invalid_client", "公開クライアントにシークレットは不要です", Status.Unauthorized)
                )
              case Some(h) =>
                Either.cond(
                  secret.exists(s => Crypto.constantTimeEquals(Crypto.sha256(s), h)),
                  (a, c),
                  OAuthError("invalid_client", "クライアントの認証に失敗しました", Status.Unauthorized)
                )
            }
          case _ => Left(OAuthError("invalid_client", "クライアントが見つかりません", Status.Unauthorized))
        }
    }
  }

  protected def cors(r: IO[Response[IO]]): IO[Response[IO]] =
    r.map(_.putHeaders(
      "Access-Control-Allow-Origin" -> "*",
      "Access-Control-Allow-Headers" -> "Authorization, Content-Type"
    ))
}
