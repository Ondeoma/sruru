package sruru.federation

import cats.effect.IO
import cats.syntax.all.*
import io.circe.Json
import io.circe.parser.parse
import org.http4s.*
import org.http4s.client.Client
import org.http4s.headers.`Content-Type`
import org.typelevel.ci.CIString

import java.nio.charset.StandardCharsets
import scala.concurrent.duration.*

/** 外部の IdP・ディレクトリとの連携の失敗. */
final class FederationError(msg: String) extends RuntimeException(msg)

/** 応答（本文は読み切ったもの）. */
private[federation] final case class HttpRes(status: Status, headers: Headers, body: Array[Byte]) {
  def text: String = new String(body, StandardCharsets.UTF_8)
  def contentType: Option[String] =
    headers.get[`Content-Type`].map(ct => s"${ct.mediaType.mainType}/${ct.mediaType.subType}")
}

private[federation] object HttpUtil {
  val MaxRetries = 3
  val MaxWait = 60.seconds

  /** 応答の本文の上限（大きな応答でメモリを使い切らせない）. */
  val MaxBody = 32L * 1024 * 1024

  /** 送る. 429・503 は Retry-After（秒）に従って最大3回まで送り直す（なければ 1・2・4 秒待つ）. */
  def run(http: Client[IO], req: Request[IO]): IO[HttpRes] = {
    def loop(attempt: Int): IO[HttpRes] =
      http.run(req).use(r =>
        r.body.take(MaxBody + 1).compile.to(Array).flatMap(b =>
          if b.length > MaxBody then IO.raiseError(new FederationError("応答が大きすぎます"))
          else IO.pure(HttpRes(r.status, r.headers, b))
        )
      ).flatMap { res =>
        if (res.status.code == 429 || res.status.code == 503) && attempt < MaxRetries then
          IO.sleep(retryAfter(res).getOrElse((1L << attempt).seconds).min(MaxWait)) >> loop(attempt + 1)
        else IO.pure(res)
      }
    loop(0)
  }

  def retryAfter(res: HttpRes): Option[FiniteDuration] =
    res.headers.get(CIString("Retry-After")).flatMap(_.head.value.trim.toLongOption).map(_.max(0L).seconds)

  def excerpt(s: String, n: Int = 200): String = {
    val t = s.replaceAll("\\s+", " ").trim
    if t.length > n then t.take(n) + "…" else t
  }

  def failure(what: String, res: HttpRes): FederationError =
    new FederationError(s"$what に失敗しました（HTTP ${res.status.code}）: ${excerpt(res.text)}")

  def parseJson(what: String, res: HttpRes): IO[Json] =
    IO.fromEither(parse(res.text).leftMap(_ => new FederationError(s"$what の応答を読めません: ${excerpt(res.text)}")))

  /** 送って JSON を返す（2xx 以外は失敗）. */
  def json(http: Client[IO], req: Request[IO], what: String): IO[Json] =
    run(http, req).flatMap(res =>
      if res.status.isSuccess then parseJson(what, res) else IO.raiseError(failure(what, res))
    )

  def bearer(req: Request[IO], token: String): Request[IO] =
    req.putHeaders(headers.Authorization(Credentials.Token(AuthScheme.Bearer, token)))

  def uri(s: String): IO[Uri] = IO.fromEither(Uri.fromString(s).leftMap(_ => new FederationError(s"URL の形式が不正です: $s")))

  /** ページ送り（next が None になるまで. 念のため上限を設ける）. */
  def pages(start: Uri, maxPages: Int = 10000)(get: Uri => IO[Json])(items: Json => List[Json],
                                                                     next: Json => Option[Uri]): IO[List[Json]] = {
    def loop(u: Uri, n: Int, acc: Vector[Json]): IO[List[Json]] =
      get(u).flatMap { j =>
        val all = acc ++ items(j)
        next(j) match {
          case Some(nu) if n < maxPages => loop(nu, n + 1, all)
          case Some(_) => IO.raiseError(new FederationError("ページ数が多すぎます"))
          case None => IO.pure(all.toList)
        }
      }
    loop(start, 1, Vector.empty)
  }
}
