package sruru.api

import cats.effect.*
import cats.syntax.all.*
import org.http4s.*
import org.http4s.client.Client
import org.http4s.headers.{Accept, Location, `User-Agent`}

import java.nio.charset.StandardCharsets
import scala.concurrent.duration.*

/**
 * アプリのサイトのアイコン（favicon）を取りに行く.
 * トップページの HTML の `<link rel="icon">`・`apple-touch-icon` を探し（大きいものを優先）、なければ `/favicon.ico`.
 *
 * 管理者が登録した URL へサーバーから接続するので（SSRF）、https（開発用の http://localhost を除く）だけにし、
 * リダイレクト・時間・大きさを制限する. 画像は中身（先頭のバイト）で種類を判定し、SVG はスクリプトなどを含むものを拒否する.
 */
final class SiteIcon(http: Client[IO]):
  import SiteIcon.*

  /** 取れたら (画像, Content-Type). 取れなければ理由. */
  def fetch(site: String): IO[Either[String, (Array[Byte], String)]] =
    Uri.fromString(site.trim).toOption.filter(allowed) match
      case None => IO.pure(Left("https の URL ではありません（開発用の http://localhost を除く）"))
      case Some(u) =>
        val origin = u.copy(path = Uri.Path.Root, query = Query.empty, fragment = None)
        (for
          page  <- get(u, MaxHtml).map(_.toOption)
          links  = page.toList.flatMap((base, body) => SiteIcon.candidates(new String(body, StandardCharsets.UTF_8), base))
          tries  = (links ++ List(origin.withPath(Uri.Path.unsafeFromString("/favicon.ico")))).distinct.take(MaxTries)
          found <- tries.collectFirstSomeM(c => image(c))
        yield found.toRight("サイトのアイコンが見つかりませんでした")).timeout(Overall).handleError(e => Left(s"サイトに接続できません: ${e.getMessage}"))

  private def image(u: Uri): IO[Option[(Array[Byte], String)]] =
    get(u, MaxImage).map(_.toOption.flatMap((_, b) => SiteIcon.sniff(b).filter(ct => ct != Svg || Conv.safeSvg(new String(b, StandardCharsets.UTF_8))).map(b -> _)))

  /** GET（リダイレクトは 3 回まで. その先も同じ条件）. 本文は max まで. (最後の URL, 本文). */
  private type Step = Either[(Uri, Array[Byte]), Uri]   // Left: 本文, Right: リダイレクト先

  private def get(u: Uri, max: Int, hops: Int = 0): IO[Either[String, (Uri, Array[Byte])]] =
    if !allowed(u) then IO.pure(Left("許可されていない URL です"))
    else
      val req = Request[IO](Method.GET, u).putHeaders(`User-Agent`(ProductId("sruru-icon-fetcher")),
        Accept(MediaRange.`text/*`, MediaRange.`image/*`, MediaRange.`*/*`.withQValue(QValue.unsafeFromString("0.1"))))
      http.run(req).use { r =>
        if r.status.responseClass == Status.Redirection then
          IO.pure(r.headers.get[Location].map(l => u.resolve(l.uri)).toRight("リダイレクト先がありません").map(x => Right(x): Step))
        else if !r.status.isSuccess then IO.pure(Left(s"HTTP ${r.status.code}"): Either[String, Step])
        else r.body.take(max.toLong + 1).compile.to(Array).map(b => Either.cond(b.length <= max, Left((u, b)): Step, "大きすぎます"))
      }.timeout(Each).flatMap {
        case Right(Right(next)) if hops < MaxHops => get(next, max, hops + 1)
        case Right(Right(_))                      => IO.pure(Left("リダイレクトが多すぎます"))
        case Right(Left(ok))                      => IO.pure(Right(ok))
        case Left(e)                              => IO.pure(Left(e))
      }

object SiteIcon:
  val MaxHtml  = 512 * 1024
  val MaxImage = 512 * 1024
  val MaxHops  = 3
  val MaxTries = 4
  val Each     = 5.seconds
  val Overall  = 12.seconds
  val Svg      = "image/svg+xml"

  private val LocalHosts = Set("localhost", "127.0.0.1", "[::1]", "::1")

  /** https か、開発用の http://localhost. 認証情報（user@host）を含む URL は使わない. */
  def allowed(u: Uri): Boolean =
    u.authority.exists(a => a.userInfo.isEmpty) && u.host.isDefined &&
      (u.scheme.contains(Uri.Scheme.https) || u.scheme.contains(Uri.Scheme.http) && u.host.exists(h => LocalHosts(h.value.toLowerCase)))

  private val LinkTag = """(?is)<link\b[^>]*>""".r
  private def attr(tag: String, name: String): Option[String] =
    s"""(?is)\\b$name\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))""".r.findFirstMatchIn(tag)
      .map(m => Option(m.group(1)).orElse(Option(m.group(2))).getOrElse(m.group(3)).trim)

  /**
   * HTML の `<link>` からアイコンの候補（良いものから）. apple-touch-icon（大きい）→ SVG → サイズの大きい順 → そのほか.
   * 相対の URL はページの URL から解決する. data: などは使わない.
   */
  def candidates(html: String, base: Uri): List[Uri] =
    val head = html.take(MaxHtml)
    LinkTag.findAllIn(head).toList.flatMap { tag =>
      val rel = attr(tag, "rel").map(_.toLowerCase.split("\\s+").toSet).getOrElse(Set.empty)
      val isIcon = rel.contains("icon") || rel.contains("apple-touch-icon") || rel.contains("apple-touch-icon-precomposed")
      for
        href <- attr(tag, "href").filter(_ => isIcon).filter(h => !h.toLowerCase.startsWith("data:"))
        ref  <- Uri.fromString(href.replace("&amp;", "&")).toOption
      yield
        val size  = attr(tag, "sizes").flatMap(_.toLowerCase.split("\\s+").flatMap(_.split('x').headOption.flatMap(_.toIntOption)).maxOption).getOrElse(0)
        val svg   = attr(tag, "type").exists(_.contains("svg")) || href.toLowerCase.endsWith(".svg")
        val touch = rel.exists(_.startsWith("apple-touch-icon"))
        val score = (if touch then 1000 else 0) + (if svg then 500 else 0) + size
        (score, base.resolve(ref))
    }.sortBy(-_._1).map(_._2).distinct

  /** 画像の種類（先頭のバイトで判定. ヘッダーは信用しない）. */
  def sniff(b: Array[Byte]): Option[String] =
    def starts(sig: Int*): Boolean = b.length >= sig.length && sig.indices.forall(i => (b(i) & 0xff) == sig(i))
    if starts(0x89, 0x50, 0x4e, 0x47) then Some("image/png")
    else if starts(0xff, 0xd8, 0xff) then Some("image/jpeg")
    else if starts(0x47, 0x49, 0x46, 0x38) then Some("image/gif")
    else if b.length >= 12 && starts(0x52, 0x49, 0x46, 0x46) && new String(b.slice(8, 12), StandardCharsets.US_ASCII) == "WEBP" then Some("image/webp")
    else if starts(0x00, 0x00, 0x01, 0x00) then Some("image/x-icon")
    else
      val t = new String(b.take(2048), StandardCharsets.UTF_8).trim.toLowerCase
      Option.when((t.startsWith("<svg") || t.startsWith("<?xml")) && t.contains("<svg"))(Svg)
