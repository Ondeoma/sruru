package sruru.api

import cats.effect.IO
import munit.CatsEffectSuite
import org.http4s.*
import org.http4s.client.Client
import org.http4s.headers.{Location, `Content-Type`}
import org.http4s.implicits.*

class SiteIconSpec extends CatsEffectSuite {

  private val png = Array[Byte](0x89.toByte, 'P', 'N', 'G', 13, 10, 26, 10, 0, 0)
  private val ico = Array[Byte](0, 0, 1, 0, 1, 0)

  test("HTML の link から候補を選ぶ（apple-touch-icon → SVG → 大きい順. 相対 URL は解決. data: は使わない）") {
    val html =
      """<html><head>
        |<link rel="icon" href="/small.png" sizes="16x16">
        |<LINK REL='shortcut icon' href='big.png' sizes='64x64'>
        |<link href="data:image/png;base64,AAAA" rel="icon">
        |<link rel="apple-touch-icon" href="https://cdn.example.com/touch.png">
        |<link rel="stylesheet" href="/style.css">
        |</head></html>""".stripMargin
    val got = SiteIcon.candidates(html, uri"https://app.example.com/app/home").map(_.renderString)
    assertEquals(
      got,
      List(
        "https://cdn.example.com/touch.png",
        "https://app.example.com/app/big.png",
        "https://app.example.com/small.png"
      )
    )
  }

  test("画像の種類は中身で判定する") {
    assertEquals(SiteIcon.sniff(png), Some("image/png"))
    assertEquals(SiteIcon.sniff(ico), Some("image/x-icon"))
    assertEquals(SiteIcon.sniff("<svg xmlns='http://www.w3.org/2000/svg'></svg>".getBytes), Some("image/svg+xml"))
    assertEquals(SiteIcon.sniff("<html>not an image</html>".getBytes), None)
  }

  test("取りに行けるのは https と開発用の http://localhost だけ") {
    assert(SiteIcon.allowed(uri"https://app.example.com/"))
    assert(SiteIcon.allowed(uri"http://localhost:8080/"))
    assert(!SiteIcon.allowed(uri"http://10.0.0.5/"))
    assert(!SiteIcon.allowed(uri"http://localhost.evil.test/"))
    assert(!SiteIcon.allowed(uri"https://user:pw@app.example.com/"))
    assert(!SiteIcon.allowed(uri"ftp://app.example.com/"))
  }

  /** 偽のサイト. */
  private def site(routes: PartialFunction[String, IO[Response[IO]]]): Client[IO] =
    Client.fromHttpApp(HttpApp[IO](req =>
      routes.applyOrElse(req.uri.renderString, (_: String) => IO.pure(Response[IO](Status.NotFound)))
    ))

  private def body(b: Array[Byte], ct: String = "application/octet-stream") =
    IO.pure(Response[IO](
      Status.Ok
    ).withEntity(b)(using EntityEncoder.byteArrayEncoder).withContentType(`Content-Type`(MediaType.unsafeParse(ct))))

  test("トップページの link をたどる（リダイレクトも）") {
    val c = site {
      case "https://app.example.com/" =>
        IO.pure(Response[IO](Status.Found).putHeaders(Location(uri"https://app.example.com/login")))
      case "https://app.example.com/login" => body("""<link rel="icon" href="/i.png">""".getBytes, "text/html")
      case "https://app.example.com/i.png" => body(png, "text/plain") // ヘッダーが違っても中身で判定する
    }
    SiteIcon(c).fetch("https://app.example.com/").map(r => assertEquals(r.map(_._2), Right("image/png")))
  }

  test("link がなければ /favicon.ico. 画像でないものは使わない") {
    val c = site {
      case "https://app.example.com/start" => body("<html></html>".getBytes, "text/html")
      case "https://app.example.com/favicon.ico" => body(ico)
    }
    val bad = site { case "https://app.example.com/favicon.ico" => body("<html>soft 404</html>".getBytes, "text/html") }
    for {
      ok <- SiteIcon(c).fetch("https://app.example.com/start")
      ng <- SiteIcon(bad).fetch("https://app.example.com/")
    } yield {
      assertEquals(ok.map(_._2), Right("image/x-icon"))
      assert(ng.isLeft)
    }
  }

  test("http へのリダイレクトや、スクリプトを含む SVG は使わない") {
    val c = site {
      case "https://app.example.com/" =>
        body("""<link rel="icon" href="/x.svg"><link rel="icon" href="http://10.0.0.5/i.png">""".getBytes, "text/html")
      case "https://app.example.com/x.svg" =>
        body("<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>".getBytes)
      case "https://app.example.com/favicon.ico" =>
        IO.pure(Response[IO](Status.Found).putHeaders(Location(uri"http://169.254.169.254/latest")))
    }
    SiteIcon(c).fetch("https://app.example.com/").map(r => assert(r.isLeft, r.toString))
  }
}
