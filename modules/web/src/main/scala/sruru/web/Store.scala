package sruru.web

import io.circe.Json
import io.github.ondeoma.scalactive.components.ComponentManager.*
import org.scalajs.dom
import sruru.shared.*

import java.util.UUID
import scala.concurrent.Future
import scala.scalajs.concurrent.JSExecutionContext.Implicits.queue
import scala.scalajs.js
import scala.util.{Failure, Success}

final case class Toast(id: Int, text: String, error: Boolean)

/** 画面全体で共有する状態（自分・画面の設定・ログイン中のアカウント・トースト）. */
object Store {

  val me: RV[Option[MeDto]] = RV(None)
  val config: RV[Option[ClientConfigDto]] = RV(None)
  val accounts: RV[List[AccountDto]] = RV(Nil)
  val toasts: RV[List[Toast]] = RV(Nil)

  private var toastSeq = 0

  def myId: Option[UUID] = me.v.map(_.id)

  /** 管理者か（管理機能を閉じたホスト名（ドメイン）では、管理者でも管理の画面を出さない）. */
  def isAdmin = me.mapC(_.exists(_.isAdmin) && config.v.forall(_.adminEnabled))

  /** 画面の名前（ポリシーの「表示」で変えられる）. */
  def title = config.mapC(_.map(_.title).filter(_.nonEmpty).getOrElse("sruru"))

  /** ロゴの URL（ポリシーの「表示」とグループの上書き）. */
  def logo = config.mapC(_.map(_.logoUrl).getOrElse("/logo.svg"))

  // ---------------------------------------------------------------- トースト

  def toast(text: String, error: Boolean = false): Unit = {
    toastSeq += 1
    val t = Toast(toastSeq, text, error)
    toasts := (toasts.v :+ t).takeRight(5)
    dom.window.setTimeout(() => dismiss(t.id), if (error) 9000 else 5000)
  }

  def dismiss(id: Int): Unit = toasts := toasts.v.filterNot(_.id == id)

  def error(e: Throwable): Unit = e match {
    case ApiError(401, _) if !Api.onLoginPage => ()
    case other => toast(other.getMessage, error = true)
  }

  /** Future の失敗をトーストで知らせる. */
  def report[A](f: Future[A])(ok: A => Unit): Unit = f.onComplete {
    case Success(a) => ok(a)
    case Failure(e) => error(e)
  }

  /** 失敗を画面の中（err）に出す. */
  def inline[A](f: Future[A], err: RV[String], busy: RV[Boolean] = RV(false))(ok: A => Unit): Unit = {
    err := ""
    busy := true
    f.onComplete { r =>
      busy := false
      r match {
        case Success(a) => ok(a)
        case Failure(e) => err := e.getMessage
      }
    }
  }

  // ---------------------------------------------------------------- 読み込み

  def reloadMe(): Future[MeDto] = Api.me().map { m => me := Some(m); m }

  def loadAccounts(): Unit = Api.accounts().foreach(accounts := _)

}

/** DOM のイベント・クリップボード・ファイルの補助. */
object Dom {

  /** 入力欄（input・select・textarea）の値. */
  def value(e: dom.Event): String = e.target.asInstanceOf[js.Dynamic].value.asInstanceOf[String]

  def checked(e: dom.Event): Boolean = e.target.asInstanceOf[dom.HTMLInputElement].checked

  def copy(text: String, message: String = "コピーしました"): Unit = {
    dom.window.navigator.clipboard.writeText(text)
    Store.toast(message)
  }

  /** 文字をファイルとして保存させる. */
  def download(fileName: String, text: String, contentType: String = "text/plain;charset=utf-8"): Unit = {
    val blob = new dom.Blob(js.Array(text), new dom.BlobPropertyBag { `type` = contentType })
    val url = dom.URL.createObjectURL(blob)
    val a = dom.document.createElement("a").asInstanceOf[dom.HTMLAnchorElement]
    a.href = url
    a.asInstanceOf[js.Dynamic].download = fileName
    dom.document.body.appendChild(a)
    a.click()
    a.remove()
    dom.window.setTimeout(() => dom.URL.revokeObjectURL(url), 1000)
  }

  /** ファイルの選択欄から1つ目のファイル（選んだ後は欄を空にする）. */
  def file(e: dom.Event): Option[dom.File] = {
    val input = e.target.asInstanceOf[dom.HTMLInputElement]
    val f = Option(input.files).filter(_.length > 0).map(_(0))
    input.value = ""
    f
  }

  /** ブラウザごと移る（サーバー側の画面・ログインのやり直し）. */
  def goto(url: String): Unit = dom.window.location.href = url

  def origin: String = dom.window.location.origin

}

/** 画像（アイコン）の補助. */
object Img {

  /**
   * 画像を中央で正方形に切り取り、size px に縮めて PNG の Blob にする（アイコンの登録用）.
   * 読めない画像（アニメーション GIF の一部など）は元のファイルをそのまま返す.
   */
  def squareThumb(file: dom.File, size: Int = 256): Future[dom.Blob] = {
    val p = scala.concurrent.Promise[dom.Blob]()
    val url = dom.URL.createObjectURL(file)
    val img = dom.document.createElement("img").asInstanceOf[dom.HTMLImageElement]
    img.onload = (_: dom.Event) => {
      val s = math.min(img.naturalWidth, img.naturalHeight)
      val canvas = dom.document.createElement("canvas").asInstanceOf[dom.HTMLCanvasElement]
      canvas.width = math.min(size, s)
      canvas.height = canvas.width
      val ctx = canvas.getContext("2d").asInstanceOf[dom.CanvasRenderingContext2D]
      ctx.asInstanceOf[js.Dynamic].imageSmoothingQuality = "high"
      ctx.drawImage(
        img,
        (img.naturalWidth - s) / 2.0,
        (img.naturalHeight - s) / 2.0,
        s,
        s,
        0,
        0,
        canvas.width,
        canvas.height
      )
      dom.URL.revokeObjectURL(url)
      // scalajs-dom に toBlob の定義がないので、DOM のメソッドをそのまま呼ぶ
      canvas.asInstanceOf[js.Dynamic].toBlob((b: dom.Blob) => p.success(if (b == null) file else b), "image/png")
    }
    img.addEventListener("error", (_: dom.Event) => { dom.URL.revokeObjectURL(url); p.success(file) })
    img.src = url
    p.future
  }

  /** 正方形に切り取って 256px に縮め、本文として送る. */
  def upload(url: String, file: dom.File): Future[Unit] = {
    squareThumb(file).flatMap { b =>
      val ct = Option(b.`type`).filter(_.nonEmpty).getOrElse("image/png")
      Api.postRawUnit(url, b, ct)
    }
  }

}

/** QR コード（frontend/main.js の qrcode）. */
object Qr {

  def dataUrl(text: String): Future[String] =
    dom.window.asInstanceOf[js.Dynamic].sruruQr.toDataURL(
      text,
      js.Dynamic.literal(margin = 1, width = 200)
    ).asInstanceOf[js.Promise[String]].toFuture

}

/** 表示の補助. */
object Fmt {

  // 日時の表示（2026/11/15 09:30・「3分前」）は sbirds-lib
  export sbirds.web.Dates.{ago, dateTime}

  def date(t: Timestamp): String = dateTime(t).take(10)

  def optDateTime(t: Option[Timestamp], empty: String = "—"): String = t.map(dateTime).getOrElse(empty)

  def optAgo(t: Option[Timestamp], empty: String = "—"): String = t.map(ago).getOrElse(empty)

  def initials(name: String): String = name.trim.take(1).toUpperCase

  /** 文字から決まる色相（アイコンの背景）. */
  def hue(s: String): Int = math.abs(s.hashCode) % 360

  /** 1行に1つ（空行は除く）. */
  def lines(s: String): List[String] = s.split("\n").toList.map(_.trim).filter(_.nonEmpty)

  /** カンマ区切り（空は除く）. */
  def commas(s: String): List[String] = s.split(",").toList.map(_.trim).filter(_.nonEmpty)

  def opt(s: String): Option[String] = Option(s.trim).filter(_.nonEmpty)

  def pretty(j: Json): String = j.spaces2

  /** ブラウザの種類（User-Agent から大まかに）. */
  def browser(ua: Option[String]): String = ua.fold("不明") { u =>
    val b =
      if (u.contains("Edg/")) "Edge"
      else if (u.contains("Chrome/")) "Chrome"
      else if (u.contains("Firefox/")) "Firefox"
      else if (u.contains("Safari/")) "Safari" else "ブラウザ"
    val os =
      if (u.contains("Windows")) "Windows"
      else if (u.contains("iPhone") || u.contains("iPad")) "iOS"
      else if (u.contains("Android")) "Android"
      else if (u.contains("Mac OS")) "macOS" else if (u.contains("Linux")) "Linux" else ""
    if (os.isEmpty) b else s"$b（$os）"
  }

  /** ログインの方法（amr）. */
  def amr(a: List[String]): String = a.map {
    case "pwd" => "パスワード"
    case "otp" => "認証アプリ"
    case "mfa" => "多要素"
    case "email" => "メール"
    case "x509" | "hwk" | "sc" => "証明書"
    case "fed" => "外部 IdP"
    case x => x
  }.distinct.mkString("・")

}

/** 画面内のダイアログ（ブラウザ標準の confirm・prompt・alert の代わり）. 表示は parts/DialogHost.st. */
final case class DialogReq(message: String,
                           okLabel: String,
                           danger: Boolean,
                           input: Option[RV[String]],
                           cancel: Boolean,
                           onOk: String => Unit,
                           onCancel: () => Unit,
                           placeholder: String = "")

object Dialog {

  val current: RV[Option[DialogReq]] = RV(None)

  private def open(r: DialogReq): Unit = current := Some(r)

  /** 確認（OK を押したら f）. */
  def confirm(message: String, ok: String = "OK", danger: Boolean = true)(f: => Unit): Unit =
    open(DialogReq(message, ok, danger, None, cancel = true, _ => f, () => ()))

  /** 文字の入力（OK を押したら入力した値で f）. */
  def prompt(message: String,
             default: String = "",
             ok: String = "OK",
             danger: Boolean = false,
             placeholder: String = "")(f: String => Unit): Unit =
    open(DialogReq(message, ok, danger, Some(RV(default)), cancel = true, f, () => (), placeholder))

  /** 確認のための文字（ユーザー名など）を入力させてから実行する. */
  def typeToConfirm(message: String, expected: String, ok: String)(f: => Unit): Unit =
    prompt(s"$message\n確認のため「$expected」と入力してください。", "", ok, danger = true, placeholder = expected) { v =>
      if (v.trim == expected) f else Store.toast("入力が一致しないため中止しました", error = true)
    }

  def alert(message: String): Unit =
    open(DialogReq(message, "OK", danger = false, None, cancel = false, _ => (), () => ()))

  def close(ok: Boolean): Unit = current.v.foreach { r =>
    current := None
    if (ok) r.onOk(r.input.map(_.v).getOrElse("")) else r.onCancel()
  }

}

/** この端末だけの表示の設定（localStorage. 使えないときは既定値）. */
object Prefs extends sbirds.web.LocalPrefs("sruru")

/** 画面の色（自動 = OS の設定、ライト、ダーク）. この端末に記憶する. */
object Theme extends sbirds.web.ThemeSwitch(Prefs, sbirds.web.ThemeSwitch.Plain)

/** オートコンプリート（parts/Combo.st）の選択肢. user はアイコン. */
final case class Opt(value: String, label: String, user: Option[UserBrief] = None, hint: String = "")

object Opt {
  def of(xs: List[(String, String)]): List[Opt] = xs.map((v, l) => Opt(v, l))

  /** 値と表示が同じ選択肢. */
  def names(xs: List[String]): List[Opt] = xs.map(x => Opt(x, x))
  def users(us: List[UserDto]): List[Opt] = us.map(u => Opt(u.id.toString, u.name, Some(Users.brief(u)), u.username))
}

object Users {

  def brief(u: UserDto): UserBrief = UserBrief(u.id, u.username, u.name, u.avatarUrl)

  def brief(a: AccountDto): UserBrief = UserBrief(a.userId, a.username, a.name, a.avatarUrl)

  def brief(m: MeDto): UserBrief = UserBrief(m.id, m.username, m.name, m.avatarUrl)

  /** 状態のバッジ（表示名, クラス）. */
  def badges(u: UserDto): List[(String, String)] =
    (if (u.disabled) List("無効" -> "badge danger") else Nil) ++
      (if (u.locked) List("ロック中" -> "badge warn") else Nil) ++
      (if (u.effectiveAdmin || u.isAdmin) List("管理者" -> "badge accent") else Nil) ++
      (if (u.isService) List("サービス" -> "badge") else Nil) ++
      (if (u.source != "local") List(u.source -> "badge") else Nil)

}
