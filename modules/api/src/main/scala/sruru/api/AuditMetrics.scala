package sruru.api

import cats.effect.*
import io.circe.{Decoder, Json}
import sruru.core.*

/**
 * 監査ログの出来事から数える業務のメトリクス（skorimako）. 属性は種類の決まった値だけ（ユーザー名・理由の文などは載せない）.
 *  - sruru.logins: ログイン（result = success・failure・locked. mfa = 2つ目の要素を使ったか）
 *  - sruru.logins.mfa: 2つ目の要素（method = totp・email・recovery. result）
 *  - sruru.logins.federation・sruru.logins.cert: 外部の IdP・クライアント証明書でのログイン（result）
 *  - sruru.password.changes・sruru.password.resets: パスワードの変更（by = self・admin）・再設定（step = request・reset）
 *  - sruru.audit.events: 監査ログのすべての出来事（action・result）
 */
object AuditMetrics {
  import sbirds.observe.Metrics

  private val MfaMethods = Set("totp", "email", "recovery")

  /** 2つ目の要素の種類（メトリクス・スパンの属性. 送られてきた値なので決まったもの以外は other）. */
  def mfaMethod(m: String): String = if MfaMethods(m) then m else "other"

  private def res(ok: Boolean) = if ok then "success" else "failure"

  def record(action: String, via: String, success: Boolean, detail: Json): IO[Unit] = {
    val specific: IO[Unit] = action match {
      case "login.success" =>
        val amr = detail.hcursor.get[List[String]]("amr").getOrElse(Nil)
        Metrics.count("sruru.logins", "result" -> "success", "mfa" -> amr.contains(Amr.Mfa).toString)
      case "login.failure" => Metrics.count("sruru.logins", "result" -> "failure")
      case "user.locked" => Metrics.count("sruru.logins", "result" -> "locked")
      case "login.mfa" =>
        Metrics.count(
          "sruru.logins.mfa",
          "method" -> mfaMethod(detail.hcursor.get[String]("method").getOrElse("")),
          "result" -> res(success)
        )
      case "login.federation" => Metrics.count("sruru.logins.federation", "result" -> res(success))
      case "login.cert" => Metrics.count("sruru.logins.cert", "result" -> res(success))
      case "user.password.change" | "user.password.set" =>
        Metrics.count(
          "sruru.password.changes",
          "by" -> (if action == "user.password.set" then "admin" else "self"),
          "result" -> res(success)
        )
      case "user.password.reset_request" =>
        Metrics.count("sruru.password.resets", "step" -> "request", "result" -> res(success))
      case "user.password.reset" => Metrics.count("sruru.password.resets", "step" -> "reset", "result" -> res(success))
      case _ => IO.unit
    }
    specific *> Metrics.count("sruru.audit.events", "action" -> action, "via" -> via, "result" -> res(success))
  }

  /** 本人にプッシュで知らせる出来事（題名・本文）. */
  def alert(action: String): Option[(String, String)] = action match {
    case "user.password.change" => Some(("パスワードが変更されました", "心当たりがなければ、すぐに管理者に連絡してください"))
    case "user.password.set" => Some(("管理者がパスワードを設定しました", "次のログインから新しいパスワードを使ってください"))
    case "user.password.reset" => Some(("パスワードを再設定しました", "心当たりがなければ、すぐに管理者に連絡してください"))
    case "user.locked" => Some(("アカウントがロックされました", "ログインの失敗が続いたため、しばらくログインできません"))
    case "mfa.totp.remove" | "mfa.reset" => Some(("2段階認証が解除されました", "心当たりがなければ、すぐに管理者に連絡してください"))
    case _ => None
  }
}
