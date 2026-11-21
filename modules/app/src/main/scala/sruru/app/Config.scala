package sruru.app

import sbirds.http.Env.*
import sbirds.db.*
import cats.effect.*
import sruru.api.*
import sbirds.mail.SmtpConfig

/** 設定は環境変数から読む. */
object Config {

  def load: IO[AppConfig] = IO.fromEither(
    (for {
      dbUrl <- required("DATABASE_URL")
      dbUser <- required("DATABASE_USER")
      dbPass <- required("DATABASE_PASSWORD")
      pub <- required("PUBLIC_URL")
      dev = enabled("DEV_MODE")
      // 例示の値（change-me）のまま本番で動かさない
      _ <- Either.cond(
        dev || !List(dbPass, opt("APP_SECRET").getOrElse("")).exists(_.toLowerCase.contains("change-me")),
        (),
        "APP_SECRET・DATABASE_PASSWORD が例示の値（change-me）のままです。秘密の値に変えてください"
      )
      secret <- opt("APP_SECRET") match {
        case Some(s) if s.length >= 16 => Right(s)
        case Some(_) => Left("APP_SECRET は16文字以上にしてください")
        case None if dev => Right("sruru-development-secret")
        case None => Left("APP_SECRET（16文字以上の秘密の値. 全ノードで同じ値）を設定してください")
      }
      tls <- (opt("TLS_KEYSTORE"), opt("TLS_KEYSTORE_PASSWORD")) match {
        case (Some(k), Some(p)) => Right(Some(TlsConfig(k, p, int("HTTPS_PORT").getOrElse(8443))))
        case (None, _) => Right(None)
        case _ => Left("TLS_KEYSTORE_PASSWORD を設定してください")
      }
      oauth <- opt("OAUTH_CLIENTS").fold(Right(Nil))(OAuthClient.parse)
    } yield {
      val base = pub.stripSuffix("/")
      val smtp = opt("SMTP_HOST").map { h =>
        val t = opt("SMTP_TLS").getOrElse("starttls").toLowerCase
        SmtpConfig(
          h,
          int("SMTP_PORT").getOrElse(if t == "ssl" then 465 else if t == "none" then 25 else 587),
          opt("SMTP_USER"),
          opt("SMTP_PASSWORD"),
          t,
          opt("MAIL_FROM").getOrElse(s"sruru@$h")
        )
      }
      AppConfig(
        port = int("HTTP_PORT").getOrElse(8080),
        db = DbConfig(dbUrl, dbUser, dbPass, int("DATABASE_POOL_SIZE").getOrElse(10)),
        api = ApiConfig(
          publicUrl = base,
          cookieSecure = base.startsWith("https://"),
          devMode = dev,
          mailEnabled = smtp.isDefined,
          oauthClients = oauth,
          magicLinkMinutes = int("MAGIC_LINK_MINUTES").map(m => math.max(1, math.min(m, 1440))).getOrElse(15),
          nodeId = opt("NODE_ID").getOrElse(java.net.InetAddress.getLocalHost.getHostName + "-" +
            java.util.UUID.randomUUID().toString.take(8))
        ),
        staticDir = opt("STATIC_DIR"),
        smtp = smtp,
        appSecret = secret,
        tls = tls
      )
    }).left.map(new IllegalArgumentException(_))
  )
}
