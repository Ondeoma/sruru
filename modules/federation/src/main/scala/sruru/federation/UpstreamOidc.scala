package sruru.federation

import cats.effect.{IO, Ref}
import cats.syntax.all.*
import io.circe.{ACursor, Json}
import org.http4s.*
import org.http4s.client.Client
import sruru.security.{Crypto, Jose}

import java.time.Instant

/** 外部の OIDC プロバイダの設定. subjectClaim は利用者を識別するクレーム（Entra は oid）. */
final case class UpstreamConfig(
  issuer: String,
  clientId: String,
  clientSecret: String,
  redirectUri: String,
  scopes: List[String],
  subjectClaim: String = "sub",
  extraAuthParams: Map[String, String] = Map.empty)

/** 外部の IdP で確認できた利用者. claims は ID トークン（と userinfo）のクレーム全体. */
final case class UpstreamIdentity(
  subject: String,
  email: Option[String],
  emailVerified: Boolean,
  name: Option[String],
  givenName: Option[String],
  familyName: Option[String],
  picture: Option[String],
  groups: List[String],
  amr: List[String],
  hostedDomain: Option[String],
  tenantId: Option[String],
  claims: Json)

/** discovery で得た外部の IdP の情報. issuer は Entra のマルチテナントでは {tenantid} を含む. */
final case class UpstreamMetadata(
  issuer: String,
  authorizationEndpoint: Uri,
  tokenEndpoint: Uri,
  jwksUri: Uri,
  userinfoEndpoint: Option[Uri])

/** 外部の OIDC プロバイダでのログイン（Authorization Code + PKCE + nonce. ID トークンは JWKS で署名を検証）. */
final class UpstreamOidc(
  http: Client[IO]) {
  private val metas = Ref.unsafe[IO, Map[String, UpstreamMetadata]](Map.empty)
  private val jwks = Ref.unsafe[IO, Map[String, List[Json]]](Map.empty)

  private def err(
    msg: String
  ) = new FederationError(msg)

  /** discovery（issuer ごとに覚えておく）. */
  def discover(
    cfg: UpstreamConfig
  ): IO[UpstreamMetadata] = {
    val key = cfg.issuer.stripSuffix("/")
    metas.get.map(_.get(key)).flatMap {
      case Some(m) => IO.pure(m)
      case None =>
        for {
          u <- HttpUtil.uri(key + "/.well-known/openid-configuration")
          j <- HttpUtil.json(http, Request[IO](Method.GET, u), "OIDC の設定（discovery）の取得")
          m <- IO.fromEither(UpstreamOidc.parseMetadata(cfg, j).leftMap(err))
          _ <- metas.update(_ + (key -> m))
        } yield m
    }
  }

  def authorizationUri(
    cfg: UpstreamConfig,
    state: String,
    nonce: String,
    verifier: String
  ): IO[Uri] =
    discover(cfg).map { m =>
      m.authorizationEndpoint.withQueryParams(
        Map(
          "response_type" -> "code",
          "client_id" -> cfg.clientId,
          "redirect_uri" -> cfg.redirectUri,
          "scope" -> cfg.scopes.mkString(" "),
          "state" -> state,
          "nonce" -> nonce,
          "code_challenge" -> Crypto.pkceS256(verifier),
          "code_challenge_method" -> "S256"
        ) ++ cfg.extraAuthParams
      )
    }

  private def keys(
    m: UpstreamMetadata,
    refresh: Boolean
  ): IO[List[Json]] = {
    val k = m.jwksUri.renderString
    jwks.get.map(_.get(k)).flatMap {
      case Some(ks) if !refresh => IO.pure(ks)
      case _ =>
        HttpUtil.json(http, Request[IO](Method.GET, m.jwksUri), "署名鍵（JWKS）の取得")
          .map(_.hcursor.get[List[Json]]("keys").getOrElse(Nil))
          .flatTap(ks => jwks.update(_ + (k -> ks)))
    }
  }

  /** 署名を検証する. 鍵が見つからなければ JWKS を取り直してもう一度（IdP の鍵の入れ替え）. */
  private def verifySignature(
    m: UpstreamMetadata,
    idToken: String
  ): IO[Json] = {
    val bad = err("ID トークンの署名を検証できません")
    keys(m, refresh = false).flatMap { ks =>
      Jose.verify(idToken, ks) match {
        case Right(c) => IO.pure(c)
        case Left(e) if e.startsWith("no matching key") =>
          keys(m, refresh = true).flatMap(ks2 => IO.fromEither(Jose.verify(idToken, ks2).leftMap(_ => bad)))
        case Left(_) => IO.raiseError(bad)
      }
    }
  }

  /** 認可コードをトークンに交換し、ID トークンを検証して利用者を返す. */
  def exchange(
    cfg: UpstreamConfig,
    code: String,
    verifier: String,
    nonce: String,
    now: Instant
  ): IO[UpstreamIdentity] =
    for {
      m <- discover(cfg)
      req = Request[IO](Method.POST, m.tokenEndpoint).withEntity(
        UrlForm(
          "grant_type" -> "authorization_code",
          "code" -> code,
          "redirect_uri" -> cfg.redirectUri,
          "client_id" -> cfg.clientId,
          "client_secret" -> cfg.clientSecret,
          "code_verifier" -> verifier
        )
      )
      tok <- HttpUtil.json(http, req, "トークンの取得")
      idToken <- IO.fromOption(tok.hcursor.get[String]("id_token").toOption)(err("トークンの応答に ID トークンがありません"))
      claims <- verifySignature(m, idToken)
      _ <- IO.fromEither(UpstreamOidc.validate(claims, m.issuer, cfg, nonce, now).leftMap(err))
      merged <- withUserinfo(m, cfg, claims, tok.hcursor.get[String]("access_token").toOption)
      id <- IO.fromEither(UpstreamOidc.identity(merged, cfg.subjectClaim).leftMap(err))
    } yield id

  /** メールアドレスか名前が ID トークンになければ userinfo で補う（ID トークンの値が優先）. userinfo の失敗は無視する. */
  private def withUserinfo(
    m: UpstreamMetadata,
    cfg: UpstreamConfig,
    claims: Json,
    accessToken: Option[String]
  ): IO[Json] = {
    val c = claims.hcursor
    val missing = c.get[String]("email").isLeft || c.get[String]("name").isLeft
    (m.userinfoEndpoint, accessToken) match {
      case (Some(u), Some(at)) if missing =>
        HttpUtil.json(http, HttpUtil.bearer(Request[IO](Method.GET, u), at), "userinfo の取得").attempt.flatMap {
          case Left(_) => IO.pure(claims)
          case Right(ui) =>
            val same = (ui.hcursor.get[String]("sub").toOption, c.get[String]("sub").toOption) match {
              case (Some(a), Some(b)) => a == b
              case _ => false
            }
            if same then IO.pure(ui.deepMerge(claims)) else IO.raiseError(err("userinfo の sub が ID トークンと一致しません"))
        }
      case _ => IO.pure(claims)
    }
  }
}

object UpstreamOidc {
  private val TenantTemplate = "{tenantid}"

  /** Entra のマルチテナント（common・organizations）. */
  def isMultiTenant(
    issuer: String
  ): Boolean = issuer.contains("/common/") || issuer.contains("/organizations/")

  /**
   * 取りに行ってよい URL（https. 開発用に issuer が http://localhost のときだけ http://localhost も）.
   * 上流の設定で返ってきた URL で、内部のアドレスへ要求を送らされたりシークレットを送らされたりしないように.
   */
  def safeEndpoint(
    issuer: String,
    u: Uri
  ): Boolean =
    u.scheme.contains(Uri.Scheme.https) && u.host.isDefined ||
      isLocalHttp(issuer) && u.scheme.contains(Uri.Scheme.http) && u.host.exists(h => LocalHosts(h.value.toLowerCase))

  private val LocalHosts = Set("localhost", "127.0.0.1", "[::1]", "::1")

  /** http://localhost（開発用）の issuer か. 前方一致ではなくホストで判定する（http://localhost@evil や localhost.evil を通さない）. */
  def isLocalHttp(
    issuer: String
  ): Boolean =
    Uri.fromString(issuer).toOption.exists(u =>
      u.scheme.contains(Uri.Scheme.http) && u.userInfo.isEmpty &&
        u.host.exists(h => LocalHosts(h.value.toLowerCase))
    )

  def parseMetadata(
    cfg: UpstreamConfig,
    j: Json
  ): Either[String, UpstreamMetadata] = {
    val c = j.hcursor
    def uri(
      name: String
    ) = c.get[String](name).toOption.flatMap(s => Uri.fromString(s).toOption).filter(safeEndpoint(cfg.issuer, _))
    for {
      iss <- c.get[String]("issuer").leftMap(_ => "OIDC の設定に issuer がありません")
      auth <- uri("authorization_endpoint").toRight("OIDC の設定に authorization_endpoint がありません")
      tok <- uri("token_endpoint").toRight("OIDC の設定に token_endpoint がありません")
      jw <- uri("jwks_uri").toRight("OIDC の設定に jwks_uri がありません")
      ok = iss.stripSuffix("/") == cfg.issuer.stripSuffix("/") ||
        (isMultiTenant(cfg.issuer) && iss.contains(TenantTemplate))
      _ <- Either.cond(ok, (), s"OIDC の設定の issuer が一致しません（$iss）")
    } yield UpstreamMetadata(iss, auth, tok, jw, uri("userinfo_endpoint"))
  }

  private def strings(
    c: ACursor
  ): List[String] =
    c.focus.toList.flatMap(j => j.asString.toList ++ j.asArray.toList.flatMap(_.flatMap(_.asString)))

  /** iss・aud（複数なら azp）・exp（60秒の猶予）・nonce を確かめる. */
  def validate(
    claims: Json,
    metaIssuer: String,
    cfg: UpstreamConfig,
    nonce: String,
    now: Instant
  ): Either[String, Unit] = {
    val c = claims.hcursor
    for {
      iss <- c.get[String]("iss").leftMap(_ => "ID トークンに iss がありません")
      expected <-
        if metaIssuer.contains(TenantTemplate) then
          c.get[String]("tid").leftMap(_ => "ID トークンに tid がありません").map(t => metaIssuer.replace(TenantTemplate, t))
        else Right(metaIssuer)
      // Google は "accounts.google.com" のこともある
      issOk = iss == expected || (expected == "https://accounts.google.com" && iss == "accounts.google.com")
      _ <- Either.cond(issOk, (), s"ID トークンの発行者（iss）が一致しません: $iss")
      aud = strings(c.downField("aud"))
      _ <- Either.cond(aud.contains(cfg.clientId), (), "ID トークンの対象（aud）が一致しません")
      azp = c.get[String]("azp").toOption
      _ <- Either.cond(azp.forall(_ == cfg.clientId) && (aud.size == 1 || azp.isDefined), (), "ID トークンの azp が一致しません")
      exp <- c.get[Long]("exp").leftMap(_ => "ID トークンに exp がありません")
      _ <- Either.cond(Instant.ofEpochSecond(exp).plusSeconds(60).isAfter(now), (), "ID トークンの有効期限が切れています")
      _ <- c.get[Long]("nbf").toOption match {
        case Some(nbf) =>
          Either.cond(!Instant.ofEpochSecond(nbf).minusSeconds(60).isAfter(now), (), "ID トークンはまだ有効ではありません")
        case None => Right(())
      }
      n <- c.get[String]("nonce").leftMap(_ => "ID トークンに nonce がありません")
      _ <- Either.cond(Crypto.constantTimeEquals(n, nonce), (), "ID トークンの nonce が一致しません")
    } yield ()
  }

  def identity(
    claims: Json,
    subjectClaim: String
  ): Either[String, UpstreamIdentity] = {
    val c = claims.hcursor
    def str(
      k: String
    ) = c.get[String](k).toOption.filter(_.nonEmpty)
    str(subjectClaim).toRight(s"ID トークンに $subjectClaim がありません").map { sub =>
      val verified =
        c.downField("email_verified").focus.exists(j => j.asBoolean.contains(true) || j.asString.contains("true"))
      UpstreamIdentity(
        sub,
        str("email"),
        verified,
        str("name"),
        str("given_name"),
        str("family_name"),
        str("picture"),
        strings(c.downField("groups")),
        strings(c.downField("amr")),
        str("hd"),
        str("tid"),
        claims
      )
    }
  }
}

/** よく使う IdP の既定値. */
final case class Preset(
  issuer: String,
  scopes: List[String],
  subjectClaim: String) {
  def config(
    clientId: String,
    clientSecret: String,
    redirectUri: String,
    extraAuthParams: Map[String, String] = Map.empty
  ): UpstreamConfig =
    UpstreamConfig(issuer, clientId, clientSecret, redirectUri, scopes, subjectClaim, extraAuthParams)
}

object Presets {
  def google: Preset = Preset("https://accounts.google.com", List("openid", "email", "profile"), "sub")

  /** tenant はテナント ID・ドメイン・common・organizations. */
  def entra(
    tenant: String
  ): Preset = Preset(s"https://login.microsoftonline.com/$tenant/v2.0", List("openid", "profile", "email"), "oid")

  /** Google の hd（Workspace のドメインに絞る. ヒントにすぎないので ID トークンの hd も必ず確かめる）. */
  def googleParams(
    hostedDomain: Option[String]
  ): Map[String, String] = hostedDomain.filter(_.nonEmpty).map("hd" -> _).toMap

  /** Entra のアカウントの選択画面を出す. */
  def entraParams(
    selectAccount: Boolean
  ): Map[String, String] = if selectAccount then Map("prompt" -> "select_account") else Map.empty
}
