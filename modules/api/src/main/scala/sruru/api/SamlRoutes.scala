package sruru.api

import cats.effect.*
import cats.syntax.all.*
import io.circe.Json
import io.circe.syntax.*
import org.http4s.*
import org.http4s.headers.`Content-Type`
import sruru.core.*
import sruru.db.*
import sruru.saml.*
import sruru.security.*

/** SAML の属性（対応の式から作る. 対応がなければ既定の属性）. */
object SamlMapping:
  val defaults: List[AttrMapping] = List(
    ("email", "{{user.email}}", false), ("name", "{{user.name}}", false), ("username", "{{user.username}}", false),
    ("givenName", "{{user.given_name}}", false), ("surname", "{{user.family_name}}", false), ("groups", "{{user.groups}}", true)
  ).map((n, e, m) => AttrMapping(java.util.UUID(0, 0), java.util.UUID(0, 0), n, e, None, None, m, 0))

  def attributes(ms: List[AttrMapping], ctx: Json): List[SamlAttribute] =
    (if ms.isEmpty then defaults else ms).flatMap { m =>
      val v = Expr.eval(m.expression, ctx)
      val values = v.asArray.map(_.toList.map(Expr.render)).getOrElse(if v.isNull then Nil else List(Expr.render(v))).filter(_.nonEmpty)
      Option.when(values.nonEmpty)(SamlAttribute(m.name, m.friendlyName, if m.multi then values else values.take(1)))
    }

/** SAML 2.0 の IdP（HTTP-Redirect・HTTP-POST の SSO、IdP 起点の SSO、SP からのログアウト）. */
final class SamlRoutes(apps: AppStore, tokens: TokenStore, sessions: SessionStore, dir: Directory, keys: KeyService, gate: AuthGate,
    val auth: SessionAuth, audit: AuditService, cfg: ApiConfig) extends RouteSupport:

  val entityId: String = s"${cfg.publicUrl}/saml/metadata"
  private val ssoUrl   = s"${cfg.publicUrl}/saml/sso"
  private val sloUrl   = s"${cfg.publicUrl}/saml/slo"

  private def html(body: String, nonce: String): IO[Response[IO]] =
    Ok(body).map(_.withContentType(`Content-Type`(MediaType.text.html, Charset.`UTF-8`))
      .putHeaders("Content-Security-Policy" -> s"default-src 'none'; script-src 'nonce-$nonce'; form-action *", "Cache-Control" -> "no-store"))

  private def spCert(s: SamlConfig) = s.spCertificate.flatMap(p => Jose.parseCerts(p).toOption.flatMap(_.headOption))

  /** 要求の発行時刻が ±300 秒に収まるか. */
  private def fresh(t: java.time.Instant): Boolean = java.time.Duration.between(t, java.time.Instant.now()).abs.getSeconds <= 300

  /** SP ごとの SessionIndex（ログインの ID をそのまま出さない. ほかの SP の SessionIndex を推測できないように）. */
  private def sessionIndex(appId: java.util.UUID, loginId: java.util.UUID): String =
    "_" + Crypto.hex(Crypto.sha256(s"sruru-saml-session:$appId:$loginId")).take(40)

  private def nameIdOf(app: Application, s: SamlConfig, u: User, m: Membership): IO[String] =
    dir.picture(u).map(pic => Expr.render(Expr.eval(s.nameIdExpr, Context.of(Context.user(u, m, pic), Some(app)))))

  /**
   * SameSite=Lax の Cookie はほかのサイトからの POST には付かない. Cookie がなければ、同じサイトから POST し直す
   * （ログアウトが空振りしたり、ログインの画面が毎回出たりしないように）.
   */
  private def withCookie(req: Request[IO], f: UrlForm)(run: => IO[Response[IO]]): IO[Response[IO]] =
    if req.cookies.exists(_.name == cfg.cookieName) || f.getFirst("_sruru").isDefined then run
    else
      val nonce  = Crypto.randomToken(12)
      val fields = f.values.toList.flatMap((k, vs) => vs.toList.map(k -> _)).filter(_._1 != "_sruru") :+ ("_sruru" -> "1")
      html(Saml.autoPost(req.uri.path.renderString, fields, nonce), nonce)

  // ------------------------------------------------------------------ SSO

  private def sso(req: Request[IO], xml: Either[String, String], relay: Option[String], redirectQuery: Option[String]): IO[Response[IO]] =
    xml.flatMap(Saml.parseAuthnRequest) match
      case Left(e) => gate.errorPage(s"SAML の要求を読めません: $e")
      case Right(ar) =>
        apps.byEntityId(ar.issuer).flatMap {
          case None => gate.errorPage(s"SAML のサービス（${ar.issuer}）が登録されていません")
          case Some((app, s)) =>
            val sigOk: Either[String, Unit] =
              if !s.wantSignedRequests then Right(())
              else spCert(s).toRight("SP の証明書が登録されていません").flatMap(c => redirectQuery match
                case Some(q) => Saml.verifyRedirectSignature(q, c)
                case None    => xml.flatMap(x => Saml.verifyPostSignature(x, c)))
            if sigOk.isLeft then gate.errorPage(s"SAML の要求の署名を確かめられません: ${sigOk.left.toOption.get}")
            else if ar.acsUrl.exists(_ != s.acsUrl) then gate.errorPage("ACS の URL が登録されたものと違います")
            else if ar.destination.exists(_ != ssoUrl) then gate.errorPage("SAML の要求の宛先（Destination）がこの IdP ではありません")
            else if !fresh(ar.issueInstant) then
              gate.errorPage("SAML の要求の発行時刻が古すぎるか、未来です（時計のずれを確かめてください）")
            else
              val params = Json.obj("requestId" -> ar.id.asJson, "relayState" -> relay.asJson, "forceAuthn" -> ar.forceAuthn.asJson,
                "isPassive" -> ar.isPassive.asJson)
              Time.now.flatMap(now => tokens.createRequest(app.id, "saml", params, AuthRequests.expires(now))).flatMap(resume(req, _))
        }

  /** IdP 起点の SSO（ポータルからの起動）. */
  private def idpInitiated(req: Request[IO], slug: String): IO[Response[IO]] =
    apps.bySlug(slug).flatMap {
      case Some(app) if app.protocol == "saml" =>
        // RelayState は仕様の上限（80 バイト）まで
        val params = Json.obj("relayState" -> req.params.get("RelayState").filter(_.getBytes("UTF-8").length <= 80).asJson)
        Time.now.flatMap(now => tokens.createRequest(app.id, "saml", params, AuthRequests.expires(now))).flatMap(resume(req, _))
      case _ => gate.errorPage("SAML のアプリケーションが見つかりません")
    }

  /** ログインの後に、署名したアサーションを SP へ POST する. */
  def resume(req: Request[IO], r: AuthRequest): IO[Response[IO]] =
    val pc = r.params.hcursor
    (apps.find(r.appId), apps.saml(r.appId)).tupled.flatMap {
      case (Some(app), Some(s)) =>
        val inResp  = pc.get[String]("requestId").toOption
        val relay   = pc.get[String]("relayState").toOption
        val passive = pc.get[Boolean]("isPassive").getOrElse(false)
        val force   = pc.get[Boolean]("forceAuthn").getOrElse(false)
        def errorToSp(status: String, sub: Option[String], msg: String): IO[Response[IO]] =
          (keys.saml, Time.now).flatMapN { (k, now) =>
            val xml   = Saml.buildErrorResponse(entityId, s.acsUrl, inResp, status, sub, Some(msg), now, k.privateKey, k.cert.get)
            val nonce = Crypto.randomToken(12)
            sruru.observe.Metrics.count("sruru.saml.assertions", "result" -> "error") *>
              tokens.deleteRequest(r.id) *> html(Saml.postForm(s.acsUrl, "SAMLResponse", xml, relay, nonce), nonce)
          }
        gate.check(req, r, app, GateOpts(force, passive, None, false)).flatMap {
          case Gate.Interact(_, _) if passive => errorToSp(Saml.StatusResponder, Some("urn:oasis:names:tc:SAML:2.0:status:NoPassive"), "ログインが必要です")
          case Gate.Interact(path, _) => gate.redirect(path)
          case Gate.Deny(_, msg) => tokens.deleteRequest(r.id) *> gate.errorPage(msg)
          // スパン・メトリクスには SAML の応答（アサーション）・NameID を載せない
          case Gate.Proceed(_, login, u, m) => sruru.observe.Telemetry.span("saml.assertion", "app" -> app.slug)(
            for
              pic  <- dir.picture(u)
              ms   <- apps.mappings(app.id)
              k    <- keys.saml
              now  <- Time.now
              ctx   = Context.of(Context.user(u, m, pic), Some(app))
              nid  <- nameIdOf(app, s, u, m)
              c    <- auth.reqCtx(req)
              res  <-
                if nid.isEmpty then tokens.deleteRequest(r.id) *> gate.errorPage("NameID の値がありません（メールアドレスなどが未登録です）。管理者に連絡してください")
                else
                  val classRef = if login.amr.contains(Amr.Swk) then "urn:oasis:names:tc:SAML:2.0:ac:classes:X509"
                    else if Amr.isMulti(login.amr) then "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract"
                    else Saml.PasswordProtectedTransport
                  val xml = Saml.buildResponse(AssertionParams(entityId, s.entityId, s.acsUrl, inResp, nid, s.nameIdFormat, sessionIndex(app.id, login.id),
                    login.authTime, classRef, SamlMapping.attributes(ms, ctx), now.minusSeconds(60), 360, Some(now.plusSeconds(s.sessionTtl.toLong)),
                    s.signResponse, s.signAssertion), k.privateKey, k.cert.get)
                  val nonce = Crypto.randomToken(12)
                  tokens.deleteRequest(r.id) *>
                    audit.log(c, Some(u), "saml", "app.authorize", audit.appTarget(app), detail = Json.obj("nameId" -> nid.asJson)) *>
                    sruru.observe.Metrics.count("sruru.saml.assertions", "result" -> "issued") *>
                    html(Saml.postForm(s.acsUrl, "SAMLResponse", xml, relay, nonce), nonce)
            yield res)
        }
      case _ => gate.errorPage("アプリケーションが見つかりません")
    }

  // ------------------------------------------------------------------ ログアウト

  private def slo(req: Request[IO], xml: Either[String, String], relay: Option[String], redirectQuery: Option[String]): IO[Response[IO]] =
    xml.flatMap(Saml.parseLogoutRequest) match
      case Left(e) => gate.errorPage(s"SAML のログアウトの要求を読めません: $e")
      case Right(lr) =>
        apps.byEntityId(lr.issuer).flatMap {
          case None => gate.errorPage("SAML のサービスが登録されていません")
          case Some((app, s)) =>
            val sigOk = if !s.wantSignedRequests then Right(()) else spCert(s).toRight("SP の証明書がありません").flatMap(c => redirectQuery match
              case Some(q) => Saml.verifyRedirectSignature(q, c)
              case None    => xml.flatMap(x => Saml.verifyPostSignature(x, c)))
            if sigOk.isLeft then gate.errorPage("ログアウトの要求の署名を確かめられません")
            else if lr.destination.exists(_ != sloUrl) then gate.errorPage("ログアウトの要求の宛先（Destination）がこの IdP ではありません")
            else if !fresh(lr.issueInstant) then gate.errorPage("ログアウトの要求の発行時刻が古すぎるか、未来です")
            else
              for
                c   <- auth.reqCtx(req)
                act <- auth.activeFor(req)
                // SessionIndex（この SP に出したもの）が合うときにログアウトする. 署名を確かめた要求に限り、SessionIndex がなければ
                // NameID が使用中のアカウントのものと同じときだけ（他人の署名付きの要求を使い回すログアウトの CSRF を防ぐ）
                done <- act.flatTraverse { (bs, l, u) =>
                          val byIndex = lr.sessionIndexes.contains(sessionIndex(app.id, l.id))
                          val byName: IO[Boolean] =
                            if byIndex || lr.sessionIndexes.nonEmpty || !s.wantSignedRequests then IO.pure(false)
                            else dir.membership(u).flatMap(m => nameIdOf(app, s, u, m)).map(n => lr.nameId.contains(n) && n.nonEmpty)
                          byName.flatMap(ok => IO.whenA(byIndex || ok)(
                            sessions.removeLogin(bs.id, u.id) *> dir.endLogin(u.id, l.id) *>
                              audit.log(c, Some(u), "saml", "logout", audit.userTarget(u), detail = Json.obj("sp" -> s.entityId.asJson))
                          ).as(Option.when(byIndex || ok)(())))
                        }
                res <- s.sloUrl match
                         case Some(dest) =>
                           (keys.saml, Time.now).flatMapN { (k, now) =>
                             // 実際にログアウトしたときだけ Success（ログアウトしたと SP に誤って伝えない）
                             val st    = if done.isDefined then Saml.StatusSuccess else Saml.StatusResponder
                             val out   = Saml.buildLogoutResponse(entityId, dest, lr.id, st, now, k.privateKey, k.cert.get)
                             val nonce = Crypto.randomToken(12)
                             html(Saml.postForm(dest, "SAMLResponse", out, relay, nonce), nonce)
                           }
                         case None => gate.redirect("/logged-out")
              yield res
        }

  // ------------------------------------------------------------------ ルート

  private def rawQuery(req: Request[IO]): String = req.uri.query.renderString

  val routes: HttpRoutes[IO] = HttpRoutes.of[IO] {
    case GET -> Root / "saml" / "metadata" =>
      keys.saml.flatMap(k => Ok(Saml.idpMetadata(entityId, ssoUrl, sloUrl, k.cert.get))
        .map(_.withContentType(`Content-Type`(MediaType.application.xml)).putHeaders("Access-Control-Allow-Origin" -> "*")))

    // HTTP-Redirect: 値は署名を確かめるのと同じ解析で取り出す（キーの符号化や重複で、検証した値と使う値がずれないように）
    case req @ GET -> Root / "saml" / "sso" =>
      Saml.redirectParams(rawQuery(req)) match
        case Left(e) => gate.errorPage(s"SAML の要求を読めません: $e")
        case Right(ps) =>
          ps.get("SAMLRequest").fold(gate.errorPage("SAMLRequest がありません"))(p =>
            sso(req, Saml.decodeRedirect(p), ps.get("RelayState"), Some(rawQuery(req))))

    case req @ POST -> Root / "saml" / "sso" =>
      req.as[UrlForm].flatMap(f => withCookie(req, f)(f.getFirst("SAMLRequest").fold(gate.errorPage("SAMLRequest がありません"))(p =>
        sso(req, Saml.decodePost(p), f.getFirst("RelayState"), None))))

    case req @ GET -> Root / "saml" / "idp" / slug => idpInitiated(req, slug)

    case req @ GET -> Root / "saml" / "slo" =>
      Saml.redirectParams(rawQuery(req)) match
        case Left(e) => gate.errorPage(s"SAML のログアウトの要求を読めません: $e")
        case Right(ps) =>
          ps.get("SAMLRequest").fold(gate.redirect("/logged-out"))(p =>
            slo(req, Saml.decodeRedirect(p), ps.get("RelayState"), Some(rawQuery(req))))

    case req @ POST -> Root / "saml" / "slo" =>
      req.as[UrlForm].flatMap(f => withCookie(req, f)(f.getFirst("SAMLRequest").fold(gate.redirect("/logged-out"))(p =>
        slo(req, Saml.decodePost(p), f.getFirst("RelayState"), None))))
  }
