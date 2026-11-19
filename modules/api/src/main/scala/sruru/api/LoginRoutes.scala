package sruru.api

import sbirds.shared.AppError

import cats.effect.*
import cats.syntax.all.*
import io.circe.Json
import io.circe.syntax.*
import org.http4s.*
import org.http4s.circe.CirceEntityCodec.*
import org.http4s.headers.{`Content-Type`, Location}
import org.typelevel.ci.CIString
import sruru.core.*
import sruru.db.*
import sruru.security.*
import sruru.shared.*

import java.util.UUID

/**
 * ログインしていなくても使うルート: 画面の設定・最初の管理者・ログインの流れ・アカウントの切り替え・同意・
 * クライアント証明書と外部の IdP でのログイン・アイコンの画像.
 */
final class LoginRoutes(login: LoginService,
                        fed: FederationService,
                        fedStore: FederationStore,
                        val auth: SessionAuth,
                        sessions: SessionStore,
                        tokens: TokenStore,
                        apps: AppStore,
                        dir: Directory,
                        factors: FactorStore,
                        settings: SettingsStore,
                        policies: PolicyService,
                        audit: AuditService,
                        box: SecretBox,
                        cfg: ApiConfig) extends RouteSupport {

  val routes: HttpRoutes[IO] = HttpRoutes.of[IO] {
    case req @ GET -> Root / "api" / "client-config" => getClientConfig(req)
    case req @ POST -> Root / "api" / "setup" => postSetup(req)
    case req @ POST -> Root / "api" / "login" / "start" => postLoginStart(req)
    case req @ GET -> Root / "api" / "login" / "flow" / UuidVar(id) => getLoginFlow(req, id)
    case req @ POST -> Root / "api" / "login" / "password" => postLoginPassword(req)
    case req @ POST -> Root / "api" / "login" / "mfa" => postLoginMfa(req)
    case req @ POST -> Root / "api" / "login" / "mfa" / "email" => postLoginMfaEmail(req)
    case req @ POST -> Root / "api" / "login" / "enroll" / "totp" => postLoginEnrollTotp(req)
    case req @ POST -> Root / "api" / "login" / "enroll" / "totp" / "verify" => postLoginEnrollTotpVerify(req)
    case req @ POST -> Root / "api" / "login" / "continue" => postLoginContinue(req)
    case req @ POST -> Root / "api" / "login" / "change-password" => postLoginChangePassword(req)
    case req @ POST -> Root / "api" / "login" / "register" => postLoginRegister(req)
    case req @ POST -> Root / "api" / "login" / "forgot" => postLoginForgot(req)
    case req @ POST -> Root / "api" / "login" / "reset" => postLoginReset(req)
    case req @ GET -> Root / "auth" / "cert" => getAuthCert(req)
    case req @ GET -> Root / "auth" / "fed" / slug / "start" => getAuthFedStart(req, slug)
    case req @ GET -> Root / "auth" / "fed" / slug / "callback" => getAuthFedCallback(req, slug)
    case GET -> Root / "api" / "auth-requests" / UuidVar(id) => getAuthRequest(id)
    case req @ POST -> Root / "api" / "auth-requests" / UuidVar(id) / "select" => postAuthRequestSelect(req, id)
    case req @ POST -> Root / "api" / "consent" => postConsent(req)
    case req @ GET -> Root / "api" / "accounts" => getAccounts(req)
    case req @ POST -> Root / "api" / "accounts" / "switch" => postAccountsSwitch(req)
    case req @ POST -> Root / "api" / "accounts" / "logout" => postAccountsLogout(req)
    case GET -> Root / "avatars" / UuidVar(id) => getAvatar(id)
    case GET -> Root / "brand-logos" / UuidVar(id) => getBrandLogo(id)
    case GET -> Root / "app-icons" / UuidVar(id) => getAppIcon(id)
    case GET -> Root / "api" / "endpoints" => getEndpoints()
  }

  private def getClientConfig(req: Request[IO]): IO[Response[IO]] = {
    // ログインしていれば、使用中のアカウントのグループの上書き（サービス名・ロゴ・案内）を反映する
    (policies.get, auth.activeFor(req), fedStore.all, dir.passwordRules, dir.users.adminCount).flatMapN {
      (global, active, fs, rules, admins) =>
        active.fold(IO.pure(global))(a => dir.policyFor(a._3)).flatMap { p =>
          Ok(ClientConfigDto(
            p.branding.title,
            cfg.version,
            Branding.logoUrl(p.branding.logo),
            p.branding.loginMessage,
            global.branding.selfRegistration,
            fs.filter(_.enabled).map(f => ProviderBriefDto(f.slug, f.name, f.kind)),
            global.cert.enabled,
            rules,
            admins == 0,
            cfg.mailEnabled
          ))
            .map(_.putHeaders("Cache-Control" -> "no-store"))
        }
    }
  }

  private def postSetup(req: Request[IO]): IO[Response[IO]] =
    csrf(req)(body[SetupReq](req)(setup(req, _)))

  private def postLoginStart(req: Request[IO]): IO[Response[IO]] =
    csrf(req)(body[LoginStartReq](req) { r =>
      withBrowser(req)(bs =>
        (ctx(req), auth.active(bs)).flatMapN((c, cur) => flowJson(bs)(login.start(c, bs, r, cur)))
      )
    })

  private def getLoginFlow(req: Request[IO], id: UUID): IO[Response[IO]] =
    withBrowser(req)(bs => flowJson(bs)(login.get(bs, id)))

  private def postLoginPassword(req: Request[IO]): IO[Response[IO]] =
    csrf(req)(body[PasswordLoginReq](req)(r =>
      withBrowser(req)(bs => ctx(req).flatMap(c => flowJson(bs)(login.password(c, bs, r))))
    ))

  private def postLoginMfa(req: Request[IO]): IO[Response[IO]] =
    csrf(req)(body[MfaReq](req)(r =>
      withBrowser(req)(bs => ctx(req).flatMap(c => flowJson(bs)(login.mfa(c, bs, r))))
    ))

  private def postLoginMfaEmail(req: Request[IO]): IO[Response[IO]] =
    csrf(req)(body[FlowReq](req)(r =>
      withBrowser(req)(bs => ctx(req).flatMap(c => flowJson(bs)(login.sendEmailCode(c, bs, r.flowId))))
    ))

  private def postLoginEnrollTotp(req: Request[IO]): IO[Response[IO]] =
    csrf(req)(body[FlowReq](req)(r => withBrowser(req)(bs => flowJson(bs)(login.enrollTotp(bs, r.flowId)))))

  private def postLoginEnrollTotpVerify(req: Request[IO]): IO[Response[IO]] =
    csrf(req)(body[FlowTotpVerifyReq](req)(r =>
      withBrowser(req)(bs => ctx(req).flatMap(c => flowJson(bs)(login.verifyEnroll(c, bs, r))))
    ))

  private def postLoginContinue(req: Request[IO]): IO[Response[IO]] =
    csrf(req)(body[FlowReq](req)(r =>
      withBrowser(req)(bs => ctx(req).flatMap(c => flowJson(bs)(login.continue(c, bs, r.flowId))))
    ))

  private def postLoginChangePassword(req: Request[IO]): IO[Response[IO]] =
    csrf(req)(body[FlowPasswordReq](req)(r =>
      withBrowser(req)(bs => ctx(req).flatMap(c => flowJson(bs)(login.changePassword(c, bs, r))))
    ))

  private def postLoginRegister(req: Request[IO]): IO[Response[IO]] =
    csrf(req)(body[RegisterReq](req)(r =>
      withBrowser(req)(bs => ctx(req).flatMap(c => flowJson(bs)(login.register(c, bs, r))))
    ))

  private def postLoginForgot(req: Request[IO]): IO[Response[IO]] =
    csrf(req)(body[ForgotReq](req)(r => ctx(req).flatMap(c => login.forgot(c, r)) *> NoContent()))

  private def postLoginReset(req: Request[IO]): IO[Response[IO]] =
    csrf(req)(body[ResetReq](req)(r => ctx(req).flatMap(c => noContent(login.reset(c, r)))))

  private def getAuthCert(req: Request[IO]): IO[Response[IO]] =
    q(req, "flow").flatMap(uuidParam).fold(redirectTo("/login"))(certLogin(req, _))

  private def getAuthFedStart(req: Request[IO], slug: String): IO[Response[IO]] =
    q(req, "flow").flatMap(uuidParam).fold(redirectTo("/login"))(fedStart(req, slug, _))

  private def getAuthFedCallback(req: Request[IO], slug: String): IO[Response[IO]] =
    fedCallback(req, slug)

  private def getAuthRequest(id: UUID): IO[Response[IO]] =
    login.requestDto(id).flatMap(_.fold(err(ErrorCode.LoginRequestExpired))(Ok(_)))

  private def postAuthRequestSelect(req: Request[IO], id: UUID): IO[Response[IO]] =
    csrf(req)(body[SwitchReq](req) { r =>
      auth.browser(req).flatMap {
        case None => err(ErrorCode.NotLoggedIn)
        case Some(bs) =>
          (
            Time.now.flatMap(now => sessions.logins(bs.id, now)),
            Time.now.flatMap(now => tokens.request(id, now))
          ).tupled.flatMap {
            case (ls, Some(ar)) if ls.exists(_.userId == r.userId) =>
              sessions.setActive(bs.id, Some(r.userId)) *> tokens.updateRequest(
                id,
                ar.params.deepMerge(Json.obj("selectedBy" -> AuthRequests.mark(bs.id, r.userId)))
              ) *>
                Ok(RedirectDto(s"/auth/resume?req=$id"))
            case (_, None) => err(ErrorCode.LoginRequestExpired)
            case _ => err(ErrorCode.AccountNotLoggedIn)
          }
      }
    })

  private def postConsent(req: Request[IO]): IO[Response[IO]] =
    csrf(req)(body[ConsentReq](req) { r =>
      auth.activeFor(req).flatMap {
        case None => err(ErrorCode.NotLoggedIn)
        case Some((bs, _, u)) =>
          Time.now.flatMap(now => tokens.request(r.requestId, now)).flatMap {
            case None => err(ErrorCode.LoginRequestExpired)
            case Some(ar) =>
              val scopes =
                ar.params.hcursor.get[String]("scope").toOption.toList.flatMap(_.split(' ').filter(_.nonEmpty))
              (ctx(req), apps.find(ar.appId)).flatMapN {
                (c, app) =>
                  val target = Some(("application", ar.appId.toString, app.map(_.slug).getOrElse("")))
                  (if r.approve then
                     apps.putConsent(u.id, ar.appId, scopes) *> audit.log(
                       c,
                       Some(u),
                       "web",
                       "consent.grant",
                       target,
                       detail = Json.obj("scopes" -> scopes.asJson)
                     )
                   else audit.log(c, Some(u), "web", "consent.deny", target)) *>
                    tokens.updateRequest(
                      ar.id,
                      ar.params.deepMerge(Json.obj((if r.approve then "consentedBy" else "deniedBy") ->
                        AuthRequests.mark(bs.id, u.id)))
                    ) *>
                    Ok(RedirectDto(s"/auth/resume?req=${ar.id}"))
              }
          }
      }
    })

  private def getAccounts(req: Request[IO]): IO[Response[IO]] =
    auth.browser(req).flatMap(_.fold(Ok(List.empty[AccountDto]))(bs => accounts(bs).flatMap(Ok(_))))

  private def postAccountsSwitch(req: Request[IO]): IO[Response[IO]] =
    csrf(req)(body[SwitchReq](req) { r =>
      auth.browser(req).flatMap {
        case None => err(ErrorCode.NotLoggedIn)
        case Some(bs) =>
          Time.now.flatMap(now => sessions.logins(bs.id, now)).flatMap { ls =>
            if ls.exists(_.userId == r.userId) then sessions.setActive(bs.id, Some(r.userId)) *> NoContent()
            else err(ErrorCode.AccountNotLoggedIn)
          }
      }
    })

  private def postAccountsLogout(req: Request[IO]): IO[Response[IO]] =
    csrf(req)(body[AccountLogoutReq](req) { r =>
      auth.browser(req).flatMap {
        case None => NoContent()
        case Some(bs) =>
          ctx(req).flatMap(c => logout(c, bs, r.userId)) *> auth.browser(req).flatMap {
            case Some(b) if b.activeUser.isDefined => NoContent()
            case _ => NoContent().map(_.addCookie(auth.clearCookie))
          }
      }
    })

  private def getAvatar(id: UUID): IO[Response[IO]] =
    dir.users.avatar(id).flatMap {
      case Some((bytes, ct)) => image(bytes, ct)
      case None =>
        dir.users.find(id).flatMap(_.filterNot(_.hasAvatar).flatTraverse(dir.picture)).flatMap {
          case Some(url) => IO.pure(Response[IO](Status.Found).putHeaders(
              Location(Uri.unsafeFromString(url)),
              "Cache-Control" -> "public, max-age=300"
            ))
          case None => NotFound()
        }
    }

  private def getBrandLogo(id: UUID): IO[Response[IO]] =
    settings.logo(id).flatMap {
      case Some((bytes, ct)) =>
        image(bytes, ct).map(_.putHeaders(
          "Cache-Control" -> "public, max-age=31536000, immutable",
          "Content-Security-Policy" -> "default-src 'none'; style-src 'unsafe-inline'; sandbox"
        ))
      case None => NotFound()
    }

  private def getAppIcon(id: UUID): IO[Response[IO]] =
    apps.icon(id).flatMap {
      case Some((bytes, ct)) => image(bytes, ct)
      case None => NotFound()
    }

  private def getEndpoints(): IO[Response[IO]] =
    Ok(ApiCatalog.all.map(e =>
      Json.obj("method" -> e.method.asJson, "path" -> e.path.asJson, "description" -> e.description.asJson)
    ))

  /** ブラウザのセッションを用意して f を呼び、新しく作ったなら Cookie を付ける. */
  private def withBrowser(req: Request[IO])(f: BrowserSession => IO[Response[IO]]): IO[Response[IO]] =
    auth.ensureBrowser(req).flatMap((b, cookie) =>
      f(b).map(r => cookie.filterNot(_ => r.cookies.exists(_.name == cfg.cookieName)).fold(r)(r.addCookie))
    )

  private def csrf(req: Request[IO])(f: => IO[Response[IO]]): IO[Response[IO]] =
    if req.headers.get(CIString("X-Sruru")).isEmpty then err(ErrorCode.CsrfHeaderMissing) else f

  /** ログインが完了したら Cookie の値を新しくする. */
  private def rotated(bs: BrowserSession, r: Either[AppError, FlowDto])(res: Response[IO]): IO[Response[IO]] =
    r match {
      case Right(d) if d.stage == "done" => auth.rotate(bs).map(res.addCookie)
      case _ => IO.pure(res)
    }

  private def flowJson(bs: BrowserSession)(r: Res[FlowDto]): IO[Response[IO]] =
    r.flatMap(x => okJson(IO.pure(x)).flatMap(rotated(bs, x)))

  private def redirectTo(path: String): IO[Response[IO]] =
    IO.pure(Response[IO](Status.SeeOther).putHeaders(
      Location(Uri.unsafeFromString(path)),
      "Cache-Control" -> "no-store"
    ))

  /** 外部での認証の結果から画面へ戻る（完了なら行き先へ、途中ならログインの画面へ）. */
  private def afterExternal(flowId: UUID, r: Either[AppError, FlowDto]): IO[Response[IO]] = r match {
    case Right(d) if d.stage == "done" => redirectTo(d.redirect.getOrElse("/"))
    case Right(_) => redirectTo(s"/login?flow=$flowId")
    case Left(f) => redirectTo(s"/login?flow=$flowId&error=" + java.net.URLEncoder.encode(f.message, "UTF-8"))
  }

  // ------------------------------------------------------------------ 最初の管理者

  /** 管理者がいなければ、最初の管理者を作るためのトークンを用意して返す（全ノードで同じ値）. */
  def setupToken: IO[Option[String]] =
    dir.users.adminCount.flatMap {
      case 0 =>
        settings.putIfAbsent("setup", Json.obj("enc" -> box.encrypt(Crypto.randomToken(18)).asJson)) *>
          settings.get("setup").map(_.flatMap(_.hcursor.get[String]("enc").toOption).flatMap(box.decrypt))
      case _ => settings.delete("setup").as(None)
    }

  private def setup(req: Request[IO], r: SetupReq): IO[Response[IO]] =
    ctx(req).flatMap { c =>
      setupToken.flatMap {
        case None => err(ErrorCode.AdminAlreadyExists)
        case Some(t) if !Crypto.constantTimeEquals(t, r.token.trim) =>
          audit.log(c, None, "web", "setup", success = false) *> err(ErrorCode.SetupTokenWrong)
        case Some(_) =>
          (dir.validUsername(r.username), dir.validEmail(Some(r.email))).tupled match {
            case Left(e) => err(ErrorCode.InvalidInput, e)
            case Right((name, email)) =>
              dir.checkPassword(None, r.password).flatMap {
                case Left(e) => err(ErrorCode.InvalidInput, e)
                case Right(_) =>
                  Directory.hash(r.password).flatMap(h =>
                    dir.users.create(NewUser(
                      name,
                      email,
                      r.name.trim.some.filter(_.nonEmpty).getOrElse(name),
                      passwordHash = Some(h),
                      isAdmin = true,
                      emailVerified = email.isDefined
                    ))
                  ).flatMap {
                    case Left(e) => fail(e)
                    case Right(u) => settings.delete("setup") *>
                        audit.log(c, Some(u), "web", "setup", audit.userTarget(u)) *> NoContent()
                  }
              }
          }
      }
    }

  // ------------------------------------------------------------------ クライアント証明書

  private def certLogin(req: Request[IO], flowId: UUID): IO[Response[IO]] =
    withBrowser(req) { bs =>
      (ctx(req), policies.get).flatMapN {
        (c, p) =>
          if !p.cert.enabled then afterExternal(flowId, Left(AppError(ErrorCode.CertLoginDisabled)))
          else
            auth.presentedChain(req).flatMap {
              case None => afterExternal(flowId, Left(AppError(ErrorCode.CertNotPresented)))
              case Some(chain) =>
                factors.authorities.flatMap { cas =>
                  val anchors = cas.filter(_.enabled).flatMap(a => Jose.parseCerts(a.pem).toOption.toList.flatten)
                  Time.now.flatMap { now =>
                    ClientCerts.validate(chain, anchors, now) match {
                      case Left(e) => login.externalFailed(c, None, "login.cert", e) *>
                          afterExternal(flowId, Left(AppError(ErrorCode.CertInvalid, e)))
                      case Right(leaf) =>
                        val info = ClientCerts.info(leaf)
                        val user: IO[Option[User]] = p.cert.mapping match {
                          case "email" => info.emails.headOption.fold(IO.pure(None))(e =>
                              dir.users.byEmail(e).map { case List(u) if u.emailVerified => Some(u); case _ => None }
                            )
                          case "upn" => info.upns.headOption.fold(IO.pure(None))(dir.users.byLoginName)
                          case "cn" => info.cn.fold(IO.pure(None))(dir.users.byUsername)
                          case _ => factors.certByFingerprint(info.fingerprint).flatMap(_.flatTraverse(uc =>
                              dir.users.find(uc.userId)
                            ))
                        }
                        user.flatMap {
                          case None =>
                            login.externalFailed(c, None, "login.cert", s"no user for ${info.subject}") *>
                              afterExternal(flowId, Left(AppError(ErrorCode.CertUserNotFound)))
                          case Some(u) =>
                            val amr = List(Amr.Swk) ++ (if p.cert.countsAsMfa then List(Amr.Mfa) else Nil)
                            login.externalAuthenticated(
                              c,
                              bs,
                              flowId,
                              u,
                              amr,
                              "login.cert",
                              Json.obj("subject" -> info.subject.asJson, "fingerprint" -> info.fingerprint.asJson)
                            ).flatMap(r => afterExternal(flowId, r).flatMap(rotated(bs, r)))
                        }
                    }
                  }
                }
            }
      }
    }

  // ------------------------------------------------------------------ 外部の IdP

  private def fedStart(req: Request[IO], slug: String, flowId: UUID): IO[Response[IO]] =
    withBrowser(req) { bs =>
      Time.now.flatMap(now => sessions.flow(flowId, bs.id, now)).flatMap {
        case None => redirectTo("/login")
        case Some(f) =>
          fedStore.bySlug(slug).flatMap {
            case Some(p) if p.enabled =>
              fed.start(p, flowId).attempt.flatMap {
                case Right((uri, data)) =>
                  sessions.saveFlow(f.copy(data = f.data.deepMerge(Json.obj("fed" -> data)))) *>
                    IO.pure(Response[IO](Status.SeeOther).putHeaders(Location(uri), "Cache-Control" -> "no-store"))
                case Left(e) => afterExternal(
                    flowId,
                    Left(AppError(ErrorCode.UpstreamIdpUnreachable, s"${p.name} に接続できません: ${e.getMessage}"))
                  )
              }
            case _ => afterExternal(flowId, Left(AppError(ErrorCode.UpstreamIdpNotFound)))
          }
      }
    }

  private def fedCallback(req: Request[IO], slug: String): IO[Response[IO]] = {
    val state = req.params.getOrElse("state", "")
    val flowId = uuidParam(state.takeWhile(_ != '.'))
    flowId.fold(redirectTo("/login")) { fid =>
      withBrowser(req) { bs =>
        ctx(req).flatMap { c =>
          Time.now.flatMap(now => sessions.flow(fid, bs.id, now)).flatMap {
            case None =>
              redirectTo("/error?message=" + java.net.URLEncoder.encode("ログインの有効期限が切れました。もう一度お試しください", "UTF-8"))
            case Some(f) =>
              val fc = f.data.hcursor.downField("fed")
              (
                fc.get[String]("slug").toOption,
                fc.get[String]("state").toOption,
                fc.get[String]("nonce").toOption,
                fc.get[String]("verifier").toOption
              ).tupled match {
                case Some((s, st, nonce, verifier)) if s == slug && Crypto.constantTimeEquals(st, state) =>
                  req.params.get("error") match {
                    case Some(e) =>
                      afterExternal(fid, Left(AppError(ErrorCode.UpstreamLoginFailed, s"外部の IdP でログインできませんでした（$e）")))
                    case None =>
                      fedStore.bySlug(slug).flatMap {
                        case Some(p) if p.enabled =>
                          // 同じ state を2回使えないように消す
                          sessions.saveFlow(f.copy(data = f.data.mapObject(_.remove("fed")))) *>
                            // 外部の IdP とのコードの交換（スパンには IdP の名前だけ. コード・トークンは載せない）
                            sbirds.observe.Telemetry.span(
                              "federation.exchange",
                              "provider" -> p.slug
                            )(fed.exchange(p, req.params.getOrElse("code", ""), verifier, nonce)).attempt.flatMap {
                              case Left(e) =>
                                login.externalFailed(c, None, "login.federation", s"${p.slug}: ${e.getMessage}") *>
                                  afterExternal(
                                    fid,
                                    Left(AppError(
                                      ErrorCode.UpstreamProviderLoginFailed,
                                      s"${p.name} でのログインに失敗しました: ${e.getMessage}"
                                    ))
                                  )
                              case Right(id) =>
                                fed.resolve(p, id).flatMap {
                                  case Left(msg) =>
                                    login.externalFailed(
                                      c,
                                      None,
                                      "login.federation",
                                      s"${p.slug}: $msg (${id.email.getOrElse(id.subject)})"
                                    ) *>
                                      afterExternal(fid, Left(AppError(ErrorCode.UpstreamAccountDenied, msg)))
                                  case Right(u) =>
                                    login.externalAuthenticated(
                                      c,
                                      bs,
                                      fid,
                                      u,
                                      fed.amr(p, id),
                                      "login.federation",
                                      Json.obj("provider" -> p.slug.asJson, "subject" -> id.subject.asJson)
                                    ).flatMap(r => afterExternal(fid, r).flatMap(rotated(bs, r)))
                                }
                            }
                        case _ => afterExternal(fid, Left(AppError(ErrorCode.UpstreamIdpNotFound)))
                      }
                  }
                case _ => afterExternal(fid, Left(AppError(ErrorCode.UpstreamStateMismatch)))
              }
          }
        }
      }
    }
  }

  // ------------------------------------------------------------------ アカウント

  private def accounts(bs: BrowserSession): IO[List[AccountDto]] =
    (Time.now.flatMap(now => sessions.logins(bs.id, now)), policies.get).flatMapN {
      (ls, p) =>
        dir.users.findMany(ls.map(_.userId)).map { us =>
          ls.flatMap(l =>
            us.find(u => u.id == l.userId && !u.disabled).map(u =>
              AccountDto(
                u.id,
                u.username,
                u.name,
                dir.pictureUrl(u, p.branding.gravatar),
                bs.activeUser.contains(u.id),
                l.authTime
              )
            )
          )
        }
    }

  private def logout(c: ReqCtx, bs: BrowserSession, userId: Option[UUID]): IO[Unit] = {
    val removed: IO[List[(UUID, UUID)]] = userId match {
      case Some(u) => sessions.removeLogin(bs.id, u).map(_.toList.map(_ -> u))
      case None => Time.now.flatMap(now => sessions.logins(bs.id, now)).flatMap(ls =>
          sessions.removeAll(bs.id).as(ls.map(l => l.id -> l.userId))
        )
    }
    removed.flatMap(_.traverse_ {
      (lid, uid) =>
        dir.endLogin(uid, lid) *>
          dir.users.find(uid).flatMap(u => audit.log(c, u, "web", "logout", u.flatMap(audit.userTarget)))
    })
  }

  // ------------------------------------------------------------------ ルート

  private def image(bytes: Array[Byte], ct: String): IO[Response[IO]] = {
    val mt = MediaType.parse(ct).toOption.filter(_.mainType == "image").getOrElse(MediaType.image.png)
    IO.pure(Response[IO](
      Status.Ok
    ).withEntity(bytes)(using EntityEncoder.byteArrayEncoder).withContentType(`Content-Type`(mt))
      .putHeaders(
        "Cache-Control" -> "public, max-age=300",
        "X-Content-Type-Options" -> "nosniff",
        "Content-Security-Policy" -> "default-src 'none'",
        "Cross-Origin-Resource-Policy" -> "cross-origin",
        "Access-Control-Allow-Origin" -> "*"
      ))
  }
}
