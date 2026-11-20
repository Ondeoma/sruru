package sruru.api

import sbirds.shared.AppError

import cats.effect.*
import cats.syntax.all.*
import io.circe.Json
import io.circe.syntax.*
import org.http4s.*
import org.http4s.circe.CirceEntityCodec.*
import sruru.core.*
import sruru.db.*
import sruru.security.*
import sruru.shared.*

import java.util.UUID

/** 自分の情報・セキュリティの設定・API トークン. */
final class MeRoutes(dir: Directory,
                     factors: FactorStore,
                     sessions: SessionStore,
                     tokens: TokenStore,
                     apps: AppStore,
                     fedStore: FederationStore,
                     login: LoginService,
                     mail: MailService,
                     policies: PolicyService,
                     audit: AuditService,
                     box: SecretBox,
                     settings: SettingsStore,
                     val auth: SessionAuth,
                     cfg: ApiConfig)
  extends RouteSupport {

  val routes: HttpRoutes[IO] = HttpRoutes.of[IO] {
    case req @ GET -> Root / "api" / "me" => getMe(req)
    case req @ PUT -> Root / "api" / "me" => putMe(req)
    case req @ POST -> Root / "api" / "me" / "avatar" => postMeAvatar(req)
    case req @ DELETE -> Root / "api" / "me" / "avatar" => deleteMeAvatar(req)
    case req @ POST -> Root / "api" / "me" / "password" => postMePassword(req)
    case req @ POST -> Root / "api" / "me" / "totp" => postMeTotp(req)
    case req @ POST -> Root / "api" / "me" / "totp" / "verify" => postMeTotpVerify(req)
    case req @ DELETE -> Root / "api" / "me" / "totp" / UuidVar(id) => deleteMeTotp(req, id)
    case req @ POST -> Root / "api" / "me" / "recovery-codes" => postMeRecoveryCodes(req)
    case req @ GET -> Root / "api" / "me" / "apps" => getMeApps(req)
    case req @ PUT -> Root / "api" / "me" / "apps" / "order" => putMeAppsOrder(req)
    case req @ DELETE -> Root / "api" / "me" / "apps" / "order" => deleteMeAppsOrder(req)
    case req @ GET -> Root / "api" / "me" / "sessions" => getMeSessions(req)
    case req @ DELETE -> Root / "api" / "me" / "sessions" => deleteMeSessions(req)
    case req @ DELETE -> Root / "api" / "me" / "sessions" / UuidVar(id) => deleteMeSession(req, id)
    case req @ GET -> Root / "api" / "me" / "tokens" => getMeTokens(req)
    case req @ POST -> Root / "api" / "me" / "tokens" => postMeTokens(req)
    case req @ DELETE -> Root / "api" / "me" / "tokens" / UuidVar(id) => deleteMeToken(req, id)
    case req @ GET -> Root / "api" / "me" / "consents" => getMeConsents(req)
    case req @ DELETE -> Root / "api" / "me" / "consents" / UuidVar(appId) => deleteMeConsent(req, appId)
    case req @ GET -> Root / "api" / "me" / "certs" => getMeCerts(req)
    case req @ POST -> Root / "api" / "me" / "certs" => postMeCerts(req)
    case req @ DELETE -> Root / "api" / "me" / "certs" / UuidVar(id) => deleteMeCert(req, id)
    case req @ POST -> Root / "api" / "me" / "email" / "verify" => postMeEmailVerify(req)
    case req @ POST -> Root / "api" / "me" / "email" / "confirm" => postMeEmailConfirm(req)
    case req @ GET -> Root / "api" / "me" / "policy-groups" => getMePolicyGroups(req)
    case req @ PUT -> Root / "api" / "me" / "policy-groups" / UuidVar(id) => putMePolicyGroup(req, id)
    case req @ POST -> Root / "api" / "me" / "policy-groups" / UuidVar(id) / "logos" => postMePolicyGroupLogo(req, id)
  }

  // ------------------------------------------------------------------ ポリシーの編集を任されたグループ

  private def delegated(p: Principal): IO[List[Group]] =
    dir.groups.policyEditableBy(
      p.user.id,
      p.membership.ids
    ).flatMap(dir.groups.findMany).map(_.sortBy(_.name.toLowerCase))

  private def delegatedDto(g: Group): DelegatedGroupDto =
    DelegatedGroupDto(g.id, g.name, g.description, g.policy.getOrElse(GroupPolicy()))

  /** 自分がポリシーを編集できるグループ（管理者が付与したもの. 本人か、所属するグループに付与されている）. */
  private def getMePolicyGroups(req: Request[IO]): IO[Response[IO]] =
    webOnly(req)(p => delegated(p).flatMap(gs => Ok(gs.map(delegatedDto))))

  /** 任されたグループのロゴ（表示の上書き）にする画像を上げる. 使うには、返った ID をポリシーに入れて保存する. */
  private def postMePolicyGroupLogo(req: Request[IO], id: UUID): IO[Response[IO]] =
    webOnly(req)(p =>
      delegated(p).map(_.find(_.id == id)).flatMap {
        case None => err(ErrorCode.PolicyEditForbidden)
        case Some(g) =>
          Conv.readImage(req, Conv.MaxLogoBytes, allowSvg = true).flatMap {
            case Left(e) => err(ErrorCode.InvalidInput, e)
            case Right((bytes, ct)) =>
              settings.addLogo(bytes, ct).flatMap(lid =>
                audited(
                  audit,
                  req,
                  p,
                  "branding.logo.upload",
                  audit.groupTarget(g),
                  Json.obj("delegated" -> true.asJson, "logo" -> lid.toString.asJson)
                ) *> Ok(Json.obj("id" -> lid.toString.asJson, "url" -> Branding.logoUrl(Some(lid.toString)).asJson))
              )
          }
      }
    )

  /** 任されたグループのポリシーだけを変える（名前・メンバーなどは変えられない）. 監査ログに残す. */
  private def putMePolicyGroup(req: Request[IO], id: UUID): IO[Response[IO]] =
    webOnly(req)(p =>
      body[DelegatedPolicyReq](req)(r =>
        delegated(p).map(_.find(_.id == id)).flatMap {
          case None => err(ErrorCode.PolicyEditForbidden)
          case Some(g) =>
            GroupPolicyCheck.validate(r.policy) match {
              case Left(e) => err(ErrorCode.InvalidInput, e)
              case Right(pol) =>
                dir.groups.save(g.copy(policy = pol)).flatMap {
                  case Left(e) => fail(e)
                  case Right(saved) =>
                    audited(
                      audit,
                      req,
                      p,
                      "group.policy.update",
                      audit.groupTarget(saved),
                      Json.obj("delegated" -> true.asJson)
                    ) *> Ok(delegatedDto(saved))
                }
            }
        }
      )
    )

  private def getMe(req: Request[IO]): IO[Response[IO]] =
    authed(req)(p => me(p.user).map(outward(p, _)).flatMap(Ok(_)))

  private def putMe(req: Request[IO]): IO[Response[IO]] =
    authed(req)(p =>
      body[MeUpdateReq](req)(r => ctx(req).flatMap(c => okJson(updateMe(p, r, c).map(_.map(outward(p, _))))))
    )

  private def postMeAvatar(req: Request[IO]): IO[Response[IO]] =
    authed(req) { p =>
      Conv.readImage(req, cfg.maxAvatarBytes).flatMap {
        case Left(e) => err(ErrorCode.InvalidInput, e)
        case Right(img) => dir.users.setAvatar(p.id, Some(img)) *> audited(audit, req, p, "user.avatar.update") *>
            NoContent()
      }
    }

  private def deleteMeAvatar(req: Request[IO]): IO[Response[IO]] =
    authed(req)(p => dir.users.setAvatar(p.id, None) *> NoContent())

  private def postMePassword(req: Request[IO]): IO[Response[IO]] =
    webOnly(req)(p => body[PasswordChangeReq](req)(r => ctx(req).flatMap(c => noContent(changePassword(p, r, c)))))

  private def postMeTotp(req: Request[IO]): IO[Response[IO]] =
    recentAuth(req)(p => startTotp(p).flatMap(Ok(_)))

  private def postMeTotpVerify(req: Request[IO]): IO[Response[IO]] =
    recentAuth(req)(p => body[TotpVerifyReq](req)(r => ctx(req).flatMap(c => okJson(verifyTotp(p, r, c)))))

  private def deleteMeTotp(req: Request[IO], id: UUID): IO[Response[IO]] =
    recentAuth(req) { p =>
      (dir.membership(p.user).flatMap(m => dir.policyFor(p.user, m).map(m -> _)), factors.totps(p.id)).flatMapN {
        case ((m, pol), ts) =>
          val confirmed = ts.filter(_.confirmed)
          if dir.mfaRequired(p.user, m, pol) && confirmed.size <= 1 && confirmed.exists(_.id == id) &&
            !(pol.mfa.allowEmail && p.user.email.isDefined && p.user.emailVerified)
          then
            err(ErrorCode.LastAuthenticatorRequired)
          else
            factors.deleteTotp(p.id, id).flatMap {
              case true => audited(audit, req, p, "mfa.totp.remove", audit.userTarget(p.user)) *> NoContent()
              case false => err(ErrorCode.ItemNotFound)
            }
      }
    }

  private def postMeRecoveryCodes(req: Request[IO]): IO[Response[IO]] =
    recentAuth(req)(p =>
      login.newRecoveryCodes(p.id).flatTap(_ => audited(audit, req, p, "mfa.recovery.regenerate"))
        .flatMap(cs => Ok(RecoveryCodesDto(cs)))
    )

  private def getMeApps(req: Request[IO]): IO[Response[IO]] =
    authed(req)(p => portal(p.user, p.membership).flatMap(Ok(_)))

  private def putMeAppsOrder(req: Request[IO]): IO[Response[IO]] =
    authed(req)(p =>
      body[AppOrderReq](req) { r =>
        if r.appIds.size > 1000 then err(ErrorCode.TooManyAuthenticators)
        else apps.setAppOrder(p.id, r.appIds.distinct) *> NoContent()
      }
    )

  private def deleteMeAppsOrder(req: Request[IO]): IO[Response[IO]] =
    authed(req)(p => apps.clearAppOrder(p.id) *> NoContent())

  private def getMeSessions(req: Request[IO]): IO[Response[IO]] =
    authed(req)(p =>
      Time.now.flatMap(now => sessions.loginsOfUser(p.id, now)).flatMap(ls =>
        Ok(ls.map(Conv.session(_, p.login.map(_.id))))
      )
    )

  private def deleteMeSessions(req: Request[IO]): IO[Response[IO]] =
    authed(req) { p =>
      // いま使っている端末以外のログインをすべて終わらせる
      dir.revokeEverything(p.user, p.login.map(_.id)) *>
        audited(audit, req, p, "session.revoke_others") *> NoContent()
    }

  private def deleteMeSession(req: Request[IO], id: UUID): IO[Response[IO]] =
    authed(req) { p =>
      sessions.login(id).flatMap {
        case Some(l) if l.userId == p.id =>
          sessions.deleteLogin(id) *> dir.endLogin(p.id, id) *> audited(audit, req, p, "session.revoke") *>
            NoContent()
        case _ => err(ErrorCode.ItemNotFound)
      }
    }

  private def getMeTokens(req: Request[IO]): IO[Response[IO]] =
    authed(req)(p => factors.tokens(p.id).flatMap(ts => Ok(ts.map(Conv.token(_)))))

  private def postMeTokens(req: Request[IO]): IO[Response[IO]] =
    recentAuth(req)(p => body[TokenReq](req)(r => ctx(req).flatMap(c => okJson(newToken(p.user, p, r, c)))))

  private def deleteMeToken(req: Request[IO], id: UUID): IO[Response[IO]] =
    authed(req)(p =>
      factors.deleteToken(id, Some(p.id)).flatMap(ok =>
        if ok then audited(audit, req, p, "token.delete", Some(("token", id.toString, ""))) *> NoContent()
        else err(ErrorCode.ItemNotFound)
      )
    )

  private def getMeConsents(req: Request[IO]): IO[Response[IO]] =
    authed(req) { p =>
      (apps.consents(p.id), Time.now.flatMap(now => tokens.grantsOf(p.id, now)), apps.all).flatMapN {
        (cs, gs, as) =>
          val byApp = (cs.map((a, s, t) => (a, s, t)) ++ gs.map((a, s, t) => (a, s, t))).groupBy(_._1)
          Ok(byApp.toList.flatMap((aid, rows) =>
            as.find(_.id == aid).map(a =>
              ConsentDto(login.appBrief(a), rows.flatMap(_._2).distinct, rows.map(_._3).max)
            )
          ))
      }
    }

  private def deleteMeConsent(req: Request[IO], appId: UUID): IO[Response[IO]] =
    authed(req)(p =>
      apps.deleteConsent(p.id, appId) *> tokens.revokeUser(p.id, Some(appId)) *>
        audited(audit, req, p, "consent.revoke", Some(("application", appId.toString, ""))) *> NoContent()
    )

  private def getMeCerts(req: Request[IO]): IO[Response[IO]] =
    authed(req)(p => factors.userCerts(p.id).flatMap(cs => Ok(cs.map(Conv.cert))))

  private def postMeCerts(req: Request[IO]): IO[Response[IO]] =
    recentAuth(req)(p =>
      body[CertReq](req)(r =>
        ctx(req).flatMap(c =>
          okJson(addOwnCert(req, p.id, r.pem).flatTap(_.traverse_(x =>
            audit.byPrincipal(c, p, "cert.add", Some(("cert", x.id.toString, x.subject)))
          )))
        )
      )
    )

  private def deleteMeCert(req: Request[IO], id: UUID): IO[Response[IO]] =
    recentAuth(req)(p =>
      factors.deleteUserCert(id, Some(p.id)).flatMap(ok =>
        if ok then NoContent() else err(ErrorCode.ItemNotFound)
      )
    )

  private def postMeEmailVerify(req: Request[IO]): IO[Response[IO]] =
    recentAuth(req) { p =>
      p.user.email match {
        case None => err(ErrorCode.EmailNotRegistered)
        case Some(e) =>
          val t = Crypto.randomToken()
          (dir.policyFor(p.user), Time.now).flatMapN {
            (pol, now) =>
              factors.createEmailToken(p.id, "verify", EmailBinding.hash(t, e), now.plusSeconds(24 * 3600)) *>
                mail.send(
                  e,
                  s"${pol.branding.title} のメールアドレスの確認",
                  s"${p.user.name} さん\n\n次のリンクを開いて、メールアドレスを確認してください（24時間有効）。\n${cfg.publicUrl}/verify-email?token=$t\n"
                ) *>
                NoContent()
          }
      }
    }

  private def postMeEmailConfirm(req: Request[IO]): IO[Response[IO]] =
    webOnly(req) { p =>
      body[Json](req) { j =>
        val t = j.hcursor.get[String]("token").getOrElse("")
        // トークンは確認を求めたときのアドレスに結び付いている（あとでアドレスを変えたら一致しない）
        val found = p.user.email.fold(IO.pure(None))(e =>
          Time.now.flatMap(now => factors.emailTokenByHash("verify", EmailBinding.hash(t, e), now))
        )
        found.flatMap {
          case Some(tk) if tk.userId == p.id =>
            factors.consumeEmailToken(tk.id).flatMap {
              case false => err(ErrorCode.EmailLinkUsed)
              case true =>
                // 確認が済んだので、確認済みの値を今のアドレスに入れ替える
                dir.users.save(p.user.withEmail(p.user.email, verified = true)) *>
                  audited(audit, req, p, "user.email.verify", audit.userTarget(p.user)) *> NoContent()
            }
          case _ => err(ErrorCode.EmailLinkExpired)
        }
      }
    }

  /**
   * 画面（ブラウザのログイン）以外、つまり API トークン・OAuth でほかのサービスが読むときは、email を確認済みの値にする
   * （未確認のアドレスをほかのサービスに渡さない）. 画面には今の値（未確認のことがある）と確認済みの値の両方を返す.
   */
  private def outward(p: Principal, d: MeDto): MeDto =
    if p.via.isInstanceOf[Via.Web] then d
    else d.copy(email = d.verifiedEmail, emailVerified = d.verifiedEmail.isDefined)

  def me(u: User): IO[MeDto] =
    for {
      m <- dir.membership(u)
      p <- dir.policyFor(u, m)
      ts <- factors.totps(u.id)
      rec <- factors.recoveryRemaining(u.id)
      defs <- dir.users.attributeDefs
      rules <- dir.passwordRulesFor(u)
    } yield MeDto(
      u.id,
      u.username,
      u.name,
      u.email,
      u.emailVerified,
      u.givenName,
      u.familyName,
      dir.pictureUrl(u, p.branding.gravatar),
      u.hasAvatar,
      dir.isAdmin(u, m),
      m.names,
      u.attributes,
      defs.map(Conv.attrDef),
      MfaStatusDto(
        ts.filter(_.confirmed).map(t => TotpDto(t.id, t.name, t.createdAt)),
        rec,
        p.mfa.allowEmail && u.email.isDefined,
        dir.mfaRequired(u, m, p)
      ),
      u.passwordHash.isDefined,
      u.source,
      u.locale,
      u.zoneinfo,
      u.phoneNumber,
      rules,
      u.verifiedEmail
    )

  /** ポータルに出すアプリ（使えるものだけ）. 本人が並べ替えた順. 並べ替えた後に増えたアプリは後ろに名前の順. */
  def portal(u: User, m: Membership): IO[List[AppBriefDto]] =
    (apps.all, apps.allAccessGroups, apps.appOrder(u.id), apps.displayNames(m.ids), apps.displayLogos(m.ids)).mapN {
      (as, access, order, names, logos) =>
        val pos = order.zipWithIndex.toMap
        as.filter(a =>
          a.enabled && a.showInPortal && (!a.restrictAccess || access.getOrElse(a.id, Nil).exists(m.ids.contains))
        )
          // グループごとの表示名の上書き
          .map { a =>
            // グループごとの表示名・ロゴの上書き
            val b = login.appBrief(a.copy(name = names.getOrElse(a.id, a.name)))
            logos.get(a.id).fold(b)(l => b.copy(iconUrl = Some(s"/brand-logos/$l")))
          }.filter(_.launchUrl.isDefined)
          .zipWithIndex.sortBy((a, i) => (pos.getOrElse(a.id, Int.MaxValue), i)).map(_._1)
    }

  private def updateMe(p: Principal, r: MeUpdateReq, c: ReqCtx): Res[MeDto] =
    for {
      defs <- dir.users.attributeDefs
      res <- (
        dir.validEmail(r.email),
        Attrs.validate(defs, r.attributes, onlyEditable = true, p.user.attributes)
      ).tupled match {
        case Left(e) => Res.fail(ErrorCode.InvalidInput, e)
        case Right((sent, attrs)) =>
          // トークンで読んだ値（確認済みのアドレス）がそのまま返ってきたときは、変更ではない（確認待ちのアドレスを消さない）
          val email = if !p.via.isInstanceOf[Via.Web] && sent == p.user.verifiedEmail then p.user.email else sent
          val external = p.user.source != "local"
          val emailChanged = email != p.user.email
          if external && emailChanged then Res.fail(ErrorCode.EmailManagedExternally)
          else if emailChanged && !p.via.isInstanceOf[Via.Web] then
            Res.fail(ErrorCode.EmailChangeUiOnly, "メールアドレスは画面から変えてください")
          else
            Time.now.map(now => !emailChanged || RecentAuth.recent(p, now)).flatMap {
              case false => Res.fail(AppError(ErrorCode.ReauthRequired))
              case true => emailFree(email, p.id).flatMap {
                  case false => Res.fail(AppError(ErrorCode.EmailInUse))
                  case true =>
                    // 変えたアドレスは未確認. 確認済みの値（verifiedEmail）は残るので、確認が済むまで各サービスには以前の
                    // アドレスを渡し続ける. 確認済みのアドレスに戻したときは、確認済みのまま
                    val backToVerified = email.exists(e => p.user.verifiedEmail.exists(_.equalsIgnoreCase(e)))
                    val verified = if emailChanged then backToVerified else p.user.emailVerified
                    val u2 = p.user.withEmail(email, verified).copy(
                      name = r.name.trim.take(200).some.filter(_.nonEmpty).getOrElse(p.user.name),
                      givenName = r.givenName.filter(_.nonEmpty),
                      familyName = r.familyName.filter(_.nonEmpty),
                      attributes = attrs,
                      locale = r.locale.filter(_.nonEmpty),
                      zoneinfo = r.zoneinfo.filter(_.nonEmpty),
                      phoneNumber = r.phoneNumber.filter(_.nonEmpty)
                    )
                    dir.users.save(u2).flatMap {
                      case Left(e) => Res.fail(e)
                      case Right(saved) =>
                        audit.byPrincipal(c, p, "user.profile.update", audit.userTarget(saved)) *>
                          dir.recomputeUser(saved) *> me(saved).map(Right(_))
                    }
                }
            }
      }
    } yield res

  /** 他のユーザーが使っていないメールアドレスか. */
  private def emailFree(email: Option[String], self: UUID): IO[Boolean] =
    email.fold(IO.pure(true))(e => dir.users.byEmail(e).map(_.forall(_.id == self)))

  /**
   * 現在のパスワードの確認には、ログインと同じ試行の制限をかける（IP ごとの回数・アカウントのロック.
   * 盗んだ Cookie から、今のパスワードを総当たりで当てられないように）.
   */
  private def changePassword(p: Principal, r: PasswordChangeReq, c: ReqCtx): Res[Unit] =
    (login.throttled(c), Time.now).flatMapN {
      (thr, now) =>
        if thr then Res.fail(AppError(ErrorCode.TooManyAttempts))
        // ロック中はパスワードを確かめない（正誤で応答を変えると、ロック中に総当たりできてしまう）
        else if p.user.passwordHash.isDefined && p.user.locked(now) then Res.fail(AppError(ErrorCode.AccountLocked))
        else
          // Argon2id は重いので blocking のスレッドで確かめる
          p.user.passwordHash.traverse(h => IO.blocking(Passwords.verify(r.current, h))).flatMap {
            case Some(false) =>
              login.countFailure(c, Some(p.user)) *>
                audit.byPrincipal(c, p, "user.password.change", audit.userTarget(p.user), success = false) *>
                Res.fail(AppError(ErrorCode.CurrentPasswordWrong))
            case None if p.user.source != "local" => Res.fail(ErrorCode.ExternalIdpAccount)
            case _ =>
              dir.setPassword(p.user, r.next, mustChange = false, keepLogin = p.login.map(_.id)).flatMap {
                case Left(e) => Res.fail(ErrorCode.InvalidInput, e)
                case Right(_) =>
                  audit.byPrincipal(c, p, "user.password.change", audit.userTarget(p.user)).as(Right(()))
              }
          }
    }

  private def startTotp(p: Principal): IO[TotpSetupDto] =
    dir.policyFor(p.user).flatMap { pol =>
      val secret = Totp.newSecret()
      factors.deleteUnconfirmedTotps(p.id) *> factors.addTotp(p.id, "認証アプリ", box.encrypt(secret)).map(d =>
        TotpSetupDto(d.id, secret, Totp.uri(pol.branding.title, p.user.username, secret))
      )
    }

  private def verifyTotp(p: Principal, r: TotpVerifyReq, c: ReqCtx): Res[RecoveryCodesDto] =
    factors.totp(r.id).flatMap {
      case Some(d) if d.userId == p.id && !d.confirmed =>
        Time.now.flatMap { now =>
          box.decrypt(d.secretEnc).flatMap(s => Totp.verify(s, r.code, now.getEpochSecond, 0)) match {
            case None => Res.fail(ErrorCode.MfaCodeWrong)
            case Some(step) =>
              for {
                before <- factors.recoveryRemaining(p.id)
                _ <- factors.confirmTotp(d.id, step)
                codes <- if before == 0 then login.newRecoveryCodes(p.id) else IO.pure(Nil)
                _ <- audit.byPrincipal(c, p, "mfa.totp.enroll", audit.userTarget(p.user))
              } yield Right(RecoveryCodesDto(codes))
          }
        }
      case _ => Res.fail(ErrorCode.MfaEnrollRestart)
    }

  def newToken(owner: User, by: Principal, r: TokenReq, c: ReqCtx): Res[CreatedTokenDto] =
    if (r.scopes.contains(TokenScopes.Admin) || r.scopes.contains(TokenScopes.Scim)) && !by.canAdmin then
      Res.fail(ErrorCode.ApiTokenAdminScopeAdminOnly)
    else
      dir.createApiToken(owner.id, r.name, r.scopes, r.days).flatMap {
        case Left(e) => Res.fail(ErrorCode.InvalidInput, e)
        case Right((t, tk)) =>
          audit.byPrincipal(
            c,
            by,
            "token.create",
            Some(("token", tk.id.toString, tk.name)),
            detail = Json.obj("owner" -> owner.username.asJson, "scopes" -> tk.scopes.asJson)
          ).as(Right(CreatedTokenDto(t, Conv.token(tk))))
      }

  def addCert(userId: UUID, pem: String): Res[UserCertDto] =
    ClientCerts.fromHeader(pem) match {
      case Left(e) => Res.fail(ErrorCode.InvalidInput, e)
      case Right(cert) => saveCert(userId, cert)
    }

  private def saveCert(userId: UUID, cert: java.security.cert.X509Certificate): Res[UserCertDto] = {
    val i = ClientCerts.info(cert)
    factors.addUserCert(userId, i.fingerprint, i.subject, i.issuer, i.notAfter).map(_.map(Conv.cert))
  }

  /**
   * 本人による証明書の登録: この要求で提示した（秘密鍵を持っている）、信頼する CA の証明書だけ.
   * 公開の情報である PEM だけで他人の証明書を自分に登録し、本人をこちらのアカウントへログインさせることを防ぐ.
   */
  private def addOwnCert(req: Request[IO], userId: UUID, pem: String): Res[UserCertDto] =
    (auth.presentedChain(req), factors.authorities, Time.now).flatMapN {
      (chain, cas, now) =>
        val anchors = cas.filter(_.enabled).flatMap(a => Jose.parseCerts(a.pem).toOption.toList.flatten)
        chain.toRight("登録する証明書をブラウザで選んで（提示して）から、もう一度お試しください")
          .flatMap(ClientCerts.validate(_, anchors, now))
          .flatMap(leaf =>
            Either.cond(
              pem.trim.isEmpty || ClientCerts.fromHeader(pem).toOption.exists(c =>
                ClientCerts.fingerprint(c) == ClientCerts.fingerprint(leaf)
              ),
              leaf,
              "貼り付けた証明書と、ブラウザで提示した証明書が違います"
            )
          ) match {
          case Left(e) => Res.fail(ErrorCode.InvalidInput, e)
          case Right(leaf) => saveCert(userId, leaf)
        }
    }

}

/** メールの確認のトークンを、そのときのメールアドレスに結び付けたハッシュ. */
object EmailBinding {
  def hash(token: String, email: String): Array[Byte] = Crypto.sha256(token + "\n" + email.trim.toLowerCase)
}
