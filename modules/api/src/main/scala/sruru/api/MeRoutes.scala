package sruru.api

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

/** 共通の変換と画像の受け取り. */
object Conv:
  def token(t: ApiToken, owner: Option[UserBrief] = None): ApiTokenDto =
    ApiTokenDto(t.id, t.name, t.prefix, t.scopes, t.expiresAt, t.lastUsedAt, t.createdAt, owner)

  def session(l: Login, current: Option[UUID]): LoginSessionDto =
    LoginSessionDto(l.id, l.ip, l.userAgent, l.createdAt, l.lastSeenAt, l.amr, current.contains(l.id))

  def cert(c: UserCert): UserCertDto = UserCertDto(c.id, c.fingerprint, c.subject, c.issuer, c.notAfter, c.createdAt)

  def attrDef(d: AttributeDef): AttributeDefDto = AttributeDefDto(d.key, d.label, d.kind, d.description, d.userEditable, d.required, d.scimPath, d.sort)

  private val imageTypes = Set("image/png", "image/jpeg", "image/webp", "image/gif")

  val Svg = "image/svg+xml"

  /**
   * 本文の画像を読む（種類と大きさを確かめる）. allowSvg はロゴだけ（配信のときに CSP でスクリプトを止める）.
   * SVG は中身が SVG であることと、スクリプト・外部の参照を含まないことも確かめる.
   */
  def readImage(req: Request[IO], max: Int, allowSvg: Boolean = false): IO[Either[String, (Array[Byte], String)]] =
    val ct = req.contentType.map(c => s"${c.mediaType.mainType}/${c.mediaType.subType}").getOrElse("")
    if !imageTypes(ct) && !(allowSvg && ct == Svg) then
      IO.pure(Left(if allowSvg then "PNG・JPEG・WebP・GIF・SVG の画像を送ってください" else "PNG・JPEG・WebP・GIF の画像を送ってください"))
    else
      req.body.take(max.toLong + 1).compile.to(Array).map { b =>
        if b.length > max then Left(s"画像は ${max / 1024}KB 以下にしてください")
        else if b.isEmpty then Left("画像が空です")
        else if ct == Svg && !safeSvg(new String(b, java.nio.charset.StandardCharsets.UTF_8)) then
          Left("SVG にスクリプト・イベントの属性・外部の参照は含められません")
        else Right((b, ct))
      }

  /** SVG にスクリプト・イベントの属性・外部の参照がないか. */
  def safeSvg(s: String): Boolean =
    val t = s.toLowerCase
    t.contains("<svg") && !List("<script", "javascript:", "<foreignobject", "<!entity", "<iframe", "<embed", "<object").exists(t.contains) &&
      !"""\son[a-z]+\s*=""".r.findFirstIn(t).isDefined && !"""(href|src)\s*=\s*["']?\s*(https?:|//|data:)""".r.findFirstIn(t).isDefined

/** 属性の値を定義に合わせて確かめる. */
object Attrs:
  def validate(defs: List[AttributeDef], attrs: Json, onlyEditable: Boolean, previous: Json): Either[String, Json] =
    val obj = attrs.asObject.getOrElse(io.circe.JsonObject.empty)
    val byKey = defs.map(d => d.key -> d).toMap
    val checked = obj.toList.traverse { (k, v) =>
      byKey.get(k) match
        case None => Left(s"属性「$k」は定義されていません")
        case Some(d) if onlyEditable && !d.userEditable => Left(s"属性「${d.label}」は変更できません")
        case Some(d) =>
          val ok = v.isNull || (d.kind match
            case "number"  => v.isNumber
            case "boolean" => v.isBoolean
            case "list"    => v.asArray.exists(_.forall(_.isString))
            case "date"    => v.asString.exists(s => scala.util.Try(java.time.LocalDate.parse(s)).isSuccess)
            case _         => v.isString)
          Either.cond(ok, k -> v, s"属性「${d.label}」の値の形式が正しくありません")
    }
    checked.flatMap { kvs =>
      // 変更できない属性は前の値を残す
      val merged = if onlyEditable then previous.deepMerge(Json.fromFields(kvs)) else Json.fromFields(kvs)
      val missing = defs.filter(d => d.required && merged.hcursor.downField(d.key).focus.forall(j => j.isNull || j.asString.exists(_.isEmpty)))
      if missing.nonEmpty && !onlyEditable then Left(s"属性「${missing.head.label}」は必須です")
      else Right(merged.dropNullValues)
    }

/** 自分の情報・セキュリティの設定・API トークン. */
final class MeRoutes(dir: Directory, factors: FactorStore, sessions: SessionStore, tokens: TokenStore, apps: AppStore, fedStore: FederationStore,
    login: LoginService, mail: MailService, policies: PolicyService, audit: AuditService, box: SecretBox, val auth: SessionAuth, cfg: ApiConfig)
    extends RouteSupport:

  def me(u: User): IO[MeDto] =
    for
      m     <- dir.membership(u)
      p     <- dir.policyFor(u, m)
      ts    <- factors.totps(u.id)
      rec   <- factors.recoveryRemaining(u.id)
      defs  <- dir.users.attributeDefs
      rules <- dir.passwordRulesFor(u)
    yield MeDto(u.id, u.username, u.name, u.email, u.emailVerified, u.givenName, u.familyName, dir.pictureUrl(u, p.branding.gravatar), u.hasAvatar,
      dir.isAdmin(u, m), m.names, u.attributes, defs.map(Conv.attrDef),
      MfaStatusDto(ts.filter(_.confirmed).map(t => TotpDto(t.id, t.name, t.createdAt)), rec, p.mfa.allowEmail && u.email.isDefined,
        dir.mfaRequired(u, m, p)),
      u.passwordHash.isDefined, u.source, u.locale, u.zoneinfo, u.phoneNumber, rules)

  /** ポータルに出すアプリ（使えるものだけ）. 本人が並べ替えた順. 並べ替えた後に増えたアプリは後ろに名前の順. */
  def portal(u: User, m: Membership): IO[List[AppBriefDto]] =
    (apps.all, apps.allAccessGroups, apps.appOrder(u.id)).mapN { (as, access, order) =>
      val pos = order.zipWithIndex.toMap
      as.filter(a => a.enabled && a.showInPortal && (!a.restrictAccess || access.getOrElse(a.id, Nil).exists(m.ids.contains)))
        .map(login.appBrief).filter(_.launchUrl.isDefined)
        .zipWithIndex.sortBy((a, i) => (pos.getOrElse(a.id, Int.MaxValue), i)).map(_._1)
    }

  private def updateMe(p: Principal, r: MeUpdateReq, c: ReqCtx): Res[MeDto] =
    for
      defs <- dir.users.attributeDefs
      res <- (dir.validEmail(r.email), Attrs.validate(defs, r.attributes, onlyEditable = true, p.user.attributes)).tupled match
        case Left(e) => Res.invalid(e)
        case Right((email, attrs)) =>
          val external = p.user.source != "local"
          val emailChanged = email != p.user.email
          if external && emailChanged then Res.invalid("外部のディレクトリから取り込んだアカウントのメールアドレスは変えられません")
          else if emailChanged && !p.via.isInstanceOf[Via.Web] then Res.forbidden("メールアドレスは画面から変えてください")
          else Time.now.map(now => !emailChanged || RecentAuth.recent(p, now)).flatMap {
            case false => Res.fail(Fail.Reauth(RecentAuth.Message))
            case true  => emailFree(email, p.id).flatMap {
            case false => Res.fail(Fail.Conflict("このメールアドレスは別のアカウントで使われています"))
            case true =>
            val u2 = p.user.copy(name = r.name.trim.take(200).some.filter(_.nonEmpty).getOrElse(p.user.name), givenName = r.givenName.filter(_.nonEmpty),
              familyName = r.familyName.filter(_.nonEmpty), email = email, emailVerified = if emailChanged then false else p.user.emailVerified,
              attributes = attrs, locale = r.locale.filter(_.nonEmpty), zoneinfo = r.zoneinfo.filter(_.nonEmpty),
              phoneNumber = r.phoneNumber.filter(_.nonEmpty))
            dir.users.save(u2).flatMap {
              case Left(e) => Res.fail(Fail.from(e))
              case Right(saved) =>
                audit.byPrincipal(c, p, "user.profile.update", audit.userTarget(saved)) *> dir.recomputeUser(saved) *> me(saved).map(Right(_))
            }
          }
          }
    yield res

  /** 他のユーザーが使っていないメールアドレスか. */
  private def emailFree(email: Option[String], self: UUID): IO[Boolean] =
    email.fold(IO.pure(true))(e => dir.users.byEmail(e).map(_.forall(_.id == self)))

  private def changePassword(p: Principal, r: PasswordChangeReq, c: ReqCtx): Res[Unit] =
    p.user.passwordHash match
      case Some(h) if !Passwords.verify(r.current, h) =>
        audit.byPrincipal(c, p, "user.password.change", audit.userTarget(p.user), success = false) *> Res.fail(Fail.Invalid("現在のパスワードが違います"))
      case None if p.user.source != "local" => Res.invalid("外部の IdP でログインするアカウントです")
      case _ =>
        dir.setPassword(p.user, r.next, mustChange = false, keepLogin = p.login.map(_.id)).flatMap {
          case Left(e) => Res.invalid(e)
          case Right(_) => audit.byPrincipal(c, p, "user.password.change", audit.userTarget(p.user)).as(Right(()))
        }

  private def startTotp(p: Principal): IO[TotpSetupDto] =
    dir.policyFor(p.user).flatMap { pol =>
      val secret = Totp.newSecret()
      factors.deleteUnconfirmedTotps(p.id) *> factors.addTotp(p.id, "認証アプリ", box.encrypt(secret)).map(d =>
        TotpSetupDto(d.id, secret, Totp.uri(pol.branding.title, p.user.username, secret)))
    }

  private def verifyTotp(p: Principal, r: TotpVerifyReq, c: ReqCtx): Res[RecoveryCodesDto] =
    factors.totp(r.id).flatMap {
      case Some(d) if d.userId == p.id && !d.confirmed =>
        Time.now.flatMap { now =>
          box.decrypt(d.secretEnc).flatMap(s => Totp.verify(s, r.code, now.getEpochSecond, 0)) match
            case None => Res.invalid("コードが違います")
            case Some(step) =>
              for
                before <- factors.recoveryRemaining(p.id)
                _      <- factors.confirmTotp(d.id, step)
                codes  <- if before == 0 then login.newRecoveryCodes(p.id) else IO.pure(Nil)
                _      <- audit.byPrincipal(c, p, "mfa.totp.enroll", audit.userTarget(p.user))
              yield Right(RecoveryCodesDto(codes))
        }
      case _ => Res.invalid("登録をやり直してください")
    }

  def newToken(owner: User, by: Principal, r: TokenReq, c: ReqCtx): Res[CreatedTokenDto] =
    if (r.scopes.contains(TokenScopes.Admin) || r.scopes.contains(TokenScopes.Scim)) && !by.canAdmin then Res.forbidden("admin・scim は管理者だけが使えます")
    else
      dir.createApiToken(owner.id, r.name, r.scopes, r.days).flatMap {
        case Left(e) => Res.invalid(e)
        case Right((t, tk)) =>
          audit.byPrincipal(c, by, "token.create", Some(("token", tk.id.toString, tk.name)),
            detail = Json.obj("owner" -> owner.username.asJson, "scopes" -> tk.scopes.asJson)).as(Right(CreatedTokenDto(t, Conv.token(tk))))
      }

  def addCert(userId: UUID, pem: String): Res[UserCertDto] =
    ClientCerts.fromHeader(pem) match
      case Left(e)     => Res.invalid(e)
      case Right(cert) => saveCert(userId, cert)

  private def saveCert(userId: UUID, cert: java.security.cert.X509Certificate): Res[UserCertDto] =
    val i = ClientCerts.info(cert)
    factors.addUserCert(userId, i.fingerprint, i.subject, i.issuer, i.notAfter).orFail.map(_.map(Conv.cert))

  /**
   * 本人による証明書の登録: この要求で提示した（秘密鍵を持っている）、信頼する CA の証明書だけ.
   * 公開の情報である PEM だけで他人の証明書を自分に登録し、本人をこちらのアカウントへログインさせることを防ぐ.
   */
  private def addOwnCert(req: Request[IO], userId: UUID, pem: String): Res[UserCertDto] =
    (auth.presentedChain(req), factors.authorities, Time.now).flatMapN { (chain, cas, now) =>
      val anchors = cas.filter(_.enabled).flatMap(a => Jose.parseCerts(a.pem).toOption.toList.flatten)
      chain.toRight("登録する証明書をブラウザで選んで（提示して）から、もう一度お試しください")
        .flatMap(ClientCerts.validate(_, anchors, now))
        .flatMap(leaf => Either.cond(pem.trim.isEmpty || ClientCerts.fromHeader(pem).toOption.exists(c => ClientCerts.fingerprint(c) == ClientCerts.fingerprint(leaf)),
          leaf, "貼り付けた証明書と、ブラウザで提示した証明書が違います")) match
        case Left(e)     => Res.invalid(e)
        case Right(leaf) => saveCert(userId, leaf)
    }

  val routes: HttpRoutes[IO] = HttpRoutes.of[IO] {
    case req @ GET -> Root / "api" / "me" => authed(req)(p => me(p.user).flatMap(Ok(_)))

    case req @ PUT -> Root / "api" / "me" =>
      authed(req)(p => body[MeUpdateReq](req)(r => ctx(req).flatMap(c => okJson(updateMe(p, r, c)))))

    case req @ POST -> Root / "api" / "me" / "avatar" =>
      authed(req) { p =>
        Conv.readImage(req, cfg.maxAvatarBytes).flatMap {
          case Left(e) => err(Status.BadRequest, e)
          case Right(img) => dir.users.setAvatar(p.id, Some(img)) *> audited(audit, req, p, "user.avatar.update") *> NoContent()
        }
      }

    case req @ DELETE -> Root / "api" / "me" / "avatar" => authed(req)(p => dir.users.setAvatar(p.id, None) *> NoContent())

    case req @ POST -> Root / "api" / "me" / "password" =>
      webOnly(req)(p => body[PasswordChangeReq](req)(r => ctx(req).flatMap(c => noContent(changePassword(p, r, c)))))

    case req @ POST -> Root / "api" / "me" / "totp" => recentAuth(req)(p => startTotp(p).flatMap(Ok(_)))

    case req @ POST -> Root / "api" / "me" / "totp" / "verify" =>
      recentAuth(req)(p => body[TotpVerifyReq](req)(r => ctx(req).flatMap(c => okJson(verifyTotp(p, r, c)))))

    case req @ DELETE -> Root / "api" / "me" / "totp" / UuidVar(id) =>
      recentAuth(req) { p =>
        (dir.membership(p.user).flatMap(m => dir.policyFor(p.user, m).map(m -> _)), factors.totps(p.id)).flatMapN { case ((m, pol), ts) =>
          val confirmed = ts.filter(_.confirmed)
          if dir.mfaRequired(p.user, m, pol) && confirmed.size <= 1 && confirmed.exists(_.id == id) && !(pol.mfa.allowEmail && p.user.email.isDefined) then
            err(Status.BadRequest, "多要素認証が必須のため、最後の認証アプリは外せません")
          else factors.deleteTotp(p.id, id).flatMap {
            case true  => audited(audit, req, p, "mfa.totp.remove", audit.userTarget(p.user)) *> NoContent()
            case false => err(Status.NotFound, "見つかりません")
          }
        }
      }

    case req @ POST -> Root / "api" / "me" / "recovery-codes" =>
      recentAuth(req)(p => login.newRecoveryCodes(p.id).flatTap(_ => audited(audit, req, p, "mfa.recovery.regenerate"))
        .flatMap(cs => Ok(RecoveryCodesDto(cs))))

    case req @ GET -> Root / "api" / "me" / "apps" => authed(req)(p => portal(p.user, p.membership).flatMap(Ok(_)))

    // ポータルの並び順（本人だけのもの）
    case req @ PUT -> Root / "api" / "me" / "apps" / "order" =>
      authed(req)(p => body[AppOrderReq](req) { r =>
        if r.appIds.size > 1000 then err(Status.BadRequest, "アプリが多すぎます")
        else apps.setAppOrder(p.id, r.appIds.distinct) *> NoContent()
      })

    case req @ DELETE -> Root / "api" / "me" / "apps" / "order" => authed(req)(p => apps.clearAppOrder(p.id) *> NoContent())

    case req @ GET -> Root / "api" / "me" / "sessions" =>
      authed(req)(p => Time.now.flatMap(now => sessions.loginsOfUser(p.id, now)).flatMap(ls => Ok(ls.map(Conv.session(_, p.login.map(_.id))))))

    case req @ DELETE -> Root / "api" / "me" / "sessions" =>
      authed(req) { p =>
        // いま使っている端末以外のログインをすべて終わらせる
        dir.revokeEverything(p.user, p.login.map(_.id)) *>
          audited(audit, req, p, "session.revoke_others") *> NoContent()
      }

    case req @ DELETE -> Root / "api" / "me" / "sessions" / UuidVar(id) =>
      authed(req) { p =>
        sessions.login(id).flatMap {
          case Some(l) if l.userId == p.id =>
            sessions.deleteLogin(id) *> dir.endLogin(p.id, id) *> audited(audit, req, p, "session.revoke") *> NoContent()
          case _ => err(Status.NotFound, "見つかりません")
        }
      }

    case req @ GET -> Root / "api" / "me" / "tokens" => authed(req)(p => factors.tokens(p.id).flatMap(ts => Ok(ts.map(Conv.token(_)))))

    case req @ POST -> Root / "api" / "me" / "tokens" =>
      recentAuth(req)(p => body[TokenReq](req)(r => ctx(req).flatMap(c => okJson(newToken(p.user, p, r, c)))))

    case req @ DELETE -> Root / "api" / "me" / "tokens" / UuidVar(id) =>
      authed(req)(p => factors.deleteToken(id, Some(p.id)).flatMap(ok =>
        if ok then audited(audit, req, p, "token.delete", Some(("token", id.toString, ""))) *> NoContent()
        else err(Status.NotFound, "見つかりません")))

    case req @ GET -> Root / "api" / "me" / "consents" =>
      authed(req) { p =>
        (apps.consents(p.id), Time.now.flatMap(now => tokens.grantsOf(p.id, now)), apps.all).flatMapN { (cs, gs, as) =>
          val byApp = (cs.map((a, s, t) => (a, s, t)) ++ gs.map((a, s, t) => (a, s, t))).groupBy(_._1)
          Ok(byApp.toList.flatMap((aid, rows) => as.find(_.id == aid).map(a =>
            ConsentDto(login.appBrief(a), rows.flatMap(_._2).distinct, rows.map(_._3).max))))
        }
      }

    case req @ DELETE -> Root / "api" / "me" / "consents" / UuidVar(appId) =>
      authed(req)(p => apps.deleteConsent(p.id, appId) *> tokens.revokeUser(p.id, Some(appId)) *>
        audited(audit, req, p, "consent.revoke", Some(("application", appId.toString, ""))) *> NoContent())

    case req @ GET -> Root / "api" / "me" / "certs" => authed(req)(p => factors.userCerts(p.id).flatMap(cs => Ok(cs.map(Conv.cert))))

    case req @ POST -> Root / "api" / "me" / "certs" =>
      recentAuth(req)(p => body[CertReq](req)(r => ctx(req).flatMap(c =>
        okJson(addOwnCert(req, p.id, r.pem).flatTap(_.traverse_(x => audit.byPrincipal(c, p, "cert.add", Some(("cert", x.id.toString, x.subject)))))))))

    case req @ DELETE -> Root / "api" / "me" / "certs" / UuidVar(id) =>
      recentAuth(req)(p => factors.deleteUserCert(id, Some(p.id)).flatMap(ok => if ok then NoContent() else err(Status.NotFound, "見つかりません")))

    case req @ POST -> Root / "api" / "me" / "email" / "verify" =>
      recentAuth(req) { p =>
        p.user.email match
          case None => err(Status.BadRequest, "メールアドレスが登録されていません")
          case Some(e) =>
            val t = Crypto.randomToken()
            (dir.policyFor(p.user), Time.now).flatMapN { (pol, now) =>
              factors.createEmailToken(p.id, "verify", EmailBinding.hash(t, e), now.plusSeconds(24 * 3600)) *>
                mail.send(e, s"${pol.branding.title} のメールアドレスの確認",
                  s"${p.user.name} さん\n\n次のリンクを開いて、メールアドレスを確認してください（24時間有効）。\n${cfg.publicUrl}/verify-email?token=$t\n") *>
                NoContent()
            }
      }

    case req @ POST -> Root / "api" / "me" / "email" / "confirm" =>
      webOnly(req) { p =>
        body[Json](req) { j =>
          val t = j.hcursor.get[String]("token").getOrElse("")
          // トークンは確認を求めたときのアドレスに結び付いている（あとでアドレスを変えたら一致しない）
          val found = p.user.email.fold(IO.pure(None))(e => Time.now.flatMap(now => factors.emailTokenByHash("verify", EmailBinding.hash(t, e), now)))
          found.flatMap {
            case Some(tk) if tk.userId == p.id =>
              factors.consumeEmailToken(tk.id).flatMap {
                case false => err(Status.BadRequest, "このリンクはすでに使われています")
                case true =>
                  dir.users.save(p.user.copy(emailVerified = true)) *>
                    audited(audit, req, p, "user.email.verify", audit.userTarget(p.user)) *> NoContent()
              }
            case _ => err(Status.BadRequest, "リンクの有効期限が切れているか、別のアカウントのものです")
          }
        }
      }
  }

/** メールの確認のトークンを、そのときのメールアドレスに結び付けたハッシュ. */
object EmailBinding:
  def hash(token: String, email: String): Array[Byte] = Crypto.sha256(token + "\n" + email.trim.toLowerCase)
