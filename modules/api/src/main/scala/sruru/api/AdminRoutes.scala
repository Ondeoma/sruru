package sruru.api

import cats.effect.*
import cats.syntax.all.*
import io.circe.Json
import io.circe.syntax.*
import org.http4s.*
import org.http4s.circe.CirceEntityCodec.*
import org.http4s.headers.`Content-Type`
import sruru.core.*
import sruru.db.*
import sruru.saml.Saml
import sruru.security.*
import sruru.shared.*

import java.time.Instant
import java.util.UUID

/** 管理 API（システム管理者のみ）. */
final class AdminRoutes(dir: Directory, factors: FactorStore, sessions: SessionStore, tokens: TokenStore, apps: AppStore, fedStore: FederationStore,
    fed: FederationService, auditStore: AuditStore, keys: KeyService, me: MeRoutes, login: LoginService, claims: Claims,
    policies: PolicyService, audit: AuditService, mail: MailService, box: SecretBox, settings: SettingsStore, val auth: SessionAuth, cfg: ApiConfig)
    extends RouteSupport:

  private val MaxLogoBytes = 512 * 1024

  private val base = cfg.publicUrl

  def idpInfo: IO[IdpInfoDto] =
    keys.saml.map { k =>
      IdpInfoDto(base, s"$base/.well-known/openid-configuration", s"$base/oauth2/jwks", s"$base/oauth2/authorize", s"$base/oauth2/token",
        s"$base/oauth2/userinfo", s"$base/oauth2/logout", s"$base/saml/metadata", s"$base/saml/metadata", s"$base/saml/sso", s"$base/saml/slo",
        k.cert.map(Jose.certPem).getOrElse(""), s"$base/scim/v2", s"$base/mcp")
    }

  // ------------------------------------------------------------------ ユーザー

  private def userDto(u: User): IO[UserDto] =
    (dir.membership(u), dir.hasTotp(u.id), policies.get, Time.now, dir.groups.staticGroupIds(u.id)).mapN((m, mfa, p, now, direct) =>
      dir.userDto(u, m, mfa, p.branding.gravatar, now, direct))

  private def listUsers(req: Request[IO]): IO[UserListDto] =
    val query = UserQuery(q(req, "q"), q(req, "status"), q(req, "groupId").flatMap(uuidParam), q(req, "source"), qInt(req, "limit", 50, 500),
      qInt(req, "offset", 0, Int.MaxValue))
    for
      now  <- Time.now
      p    <- policies.get
      res  <- dir.users.list(query, now)
      ms   <- dir.groups.memberships(res._1.map(_.id))
      mfa  <- factors.usersWithTotp(Some(res._1.map(_.id)))
    yield UserListDto(res._1.map(u => dir.userDto(u, ms.getOrElse(u.id, Membership(Nil)), mfa(u.id), p.branding.gravatar, now)), res._2)

  private def fromReq(r: UserReq, prev: Option[User], defs: List[AttributeDef]): Either[String, User => User] =
    for
      name  <- dir.validUsername(r.username)
      email <- dir.validEmail(r.email)
      attrs <- Attrs.validate(defs, r.attributes, onlyEditable = false, Json.obj())
    yield (u: User) => u.copy(username = name, name = r.name.trim.some.filter(_.nonEmpty).getOrElse(name), email = email,
      emailVerified = r.emailVerified, givenName = r.givenName.filter(_.nonEmpty), familyName = r.familyName.filter(_.nonEmpty), isAdmin = r.isAdmin,
      disabled = r.disabled, mustChangePassword = r.mustChangePassword, attributes = attrs, locale = r.locale.filter(_.nonEmpty),
      zoneinfo = r.zoneinfo.filter(_.nonEmpty), phoneNumber = r.phoneNumber.filter(_.nonEmpty))

  private def createUser(p: Principal, r: UserReq, c: ReqCtx): Res[UserDto] =
    dir.users.attributeDefs.flatMap { defs =>
      fromReq(r, None, defs) match
        case Left(e) => Res.invalid(e)
        case Right(f) =>
          r.password.filter(_.nonEmpty).traverse(pw => dir.checkPassword(None, pw)).map(_.sequence).flatMap {
            case Left(e) => Res.invalid(e)
            case Right(_) =>
              r.password.filter(_.nonEmpty).traverse(Directory.hash).flatMap(h =>
                dir.users.create(NewUser(r.username.trim, None, r.name, passwordHash = h, isService = r.isService))).flatMap {
                case Left(e) => Res.fail(Fail.from(e))
                case Right(u0) =>
                  dir.users.save(f(u0)).flatMap {
                    case Left(e) => dir.users.delete(u0.id) *> Res.fail(Fail.from(e))
                    case Right(u) =>
                      r.groupIds.traverse_(gs => gs.traverse_(g => dir.groups.addMember(g, u.id))) *> dir.recomputeUser(u) *>
                        audit.byPrincipal(c, p, "user.create", audit.userTarget(u)) *> userDto(u).map(Right(_))
                  }
              }
          }
    }

  private def updateUser(p: Principal, id: UUID, r: UserReq, c: ReqCtx): Res[UserDto] =
    (dir.users.find(id), dir.users.attributeDefs).tupled.flatMap {
      case (None, _) => Res.notFound("ユーザーが見つかりません")
      case (Some(u), defs) =>
        fromReq(r, Some(u), defs) match
          case Left(e) => Res.invalid(e)
          case Right(f) =>
            val next = f(u)
            if u.id == p.id && (!next.isAdmin && u.isAdmin || next.disabled) then Res.invalid("自分の管理者の権限を外したり、自分を無効にしたりはできません")
            // メールアドレスはパスワードの再設定の宛先になるので、トークンからは変えさせない
            else if (next.email != u.email || next.emailVerified != u.emailVerified) && !p.via.isInstanceOf[Via.Web] then
              Res.forbidden("メールアドレスは画面から変えてください（API トークンでは変えられません）")
            else
              dir.users.save(next).flatMap {
                case Left(e) => Res.fail(Fail.from(e))
                case Right(saved) =>
                  val becameDisabled = saved.disabled && !u.disabled
                  r.groupIds.traverse_(gs => dir.groups.staticGroupIds(id).flatMap { cur =>
                    (gs.filterNot(cur.contains).traverse_(g => dir.groups.addMember(g, id)) *> cur.filterNot(gs.contains).traverse_(g => dir.groups.removeMember(g, id)))
                  }) *>
                    IO.whenA(becameDisabled)(revokeAll(saved)) *> dir.recomputeUser(saved) *>
                    audit.byPrincipal(c, p, if becameDisabled then "user.disable" else "user.update", audit.userTarget(saved),
                      detail = Json.obj("changes" -> diff(u, saved))) *> userDto(saved).map(Right(_))
              }
    }

  private def diff(a: User, b: User): Json =
    val pairs = List("username" -> (a.username, b.username), "name" -> (a.name, b.name), "email" -> (a.email.getOrElse(""), b.email.getOrElse("")),
      "isAdmin" -> (a.isAdmin.toString, b.isAdmin.toString), "disabled" -> (a.disabled.toString, b.disabled.toString),
      "attributes" -> (a.attributes.noSpaces, b.attributes.noSpaces))
    Json.fromFields(pairs.filter((_, v) => v._1 != v._2).map((k, v) => k -> Json.obj("from" -> v._1.asJson, "to" -> v._2.asJson)))

  /** すべてのログインを終わらせ、トークンを失効させる. */
  private def revokeAll(u: User): IO[Unit] =
    dir.revokeEverything(u, None)

  private def userDetail(u: User): IO[UserDetailDto] =
    for
      d    <- userDto(u)
      now  <- Time.now
      ls   <- sessions.loginsOfUser(u.id, now)
      ts   <- factors.tokens(u.id)
      cs   <- factors.userCerts(u.id)
      ids  <- fedStore.identitiesOf(u.id)
      fs   <- fedStore.all
      cons <- apps.consents(u.id)
      as   <- apps.all
    yield UserDetailDto(d, ls.map(Conv.session(_, None)), ts.map(Conv.token(_)), cs.map(Conv.cert),
      ids.map(i => IdentityDto(i.providerId, fs.find(_.id == i.providerId).map(_.name).getOrElse("?"), i.subject, i.email, i.lastLoginAt)),
      cons.flatMap((a, s, t) => as.find(_.id == a).map(x => ConsentDto(login.appBrief(x), s, t))))

  private def withUser(id: UUID)(f: User => IO[Response[IO]]): IO[Response[IO]] =
    dir.users.find(id).flatMap(_.fold(err(Status.NotFound, "ユーザーが見つかりません"))(f))

  // ------------------------------------------------------------------ グループ

  private def groupFrom(r: GroupReq): Either[String, (String, Option[GroupRule], Option[GroupPolicy])] =
    for
      name <- Either.cond(r.name.trim.nonEmpty && r.name.trim.length <= 200, r.name.trim, "グループ名を入力してください")
      _    <- Either.cond(r.attributes.isObject, (), "属性は JSON のオブジェクトで指定してください")
      rule <- r.rule.filterNot(_.isNull).traverse(j => j.as[GroupRule].left.map(_ => "ルールの形式が正しくありません").flatMap(GroupRule.validate))
      _    <- Either.cond(!(r.isAdmin && rule.isDefined), (), "管理者のグループには条件（動的なメンバー）を付けられません")
      _    <- IpRules.parseAll(r.policy.ip.allow ++ r.policy.ip.deny)
      pol  <- GroupPolicy.validate(r.policy)
      _    <- pol.branding.logo.traverse_(l => scala.util.Try(UUID.fromString(l)).toEither.left.map(_ => "ロゴの指定が正しくありません"))
    yield (name, rule, Option.when(!pol.isEmpty)(pol))

  // ------------------------------------------------------------------ アプリケーション

  private def appDto(a: Application): IO[AppDto] =
    (apps.oidc(a.id), apps.saml(a.id), apps.mappings(a.id), apps.accessGroups(a.id)).mapN { (o, s, ms, gs) =>
      AppDto(a.id, a.slug, a.name, a.description, a.protocol, a.enabled, a.launchUrl, a.showInPortal, login.appBrief(a).iconUrl, a.requireMfa,
        a.ipAllow, a.restrictAccess, gs, ms.map(m => MappingDto(m.name, m.expression, m.scope, m.friendlyName, m.multi)),
        o.map(c => OidcDto(c.clientId, !c.isPublic, c.redirectUris, c.postLogoutRedirectUris, c.grantTypes, c.scopes, c.consent, c.subMode,
          c.signingAlg, c.accessTokenTtl, c.idTokenTtl, c.refreshTokenTtl, c.includeGroups, c.backchannelLogoutUri)),
        s.map(x => SamlDto(x.entityId, x.acsUrl, x.acsBinding, x.sloUrl, x.nameIdFormat, x.nameIdExpr, x.signResponse, x.signAssertion,
          x.spCertificate, x.wantSignedRequests, x.sessionTtl)), Some(a.createdAt))
    }

  /** http・https の URL. */
  private def webUrl(s: String): Boolean =
    scala.util.Try(new java.net.URI(s)).toOption.exists(u => Set("http", "https").contains(Option(u.getScheme).getOrElse("")) && u.getHost != null)

  /** OIDC のリダイレクト URI（ネイティブアプリのカスタムスキームも許す. 危険なスキームは除く）. */
  private def validUrl(s: String): Boolean =
    webUrl(s) || s.matches("^[a-z][a-z0-9+.-]*:/.+") && !Set("javascript", "data", "vbscript", "file", "blob").contains(s.takeWhile(_ != ':'))

  private def validateApp(r: AppReq): Either[String, Unit] =
    for
      _ <- Either.cond(r.slug.matches("^[a-z0-9][a-z0-9-]{0,62}$"), (), "スラッグは英小文字・数字・ハイフンにしてください")
      _ <- Either.cond(r.name.trim.nonEmpty, (), "名前を入力してください")
      _ <- Either.cond(Set("oidc", "saml").contains(r.protocol), (), "プロトコルは oidc か saml です")
      _ <- IpRules.parseAll(r.ipAllow)
      _ <- r.launchUrl.filter(_.nonEmpty).traverse_(u => Either.cond(webUrl(u), (), s"起動の URL が不正です: $u"))
      _ <- r.mappings.traverse_(m => Either.cond(m.name.trim.nonEmpty, (), "属性の名前を入力してください") *>
             Expr.validate(m.expression).left.map(e => s"「${m.name}」の式: $e"))
      _ <- r.oidc.filter(_ => r.protocol == "oidc").traverse_ { o =>
             for
               _ <- o.redirectUris.find(u => !validUrl(u)).map(u => s"リダイレクト URI が不正です: $u").toLeft(())
               _ <- o.postLogoutRedirectUris.find(u => !validUrl(u)).map(u => s"ログアウト後の URI が不正です: $u").toLeft(())
               _ <- Either.cond(o.grantTypes.forall(Set("authorization_code", "refresh_token", "client_credentials").contains), (), "不明なグラントです")
               _ <- Either.cond(!o.grantTypes.contains("authorization_code") || o.redirectUris.nonEmpty, (), "リダイレクト URI を1つ以上登録してください")
               _ <- Either.cond(Set("RS256", "ES256").contains(o.signingAlg), (), "署名のアルゴリズムは RS256 か ES256 です")
               _ <- Either.cond(o.accessTokenTtl >= 60 && o.idTokenTtl >= 60 && o.refreshTokenTtl >= 60, (), "有効期間は60秒以上にしてください")
               _ <- o.backchannelLogoutUri.filter(_.nonEmpty).traverse_(u => Either.cond(webUrl(u), (), "バックチャネルの URI が不正です"))
             yield ()
           }
      _ <- Either.cond(r.protocol != "oidc" || r.oidc.isDefined, (), "OIDC の設定がありません")
      _ <- r.saml.filter(_ => r.protocol == "saml").traverse_ { s =>
             for
               _ <- Either.cond(s.entityId.trim.nonEmpty, (), "エンティティ ID を入力してください")
               _ <- Either.cond(webUrl(s.acsUrl), (), "ACS の URL が不正です")
               _ <- s.sloUrl.filter(_.nonEmpty).traverse_(u => Either.cond(webUrl(u), (), "SLO の URL が不正です"))
               _ <- Either.cond(s.signResponse || s.signAssertion, (), "応答かアサーションの少なくとも一方は署名してください")
               _ <- Expr.validate(s.nameIdExpr).left.map(e => s"NameID の式: $e")
               _ <- s.spCertificate.filter(_.trim.nonEmpty).traverse_(p => Jose.parseCerts(p))
             yield ()
           }
      _ <- Either.cond(r.protocol != "saml" || r.saml.isDefined, (), "SAML の設定がありません")
    yield ()

  private def application(id: UUID, r: AppReq, now: Instant): Application =
    Application(id, r.slug, r.name.trim, r.description, r.protocol, r.enabled, r.launchUrl.filter(_.nonEmpty), r.showInPortal, None, r.requireMfa,
      r.ipAllow.map(_.trim).filter(_.nonEmpty), r.restrictAccess, now, now)

  private def oidcCfg(id: UUID, o: OidcDto, slug: String, secret: Option[Array[Byte]]): OidcClientConfig =
    OidcClientConfig(id, o.clientId.trim.some.filter(_.nonEmpty).getOrElse(slug), secret, o.redirectUris.map(_.trim).filter(_.nonEmpty),
      o.postLogoutRedirectUris.map(_.trim).filter(_.nonEmpty), o.grantTypes, o.scopes, o.consent, o.subMode, o.signingAlg, o.accessTokenTtl,
      o.idTokenTtl, o.refreshTokenTtl, o.includeGroups, o.backchannelLogoutUri.filter(_.nonEmpty))

  private def samlCfg(id: UUID, s: SamlDto): SamlConfig =
    SamlConfig(id, s.entityId.trim, s.acsUrl.trim, s.acsBinding, s.sloUrl.filter(_.nonEmpty), s.nameIdFormat, s.nameIdExpr, s.signResponse,
      s.signAssertion, s.spCertificate.filter(_.trim.nonEmpty), s.wantSignedRequests, s.sessionTtl)

  private def mappingsOf(id: UUID, r: AppReq): List[AttrMapping] =
    r.mappings.map(m => AttrMapping(UUID.randomUUID(), id, m.name.trim, m.expression, m.scope.filter(_.nonEmpty), m.friendlyName.filter(_.nonEmpty), m.multi, 0))

  private def createApp(p: Principal, r: AppReq, c: ReqCtx): Res[AppCreatedDto] =
    validateApp(r) match
      case Left(e) => Res.invalid(e)
      case Right(_) =>
        Time.now.flatMap { now =>
          val id     = UUID.randomUUID()
          val secret = r.oidc.filter(o => r.protocol == "oidc" && o.confidential).map(_ => Crypto.randomToken(32))
          apps.create(application(id, r, now), r.oidc.filter(_ => r.protocol == "oidc").map(o => oidcCfg(id, o, r.slug, secret.map(Crypto.sha256))),
            r.saml.filter(_ => r.protocol == "saml").map(samlCfg(id, _))).flatMap {
            case Left(e) => Res.fail(Fail.from(e))
            case Right(a) =>
              apps.setMappings(id, mappingsOf(id, r)) *> apps.setAccessGroups(id, r.accessGroups) *>
                audit.byPrincipal(c, p, "app.create", audit.appTarget(a)) *> appDto(a).map(d => Right(AppCreatedDto(d, secret)))
          }
        }

  private def updateApp(p: Principal, id: UUID, r: AppReq, c: ReqCtx): Res[AppDto] =
    apps.find(id).flatMap {
      case None => Res.notFound("アプリケーションが見つかりません")
      case Some(a) =>
        validateApp(r.copy(protocol = a.protocol)) match
          case Left(e) => Res.invalid(e)
          case Right(_) =>
            val next = application(id, r.copy(protocol = a.protocol), a.createdAt)
            apps.save(next.copy(iconUpdatedAt = a.iconUpdatedAt)).flatMap {
              case Left(e) => Res.fail(Fail.from(e))
              case Right(saved) =>
                val proto: Res[Unit] = a.protocol match
                  case "oidc" =>
                    apps.oidc(id).flatMap(prev => r.oidc.fold(Res.ok(())) { o =>
                      val secret = prev.flatMap(_.secretHash)
                      apps.saveOidc(oidcCfg(id, o, r.slug, secret)).orFail.flatMap {
                        // 公開・機密の切り替え
                        case Right(_) if !o.confidential && secret.isDefined => apps.setSecret(id, None).as(Right(()))
                        case other => IO.pure(other)
                      }
                    })
                  case _ => r.saml.fold(Res.ok(()))(s => apps.saveSaml(samlCfg(id, s)).orFail)
                proto.flatMap {
                  case Left(e) => Res.fail(e)
                  case Right(_) =>
                    apps.setMappings(id, mappingsOf(id, r)) *> apps.setAccessGroups(id, r.accessGroups) *>
                      audit.byPrincipal(c, p, "app.update", audit.appTarget(saved)) *> appDto(saved).map(Right(_))
                }
            }
    }

  /** このユーザーに渡すクレーム・属性の見本. */
  private def preview(a: Application, u: User): IO[Json] =
    dir.membership(u).flatMap { m =>
      a.protocol match
        case "oidc" =>
          apps.oidc(a.id).flatMap(_.fold(IO.pure(Json.obj()))(c => claims.build(u, m, a, c, c.scopes.toSet)))
        case _ =>
          (apps.saml(a.id), apps.mappings(a.id), dir.picture(u)).flatMapN { (s, ms, pic) =>
            val ctx = Context.of(Context.user(u, m, pic), Some(a))
            IO.pure(Json.obj("nameId" -> s.map(x => Expr.render(Expr.eval(x.nameIdExpr, ctx))).asJson,
              "attributes" -> SamlMapping.attributes(ms, ctx).map(x => Json.obj("name" -> x.name.asJson, "values" -> x.values.asJson)).asJson))
          }
    }

  // ------------------------------------------------------------------ 外部の IdP

  private def fedDto(p: FederationProvider): FederationDto =
    val sync = fed.syncConfig(p).map(j => j.mapObject(_.filterKeys(k => !Set("serviceAccountJson", "clientSecret").contains(k)))
      .deepMerge(Json.obj("hasKey" -> j.hcursor.downField("serviceAccountJson").focus.orElse(j.hcursor.downField("clientSecret").focus).isDefined.asJson)))
    FederationDto(p.id, p.slug, p.kind, p.name, p.enabled, p.issuer, p.clientId, box.decrypt(p.clientSecretEnc).exists(_.nonEmpty), p.scopes,
      p.subjectClaim, p.jit, p.linkByEmail, p.allowedDomains, p.defaultGroups, p.trustMfa, p.syncEnabled, sync.getOrElse(Json.obj()),
      p.syncIntervalMin, p.lastSyncAt, p.lastSyncResult, fed.callbackUrl(p.slug))

  private def fedFrom(r: FederationReq, prev: Option[FederationProvider]): Either[String, FederationProvider] =
    for
      _ <- Either.cond(r.slug.matches("^[a-z0-9][a-z0-9-]{0,62}$"), (), "スラッグは英小文字・数字・ハイフンにしてください")
      _ <- Either.cond(Set("google", "entra", "oidc").contains(r.kind), (), "種類は google・entra・oidc です")
      _ <- Either.cond(org.http4s.Uri.fromString(r.issuer.trim).toOption.exists(u => sruru.federation.UpstreamOidc.safeEndpoint(r.issuer.trim, u)), (),
             "issuer は https:// で始まる URL にしてください")
      // issuer を変えたら、シークレットも入れ直してもらう（保存済みのシークレットを別のサーバーへ送らせない）
      _ <- Either.cond(prev.forall(p => p.issuer == r.issuer.trim.stripSuffix("/") && p.kind == r.kind) || r.clientSecret.exists(_.nonEmpty), (),
             "issuer や種類を変えたときは、クライアントシークレットも入力し直してください")
      _ <- Either.cond(r.clientId.trim.nonEmpty, (), "クライアント ID を入力してください")
      _ <- Either.cond(r.syncIntervalMin >= 5, (), "同期の間隔は5分以上にしてください")
    yield
      // シークレット・同期の設定は、送られたときだけ変える（同期の設定は秘密でない項目を前の値に重ねる）
      val prevSync = prev.flatMap(fed.syncConfig)
      val sync = r.syncConfig.filterNot(_.isNull).map(j => prevSync.fold(j)(_.deepMerge(j.dropNullValues).deepMerge(
        Json.fromFields(j.asObject.toList.flatMap(_.toList).filter((_, v) => v.asString.exists(_.nonEmpty) || !v.isString)))))
        .orElse(prevSync)
      FederationProvider(prev.map(_.id).getOrElse(UUID.randomUUID()), r.slug, r.kind, r.name.trim, r.enabled, r.issuer.trim.stripSuffix("/"),
        r.clientId.trim, r.clientSecret.filter(_.nonEmpty).map(box.encrypt).orElse(prev.map(_.clientSecretEnc)).getOrElse(box.encrypt("")),
        r.scopes, r.subjectClaim, r.jit, r.linkByEmail, r.allowedDomains.map(_.trim).filter(_.nonEmpty), r.defaultGroups, r.trustMfa, r.syncEnabled,
        sync.map(j => box.encrypt(j.noSpaces)), r.syncIntervalMin, prev.flatMap(_.lastSyncAt), prev.flatMap(_.lastSyncResult),
        prev.map(_.createdAt).getOrElse(Instant.now()))

  // ------------------------------------------------------------------ 監査ログ

  private def auditQuery(req: Request[IO]): AuditQuery =
    def instant(s: String) = scala.util.Try(Instant.parse(s)).toOption.orElse(scala.util.Try(java.time.LocalDateTime.parse(s).atZone(
      java.time.ZoneId.of("Asia/Tokyo")).toInstant).toOption).orElse(scala.util.Try(java.time.LocalDate.parse(s).atStartOfDay(
      java.time.ZoneId.of("Asia/Tokyo")).toInstant).toOption)
    AuditQuery(q(req, "q"), q(req, "action"), q(req, "actorId").flatMap(uuidParam), q(req, "targetId"), q(req, "from").flatMap(instant),
      q(req, "to").flatMap(instant), q(req, "success").map(_ == "true"), q(req, "via"), qInt(req, "limit", 100, 1000), qInt(req, "offset", 0, Int.MaxValue))

  private def auditDto(r: AuditRow): AuditDto =
    AuditDto(r.id, r.at, r.actorId, r.actorName, r.via, r.action, r.targetType, r.targetId, r.targetName, r.ip, r.userAgent, r.success, r.detail)

  private def csvCell(s: String): String =
    val t = if s.headOption.exists("=+-@".contains(_)) then "'" + s else s // 表計算ソフトでの式の実行を防ぐ
    "\"" + t.replace("\"", "\"\"") + "\""

  // ------------------------------------------------------------------ ルート

  val routes: HttpRoutes[IO] = HttpRoutes.of[IO] {
    case req @ GET -> Root / "api" / "admin" / "dashboard" =>
      admin(req) { _ =>
        for
          now   <- Time.now
          all   <- dir.users.all
          gs    <- dir.groups.all
          as    <- apps.all
          today  = now.minusSeconds(86400)
          ok    <- auditStore.countSince("login.success", today, true)
          ng    <- auditStore.countSince("login.failure", today, false)
          mfa   <- factors.usersWithTotp().map(_.size)
          recent <- auditStore.search(AuditQuery(success = Some(false), limit = 10))
          res   <- Ok(DashboardDto(all.count(!_.isService), all.count(_.disabled), all.count(_.locked(now)), gs.size, as.size, ok, ng, mfa,
                     recent._1.map(auditDto)))
        yield res
      }

    case req @ GET -> Root / "api" / "admin" / "idp-info" => admin(req)(_ => idpInfo.flatMap(Ok(_)))

    // ---------------------------------------------------------------- ユーザー
    case req @ GET -> Root / "api" / "admin" / "users" => admin(req)(_ => listUsers(req).flatMap(Ok(_)))

    case req @ POST -> Root / "api" / "admin" / "users" =>
      admin(req)(p => body[UserReq](req)(r => ctx(req).flatMap(c => okJson(createUser(p, r, c)))))

    case req @ GET -> Root / "api" / "admin" / "users" / UuidVar(id) => admin(req)(_ => withUser(id)(u => userDetail(u).flatMap(Ok(_))))

    case req @ PUT -> Root / "api" / "admin" / "users" / UuidVar(id) =>
      admin(req)(p => body[UserReq](req)(r => ctx(req).flatMap(c => okJson(updateUser(p, id, r, c)))))

    case req @ DELETE -> Root / "api" / "admin" / "users" / UuidVar(id) =>
      admin(req) { p =>
        if id == p.id then err(Status.BadRequest, "自分は削除できません")
        else withUser(id)(u => revokeAll(u) *> dir.users.delete(id) *> audited(audit, req, p, "user.delete", audit.userTarget(u)) *> NoContent())
      }

    case req @ POST -> Root / "api" / "admin" / "users" / UuidVar(id) / "password" =>
      adminWeb(req)(p => body[SetPasswordReq](req) { r =>
        withUser(id) { u =>
          if r.sendResetMail then
            ctx(req).flatMap(c => login.forgot(c, ForgotReq(u.username))) *> audited(audit, req, p, "user.password.reset_mail", audit.userTarget(u)) *>
              Ok(GeneratedPasswordDto(None))
          else
            val pw = r.password.filter(_.nonEmpty).getOrElse(dir.randomPassword)
            dir.setPassword(u, pw, r.mustChange, None).flatMap {
              case Left(e) => err(Status.BadRequest, e)
              case Right(_) =>
                dir.users.unlock(u.id) *> audited(audit, req, p, "user.password.set", audit.userTarget(u)) *>
                  Ok(GeneratedPasswordDto(Option.when(r.password.forall(_.isEmpty))(pw)))
            }
        }
      })

    case req @ POST -> Root / "api" / "admin" / "users" / UuidVar(id) / "unlock" =>
      admin(req)(p => withUser(id)(u => dir.users.unlock(id) *> audited(audit, req, p, "user.unlock", audit.userTarget(u)) *> NoContent()))

    case req @ POST -> Root / "api" / "admin" / "users" / UuidVar(id) / "reset-mfa" =>
      adminWeb(req)(p => withUser(id)(u => factors.resetMfa(id) *> audited(audit, req, p, "mfa.reset", audit.userTarget(u)) *> NoContent()))

    case req @ POST -> Root / "api" / "admin" / "users" / UuidVar(id) / "logout" =>
      admin(req)(p => withUser(id)(u => revokeAll(u) *> audited(audit, req, p, "user.logout_all", audit.userTarget(u)) *> NoContent()))

    case req @ DELETE -> Root / "api" / "admin" / "users" / UuidVar(id) / "sessions" / UuidVar(sid) =>
      admin(req)(p => withUser(id)(u => sessions.login(sid).flatMap {
        case Some(l) if l.userId == id =>
          sessions.deleteLogin(sid) *> dir.endLogin(u.id, sid) *> audited(audit, req, p, "session.revoke", audit.userTarget(u)) *> NoContent()
        case _ => err(Status.NotFound, "見つかりません")
      }))

    case req @ DELETE -> Root / "api" / "admin" / "users" / UuidVar(id) / "consents" / UuidVar(appId) =>
      admin(req)(p => withUser(id)(u => apps.deleteConsent(id, appId) *> tokens.revokeUser(id, Some(appId)) *>
        audited(audit, req, p, "consent.revoke", audit.userTarget(u), Json.obj("app" -> appId.asJson)) *> NoContent()))

    case req @ POST -> Root / "api" / "admin" / "users" / UuidVar(id) / "avatar" =>
      admin(req)(p => withUser(id)(u => Conv.readImage(req, cfg.maxAvatarBytes).flatMap {
        case Left(e)    => err(Status.BadRequest, e)
        case Right(img) => dir.users.setAvatar(id, Some(img)) *> audited(audit, req, p, "user.avatar.update", audit.userTarget(u)) *> NoContent()
      }))

    case req @ DELETE -> Root / "api" / "admin" / "users" / UuidVar(id) / "avatar" =>
      admin(req)(p => withUser(id)(u => dir.users.setAvatar(id, None) *> audited(audit, req, p, "user.avatar.remove", audit.userTarget(u)) *> NoContent()))

    case req @ POST -> Root / "api" / "admin" / "users" / UuidVar(id) / "certs" =>
      adminWeb(req)(p => body[CertReq](req)(r => withUser(id)(u =>
        okJson(me.addCert(id, r.pem).flatTap(_.traverse_(x => audited(audit, req, p, "cert.add", audit.userTarget(u), Json.obj("subject" -> x.subject.asJson))))))))

    case req @ DELETE -> Root / "api" / "admin" / "users" / UuidVar(id) / "certs" / UuidVar(cid) =>
      adminWeb(req)(p => factors.deleteUserCert(cid, Some(id)).flatMap(ok =>
        if ok then audited(audit, req, p, "cert.remove", Some(("user", id.toString, ""))) *> NoContent() else err(Status.NotFound, "見つかりません")))

    case req @ POST -> Root / "api" / "admin" / "users" / UuidVar(id) / "tokens" =>
      adminWeb(req)(p => body[TokenReq](req)(r => withUser(id)(u => ctx(req).flatMap { c =>
        val scopes = r.scopes.filter(TokenScopes.all.contains).distinct
        if r.name.trim.isEmpty || scopes.isEmpty then err(Status.BadRequest, "名前とスコープを指定してください")
        else
          Time.now.flatMap { now =>
            val (t, prefix) = ApiTokens.generate()
            factors.createToken(u.id, r.name.trim, prefix, Crypto.sha256(t), scopes, r.days.filter(_ > 0).map(d => now.plusSeconds(d.toLong * 86400)))
              .flatTap(tk => audit.byPrincipal(c, p, "token.create", Some(("token", tk.id.toString, tk.name)),
                detail = Json.obj("owner" -> u.username.asJson, "scopes" -> scopes.asJson)))
              .flatMap(tk => Ok(CreatedTokenDto(t, Conv.token(tk))))
          }
      })))

    // ---------------------------------------------------------------- グループ
    case req @ GET -> Root / "api" / "admin" / "groups" =>
      admin(req)(_ => (dir.groups.all, dir.groups.memberCounts).flatMapN((gs, cs) => Ok(gs.map(g => dir.groupDto(g, cs.getOrElse(g.id, 0))))))

    case req @ POST -> Root / "api" / "admin" / "groups" =>
      admin(req)(p => body[GroupReq](req) { r =>
        groupFrom(r) match
          case Left(e) => err(Status.BadRequest, e)
          case Right((name, rule, pol)) =>
            dir.groups.create(NewGroup(name, r.description, r.parentId, r.attributes, r.isAdmin, rule, priority = r.priority, policy = pol)).flatMap {
              case Left(e) => fail(Fail.from(e))
              case Right(g) => dir.recomputeGroup(g) *> audited(audit, req, p, "group.create", audit.groupTarget(g)) *> Ok(dir.groupDto(g, 0))
            }
      })

    case req @ GET -> Root / "api" / "admin" / "groups" / UuidVar(id) =>
      admin(req)(_ => dir.groups.find(id).flatMap(_.fold(err(Status.NotFound, "グループが見つかりません"))(g =>
        dir.groups.effectiveMembers(id).flatMap(ms => Ok(dir.groupDto(g, ms.size))))))

    case req @ PUT -> Root / "api" / "admin" / "groups" / UuidVar(id) =>
      admin(req)(p => body[GroupReq](req) { r =>
        dir.groups.find(id).flatMap {
          case None => err(Status.NotFound, "グループが見つかりません")
          case Some(g) =>
            groupFrom(r) match
              case Left(e) => err(Status.BadRequest, e)
              case Right((name, rule, pol)) =>
                dir.groups.save(g.copy(name = name, description = r.description, parentId = r.parentId.filterNot(_ == id), attributes = r.attributes,
                  isAdmin = r.isAdmin, rule = rule, priority = r.priority, policy = pol)).flatMap {
                  case Left(e) => fail(Fail.from(e))
                  case Right(saved) =>
                    dir.recomputeGroup(saved) *> audited(audit, req, p, "group.update", audit.groupTarget(saved),
                      Json.obj("priority" -> saved.priority.asJson, "policy" -> saved.policy.asJson)) *>
                      dir.groups.effectiveMembers(id).flatMap(ms => Ok(dir.groupDto(saved, ms.size)))
                }
        }
      })

    case req @ DELETE -> Root / "api" / "admin" / "groups" / UuidVar(id) =>
      admin(req)(p => dir.groups.find(id).flatMap(_.fold(err(Status.NotFound, "グループが見つかりません"))(g =>
        dir.groups.delete(id) *> audited(audit, req, p, "group.delete", audit.groupTarget(g)) *> NoContent())))

    case req @ GET -> Root / "api" / "admin" / "groups" / UuidVar(id) / "members" =>
      admin(req) { _ =>
        for
          p   <- policies.get
          d   <- dir.groups.members(id).flatMap(dir.users.findMany)
          dy  <- dir.groups.dynamicMembers(id).flatMap(dir.users.findMany)
          eff <- dir.groups.effectiveMembers(id)
          res <- Ok(GroupMembersDto(d.sortBy(_.username).map(dir.brief(_, p.branding.gravatar)), dy.sortBy(_.username).map(dir.brief(_, p.branding.gravatar)),
                   eff.size))
        yield res
      }

    case req @ PUT -> Root / "api" / "admin" / "groups" / UuidVar(id) / "members" =>
      admin(req)(p => body[MembersReq](req)(r => dir.groups.setMembers(id, r.userIds) *>
        audited(audit, req, p, "group.members.set", Some(("group", id.toString, "")), Json.obj("count" -> r.userIds.size.asJson)) *> NoContent()))

    case req @ POST -> Root / "api" / "admin" / "groups" / UuidVar(id) / "members" =>
      admin(req)(p => body[MembersReq](req)(r => r.userIds.traverse_(u => dir.groups.addMember(id, u)) *>
        audited(audit, req, p, "group.members.add", Some(("group", id.toString, "")), Json.obj("users" -> r.userIds.asJson)) *> NoContent()))

    case req @ DELETE -> Root / "api" / "admin" / "groups" / UuidVar(id) / "members" / UuidVar(uid) =>
      admin(req)(p => dir.groups.removeMember(id, uid) *>
        audited(audit, req, p, "group.members.remove", Some(("group", id.toString, "")), Json.obj("user" -> uid.asJson)) *> NoContent())

    // ---------------------------------------------------------------- 属性
    case req @ GET -> Root / "api" / "admin" / "attributes" => admin(req)(_ => dir.users.attributeDefs.flatMap(ds => Ok(ds.map(Conv.attrDef))))

    case req @ PUT -> Root / "api" / "admin" / "attributes" / key =>
      admin(req)(p => body[AttributeDefDto](req) { d =>
        if !key.matches("^[a-zA-Z_][a-zA-Z0-9_]{0,63}$") then err(Status.BadRequest, "キーは英数字と _ にしてください（先頭は英字か _）")
        else if !AttrKinds.all.exists(_._1 == d.kind) then err(Status.BadRequest, "種類が正しくありません")
        else dir.users.putAttributeDef(AttributeDef(key, d.label.trim.some.filter(_.nonEmpty).getOrElse(key), d.kind, d.description, d.userEditable,
          d.required, d.scimPath.filter(_.nonEmpty), d.sort)) *> audited(audit, req, p, "attribute.define", Some(("attribute", key, d.label))) *> NoContent()
      })

    case req @ DELETE -> Root / "api" / "admin" / "attributes" / key =>
      admin(req)(p => dir.users.deleteAttributeDef(key) *> audited(audit, req, p, "attribute.delete", Some(("attribute", key, ""))) *> NoContent())

    // ---------------------------------------------------------------- アプリケーション
    case req @ GET -> Root / "api" / "admin" / "apps" => admin(req)(_ => apps.all.flatMap(_.traverse(appDto)).flatMap(Ok(_)))

    case req @ POST -> Root / "api" / "admin" / "apps" =>
      admin(req)(p => body[AppReq](req)(r => ctx(req).flatMap(c => okJson(createApp(p, r, c)))))

    case req @ GET -> Root / "api" / "admin" / "apps" / UuidVar(id) =>
      admin(req)(_ => apps.find(id).flatMap(_.fold(err(Status.NotFound, "アプリケーションが見つかりません"))(a => appDto(a).flatMap(Ok(_)))))

    case req @ PUT -> Root / "api" / "admin" / "apps" / UuidVar(id) =>
      admin(req)(p => body[AppReq](req)(r => ctx(req).flatMap(c => okJson(updateApp(p, id, r, c)))))

    case req @ DELETE -> Root / "api" / "admin" / "apps" / UuidVar(id) =>
      admin(req)(p => apps.find(id).flatMap(_.fold(err(Status.NotFound, "アプリケーションが見つかりません"))(a =>
        apps.delete(id) *> audited(audit, req, p, "app.delete", audit.appTarget(a)) *> NoContent())))

    case req @ POST -> Root / "api" / "admin" / "apps" / UuidVar(id) / "secret" =>
      admin(req)(p => apps.find(id).flatMap {
        case Some(a) if a.protocol == "oidc" =>
          val s = Crypto.randomToken(32)
          apps.setSecret(id, Some(Crypto.sha256(s))) *> audited(audit, req, p, "app.secret.rotate", audit.appTarget(a)) *> Ok(SecretDto(Some(s)))
        case _ => err(Status.NotFound, "OIDC のアプリケーションが見つかりません")
      })

    case req @ POST -> Root / "api" / "admin" / "apps" / UuidVar(id) / "icon" =>
      admin(req)(p => Conv.readImage(req, cfg.maxAvatarBytes).flatMap {
        case Left(e)    => err(Status.BadRequest, e)
        case Right(img) => apps.setIcon(id, Some(img)) *> audited(audit, req, p, "app.icon.update", Some(("application", id.toString, ""))) *> NoContent()
      })

    case req @ DELETE -> Root / "api" / "admin" / "apps" / UuidVar(id) / "icon" => admin(req)(_ => apps.setIcon(id, None) *> NoContent())

    case req @ POST -> Root / "api" / "admin" / "apps" / UuidVar(id) / "preview" =>
      admin(req)(_ => body[PreviewReq](req)(r => (apps.find(id), dir.users.find(r.userId)).tupled.flatMap {
        case (Some(a), Some(u)) => preview(a, u).flatMap(Ok(_))
        case _                  => err(Status.NotFound, "アプリケーションかユーザーが見つかりません")
      }))

    case req @ POST -> Root / "api" / "admin" / "saml" / "parse-metadata" =>
      admin(req)(_ => req.bodyText.compile.string.flatMap(xml => Saml.parseSpMetadata(xml) match
        case Left(e) => err(Status.BadRequest, e)
        case Right(m) =>
          Ok(SamlDto(entityId = m.entityId, acsUrl = m.acsUrl.getOrElse(""), acsBinding = m.acsBinding.getOrElse("post"), sloUrl = m.sloUrl,
            spCertificate = m.certificatePem))))

    case req @ POST -> Root / "api" / "admin" / "expr" / "test" =>
      admin(req)(_ => body[Json](req) { j =>
        val c = j.hcursor
        (c.get[String]("expression").toOption, c.get[String]("userId").toOption.flatMap(uuidParam)) match
          case (Some(e), Some(uid)) =>
            Expr.validate(e) match
              case Left(msg) => Ok(Json.obj("error" -> msg.asJson))
              case Right(_) =>
                dir.users.find(uid).flatMap(_.fold(err(Status.NotFound, "ユーザーが見つかりません"))(u =>
                  dir.context(u).flatMap((ctx, _) => Ok(Json.obj("value" -> Expr.eval(e, Context.of(ctx, None)))))))
          case _ => err(Status.BadRequest, "expression と userId を指定してください")
      })

    // ---------------------------------------------------------------- ポリシー
    case req @ GET -> Root / "api" / "admin" / "policies" => admin(req)(_ => policies.get.flatMap(Ok(_)))

    case req @ PUT -> Root / "api" / "admin" / "policies" =>
      admin(req)(p => body[PoliciesDto](req) { np =>
        val checks = List(
          IpRules.parseAll(np.ip.allow), IpRules.parseAll(np.ip.deny), IpRules.parseAll(np.ip.adminAllow), IpRules.parseAll(np.ip.trustedProxies)
        ).collectFirst { case Left(e) => e }
          .orElse(Option.when(np.branding.logo.exists(l => scala.util.Try(UUID.fromString(l)).isFailure))("ロゴの指定が正しくありません"))
          .orElse(Option.when(np.password.minLength < 4)("パスワードの最小の長さは4以上にしてください"))
          .orElse(Option.when(np.audit.retentionDays != 0 && np.audit.retentionDays < 30)(
            "監査ログの保存期間は30日以上（または 0 で消さない）にしてください"))
          .orElse(Option.when(!Set("off", "optional", "required").contains(np.mfa.mode))("多要素認証のモードが正しくありません"))
          .orElse(Option.when(np.session.lifetimeHours < 1)("ログインの有効期間は1時間以上にしてください"))
        checks match
          case Some(e) => err(Status.BadRequest, e)
          case None =>
            ctx(req).flatMap { c =>
              // 自分を締め出す管理画面の IP 制限は受け付けない
              if np.ip.adminAllow.nonEmpty && !IpRules.matches(c.ip, np.ip.adminAllow) then
                err(Status.BadRequest, s"いまの IP アドレス（${c.ip}）が管理画面の許可に含まれていません")
              else
                // allowAlso はユーザーに効くポリシーを計算したときだけのもの（全体には保存しない）
                policies.get.flatMap(old => policies.put(np.copy(ip = np.ip.copy(allowAlso = Nil))) *>
                  audit.byPrincipal(c, p, "policies.update", detail = Json.obj("before" -> old.asJson, "after" -> np.asJson))) *> NoContent()
            }
      })

    // ---------------------------------------------------------------- ロゴ（全体・グループのブランド）
    case req @ POST -> Root / "api" / "admin" / "logos" =>
      admin(req)(p => Conv.readImage(req, MaxLogoBytes, allowSvg = true).flatMap {
        case Left(e) => err(Status.BadRequest, e)
        case Right((bytes, ct)) =>
          settings.addLogo(bytes, ct).flatMap(id => audited(audit, req, p, "branding.logo.upload", Some(("logo", id.toString, ""))) *>
            Ok(Json.obj("id" -> id.toString.asJson, "url" -> Branding.logoUrl(Some(id.toString)).asJson)))
      })

    // ---------------------------------------------------------------- 外部の IdP
    case req @ GET -> Root / "api" / "admin" / "federation" => admin(req)(_ => fedStore.all.flatMap(fs => Ok(fs.map(fedDto))))

    case req @ POST -> Root / "api" / "admin" / "federation" =>
      admin(req)(p => body[FederationReq](req)(r => fedFrom(r, None) match
        case Left(e) => err(Status.BadRequest, e)
        case Right(f) =>
          fedStore.create(f).flatMap {
            case Left(e) => fail(Fail.from(e))
            case Right(x) => audited(audit, req, p, "federation.create", Some(("federation", x.id.toString, x.slug))) *> Ok(fedDto(x))
          }))

    case req @ PUT -> Root / "api" / "admin" / "federation" / UuidVar(id) =>
      admin(req)(p => body[FederationReq](req)(r => fedStore.find(id).flatMap {
        case None => err(Status.NotFound, "見つかりません")
        case Some(prev) =>
          fedFrom(r, Some(prev)) match
            case Left(e) => err(Status.BadRequest, e)
            case Right(f) =>
              fedStore.save(f).flatMap {
                case Left(e) => fail(Fail.from(e))
                case Right(_) => audited(audit, req, p, "federation.update", Some(("federation", id.toString, f.slug))) *> Ok(fedDto(f))
              }
      }))

    case req @ DELETE -> Root / "api" / "admin" / "federation" / UuidVar(id) =>
      admin(req)(p => fedStore.delete(id) *> audited(audit, req, p, "federation.delete", Some(("federation", id.toString, ""))) *> NoContent())

    case req @ POST -> Root / "api" / "admin" / "federation" / UuidVar(id) / "sync" =>
      admin(req)(p => fedStore.find(id).flatMap {
        case None => err(Status.NotFound, "見つかりません")
        case Some(f) => ctx(req).flatMap(c => fed.sync(f, Some(p.user), c)).flatMap(m => Ok(SyncResultDto(m)))
      })

    // ---------------------------------------------------------------- 証明書
    case req @ GET -> Root / "api" / "admin" / "cert-authorities" =>
      admin(req)(_ => factors.authorities.flatMap(cs => Ok(cs.map { a =>
        val c = Jose.parseCerts(a.pem).toOption.flatMap(_.headOption)
        CertAuthorityDto(a.id, a.name, c.map(_.getSubjectX500Principal.getName).getOrElse("?"), c.map(_.getNotAfter.toInstant), a.enabled, a.createdAt)
      })))

    case req @ POST -> Root / "api" / "admin" / "cert-authorities" =>
      admin(req)(p => body[CertAuthorityReq](req)(r => Jose.parseCerts(r.pem) match
        case Left(e) => err(Status.BadRequest, e)
        case Right(cs) =>
          factors.addAuthority(r.name.trim.some.filter(_.nonEmpty).getOrElse(cs.head.getSubjectX500Principal.getName), r.pem.trim).flatMap { a =>
            audited(audit, req, p, "cert_authority.add", Some(("cert_authority", a.id.toString, a.name))) *>
              Ok(CertAuthorityDto(a.id, a.name, cs.head.getSubjectX500Principal.getName, Some(cs.head.getNotAfter.toInstant), true, a.createdAt))
          }))

    case req @ DELETE -> Root / "api" / "admin" / "cert-authorities" / UuidVar(id) =>
      admin(req)(p => factors.deleteAuthority(id) *> audited(audit, req, p, "cert_authority.delete", Some(("cert_authority", id.toString, ""))) *> NoContent())

    // ---------------------------------------------------------------- トークン・鍵
    case req @ GET -> Root / "api" / "admin" / "tokens" =>
      admin(req)(_ => (factors.allTokens, policies.get).flatMapN((ts, p) => dir.users.findMany(ts.map(_.userId).distinct).flatMap(us =>
        Ok(ts.map(t => Conv.token(t, us.find(_.id == t.userId).map(dir.brief(_, p.branding.gravatar))))))))

    case req @ DELETE -> Root / "api" / "admin" / "tokens" / UuidVar(id) =>
      admin(req)(p => factors.deleteToken(id, None) *> audited(audit, req, p, "token.delete", Some(("token", id.toString, ""))) *> NoContent())

    case req @ GET -> Root / "api" / "admin" / "keys" =>
      admin(req)(_ => tokens.keys.flatMap(ks => Ok(ks.map(k => KeyDto(k.kid, k.alg, k.active, k.createdAt, k.retiredAt)))))

    case req @ POST -> Root / "api" / "admin" / "keys" / "rotate" =>
      admin(req) { p =>
        val alg = q(req, "alg").filter(Set("RS256", "ES256")).getOrElse("RS256")
        keys.rotate(alg).flatMap(k => audited(audit, req, p, "key.rotate", Some(("key", k.kid, alg))) *>
          Ok(KeyDto(k.kid, k.alg, k.active, k.createdAt, k.retiredAt)))
      }

    case req @ DELETE -> Root / "api" / "admin" / "keys" / kid =>
      admin(req)(p => keys.retire(kid).flatMap(ok =>
        if ok then audited(audit, req, p, "key.retire", Some(("key", kid, ""))) *> NoContent()
        else err(Status.BadRequest, "使用中の鍵は退役できません（先に入れ替えてください）")))

    // ---------------------------------------------------------------- 監査ログ
    case req @ GET -> Root / "api" / "admin" / "audit" =>
      admin(req)(_ => auditStore.search(auditQuery(req)).flatMap((rows, total) => Ok(AuditListDto(rows.map(auditDto), total))))

    case req @ GET -> Root / "api" / "admin" / "audit.csv" =>
      admin(req) { p =>
        val header = "id,at,actor,via,action,target_type,target_id,target_name,ip,user_agent,success,detail\n"
        val rows = auditStore.stream(auditQuery(req).copy(limit = Int.MaxValue)).map { r =>
          List(r.id.toString, r.at.toString, r.actorName.getOrElse(""), r.via, r.action, r.targetType.getOrElse(""), r.targetId.getOrElse(""),
            r.targetName.getOrElse(""), r.ip.getOrElse(""), r.userAgent.getOrElse(""), r.success.toString, r.detail.noSpaces).map(csvCell).mkString(",") + "\n"
        }
        audited(audit, req, p, "audit.export", None) *>
          IO.pure(Response[IO](Status.Ok).withEntity((fs2.Stream.emit("﻿" + header) ++ rows).through(fs2.text.utf8.encode))
            .withContentType(`Content-Type`(MediaType.text.csv, Charset.`UTF-8`))
            .putHeaders("Content-Disposition" -> "attachment; filename=\"sruru-audit.csv\"", "Cache-Control" -> "no-store"))
      }

    case req @ POST -> Root / "api" / "admin" / "audit" / "verify" =>
      admin(req)(p => auditStore.verify.flatMap((n, broken) =>
        audited(audit, req, p, "audit.verify", None, Json.obj("checked" -> n.asJson, "brokenAt" -> broken.asJson)) *> Ok(AuditVerifyDto(n, broken))))
  }
