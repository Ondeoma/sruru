package sruru.api

import sruru.core.ErrorCode

import sbirds.http.Errors

import sbirds.shared.AppError

import cats.effect.*
import cats.syntax.all.*
import io.circe.{Json, JsonObject}
import io.circe.syntax.*
import org.http4s.*
import org.http4s.circe.CirceEntityCodec.*
import org.http4s.headers.`Content-Type`
import sruru.core.*
import sruru.core.ScimFilter.Filter
import sruru.db.*

import java.util.UUID

/** SCIM 2.0（RFC 7643・7644）のサービスプロバイダ. 認証は scim（または admin）スコープの API トークン. */
final class ScimRoutes(dir: Directory,
                       sessions: SessionStore,
                       tokens: TokenStore,
                       policies: PolicyService,
                       audit: AuditService,
                       val auth: SessionAuth,
                       cfg: ApiConfig) extends RouteSupport {

  val routes: HttpRoutes[IO] = HttpRoutes.of[IO] {
    case req @ GET -> Root / "scim" / "v2" / "ServiceProviderConfig" => getScimV2ServiceProviderConfig(req)
    case req @ GET -> Root / "scim" / "v2" / "ResourceTypes" => getScimV2ResourceTypes(req)
    case req @ GET -> Root / "scim" / "v2" / "Schemas" => getScimV2Schemas(req)
    case req @ GET -> Root / "scim" / "v2" / "Users" => getScimV2Users(req)
    case req @ POST -> Root / "scim" / "v2" / "Users" => postScimV2Users(req)
    case req @ GET -> Root / "scim" / "v2" / "Users" / id => getScimV2User(req, id)
    case req @ PUT -> Root / "scim" / "v2" / "Users" / id => putScimV2User(req, id)
    case req @ PATCH -> Root / "scim" / "v2" / "Users" / id => patchScimV2User(req, id)
    case req @ DELETE -> Root / "scim" / "v2" / "Users" / id => deleteScimV2User(req, id)
    case req @ GET -> Root / "scim" / "v2" / "Groups" => getScimV2Groups(req)
    case req @ POST -> Root / "scim" / "v2" / "Groups" => postScimV2Groups(req)
    case req @ GET -> Root / "scim" / "v2" / "Groups" / id => getScimV2Group(req, id)
    case req @ PUT -> Root / "scim" / "v2" / "Groups" / id => putScimV2Group(req, id)
    case req @ PATCH -> Root / "scim" / "v2" / "Groups" / id => patchScimV2Group(req, id)
    case req @ DELETE -> Root / "scim" / "v2" / "Groups" / id => deleteScimV2Group(req, id)
  }

  private def getScimV2ServiceProviderConfig(req: Request[IO]): IO[Response[IO]] =
    scimAuth(req)(_ => scim(Status.Ok, serviceProviderConfig))

  private def getScimV2ResourceTypes(req: Request[IO]): IO[Response[IO]] =
    scimAuth(req)(_ => scim(Status.Ok, listResponse(resourceTypes, resourceTypes.size, 1)))

  private def getScimV2Schemas(req: Request[IO]): IO[Response[IO]] =
    scimAuth(req)(_ => schemas.flatMap(s => scim(Status.Ok, listResponse(s, s.size, 1))))

  private def getScimV2Users(req: Request[IO]): IO[Response[IO]] =
    scimAuth(req)(_ => listUsers(req))

  private def postScimV2Users(req: Request[IO]): IO[Response[IO]] =
    scimAuth(req)(p => jsonBody(req)(j => saveUser(p, req, None, j, "scim.user.create")))

  private def getScimV2User(req: Request[IO], id: String): IO[Response[IO]] =
    scimAuth(req)(_ => withUser(id)(u => userOut(u).flatMap(scim(Status.Ok, _))))

  private def putScimV2User(req: Request[IO], id: String): IO[Response[IO]] =
    scimAuth(req)(p =>
      withWritableUser(id)(u => jsonBody(req)(j => saveUser(p, req, Some(u), j, "scim.user.replace")))
    )

  private def patchScimV2User(req: Request[IO], id: String): IO[Response[IO]] =
    scimAuth(req)(p =>
      withWritableUser(id)(u =>
        jsonBody(req) { j =>
          userOut(u).flatMap(cur =>
            patch(j, cur) match {
              case Left(e) => scimErr(ErrorCode.ScimPatchInvalid, e, Some("invalidSyntax"))
              case Right(n) => saveUser(p, req, Some(u), n, "scim.user.patch")
            }
          )
        }
      )
    )

  private def deleteScimV2User(req: Request[IO], id: String): IO[Response[IO]] =
    scimAuth(req)(p =>
      withWritableUser(id)(u =>
        dir.revokeSessions(u.id) *> dir.users.delete(u.id) *>
          ctxOf(req).flatMap(c => audit.byPrincipal(c, p, "scim.user.delete", audit.userTarget(u))) *> NoContent()
      )
    )

  private def getScimV2Groups(req: Request[IO]): IO[Response[IO]] =
    scimAuth(req) { _ =>
      param(req, "filter").traverse(ScimFilter.parse) match {
        case Left(e) => scimErr(ErrorCode.ScimFilterInvalid, e, Some("invalidFilter"))
        case Right(filter) =>
          val (start, count) = paging(req)
          val excluded = param(req, "excludedAttributes").exists(_.toLowerCase.contains("members"))
          (
            dir.groups.all,
            if excluded then IO.pure(Map.empty[UUID, List[UUID]]) else dir.groups.allMembers
          ).flatMapN {
            (gs, members) =>
              dir.users.findMany(members.values.flatten.toList.distinct).map { us =>
                val byId = us.map(u => u.id -> u).toMap
                gs.map(g =>
                  if excluded then groupJson(g, Nil).mapObject(_.remove("members"))
                  else groupJson(g, members.getOrElse(g.id, Nil).flatMap(byId.get))
                )
              }
          }.flatMap { all =>
            val hits = filter.fold(all)(f => all.filter(ScimFilter.matches(f, _)))
            scim(Status.Ok, listResponse(hits.slice(start - 1, start - 1 + count), hits.size, start))
          }
      }
    }

  private def postScimV2Groups(req: Request[IO]): IO[Response[IO]] =
    scimAuth(req)(p => jsonBody(req)(j => saveGroup(p, req, None, j, "scim.group.create")))

  private def getScimV2Group(req: Request[IO], id: String): IO[Response[IO]] =
    scimAuth(req)(_ => withGroup(id)(g => groupOut(g).flatMap(scim(Status.Ok, _))))

  private def putScimV2Group(req: Request[IO], id: String): IO[Response[IO]] =
    scimAuth(req)(p =>
      withWritableGroup(id)(g => jsonBody(req)(j => saveGroup(p, req, Some(g), j, "scim.group.replace")))
    )

  private def patchScimV2Group(req: Request[IO], id: String): IO[Response[IO]] =
    scimAuth(req)(p =>
      withWritableGroup(id)(g =>
        jsonBody(req) { j =>
          groupOut(g).flatMap(cur =>
            patch(j, cur) match {
              case Left(e) => scimErr(ErrorCode.ScimPatchInvalid, e, Some("invalidSyntax"))
              case Right(n) => saveGroup(p, req, Some(g), n, "scim.group.patch")
            }
          )
        }
      )
    )

  private def deleteScimV2Group(req: Request[IO], id: String): IO[Response[IO]] =
    scimAuth(req)(p =>
      withWritableGroup(id)(g =>
        dir.groups.delete(g.id) *>
          ctxOf(req).flatMap(c => audit.byPrincipal(c, p, "scim.group.delete", audit.groupTarget(g))) *> NoContent()
      )
    )

  private val Base = s"${cfg.publicUrl}/scim/v2"
  private val UserSchema = "urn:ietf:params:scim:schemas:core:2.0:User"
  private val GroupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group"
  private val Enterprise = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
  private val SruruExt = "urn:sruru:params:scim:schemas:extension:2.0:User"
  private val ListSchema = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
  private val PatchSchema = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
  private val ScimType = `Content-Type`(new MediaType("application", "scim+json"), Charset.`UTF-8`)

  private def scim(status: Status, j: Json): IO[Response[IO]] =
    cfg.url.map(u => Response[IO](status).withEntity(here(j.dropNullValues, u)).withContentType(ScimType))

  /** location・$ref の URL を、要求のホスト名のものにする（中では既定のホスト名で組み立てている）. */
  private def here(j: Json, url: String): Json =
    if url == cfg.publicUrl then j
    else {
      def go(x: Json): Json = x.arrayOrObject(
        x,
        a => Json.fromValues(a.map(go)),
        o =>
          Json.fromFields(o.toIterable.map {
            case (k @ ("location" | "$ref"), v) =>
              k -> v.asString.filter(_.startsWith(Base)).fold(go(v))(s =>
                Json.fromString(s"$url/scim/v2" + s.drop(Base.length))
              )
            case (k, v) => k -> go(v)
          })
      )
      go(j)
    }

  /** SCIM の形式のエラーの応答（コード付きでログに出る. 本文は SCIM の決まりどおり）. */
  private def scimErr(code: ErrorCode,
                      detail: String | Null = null,
                      scimType: Option[String] = None): IO[Response[IO]] = {
    val e = AppError(code, Option(detail))
    Errors.log(e) *> scim(
      Status.fromInt(code.status).getOrElse(Status.BadRequest),
      Json.obj(
        "schemas" -> List("urn:ietf:params:scim:api:messages:2.0:Error").asJson,
        "status" -> code.status.toString.asJson,
        "scimType" -> scimType.asJson,
        "detail" -> e.message.asJson
      )
    )
  }

  /** SCIM の要求の認証. 要求ごとにスパンと sruru.scim.requests（method・resource・status）を残す（本文は載せない）. */
  private def scimAuth(req: Request[IO])(f: Principal => IO[Response[IO]]): IO[Response[IO]] = {
    val resource = req.pathInfo.segments.drop(2).headOption.map(_.decoded()).getOrElse("")
    sbirds.observe.Telemetry.span("scim.request", "scim.resource" -> resource)(
      auth.principal(req).flatMap {
        case Some(p) if p.canScim =>
          sbirds.observe.Telemetry.withUser(p.id.toString, p.user.username)(
            auth.adminIpAllowed(req).ifM(f(p), scimErr(ErrorCode.ScimIpDenied))
          )
        case Some(_) => scimErr(ErrorCode.ScimTokenScopeRequired)
        case None => scimErr(ErrorCode.ScimTokenRequired)
      }
    ).flatTap(r =>
      sbirds.observe.Metrics.count(
        "sruru.scim.requests",
        "method" -> req.method.name,
        "resource" -> resource,
        "status" -> r.status.code.toString
      )
    )
  }

  private def jsonBody(req: Request[IO])(f: Json => IO[Response[IO]]): IO[Response[IO]] =
    req.bodyText.compile.string.flatMap(s =>
      io.circe.parser.parse(s) match {
        case Left(_) => scimErr(ErrorCode.ScimJsonUnreadable, scimType = Some("invalidSyntax"))
        case Right(j) => f(j)
      }
    )

  private def ctxOf(req: Request[IO]): IO[ReqCtx] = auth.reqCtx(req)

  // ------------------------------------------------------------------ ユーザー

  private def userJson(u: User, m: Membership, defs: List[AttributeDef], pic: Option[String]): Json = {
    val ent = defs.flatMap(d =>
      d.scimPath.filter(_.startsWith(Enterprise + ":")).map(p => p.drop(Enterprise.length + 1) -> d.key)
    )
      .flatMap((name, key) => u.attributes.hcursor.downField(key).focus.filterNot(_.isNull).map(name -> _))
    Json.obj(
      "schemas" -> (List(UserSchema, Enterprise, SruruExt)).asJson,
      "id" -> u.id.toString.asJson,
      "externalId" -> u.externalId.asJson,
      "userName" -> u.username.asJson,
      "name" -> Json.obj(
        "formatted" -> u.name.asJson,
        "givenName" -> u.givenName.asJson,
        "familyName" -> u.familyName.asJson
      ).dropNullValues,
      "displayName" -> u.name.asJson,
      "active" -> (!u.disabled).asJson,
      // 渡すのは確認済みのアドレスだけ（確認待ちの間は以前の確認済みのアドレス）
      "emails" ->
        u.verifiedEmail.map(e =>
          List(Json.obj("value" -> e.asJson, "type" -> "work".asJson, "primary" -> true.asJson))
        ).asJson,
      "phoneNumbers" -> u.phoneNumber.map(p => List(Json.obj("value" -> p.asJson, "type" -> "work".asJson))).asJson,
      "photos" -> pic.map(p => List(Json.obj("value" -> p.asJson, "type" -> "photo".asJson))).asJson,
      "locale" -> u.locale.asJson,
      "timezone" -> u.zoneinfo.asJson,
      "groups" -> m.groups.map(g =>
        Json.obj(
          "value" -> g.id.toString.asJson,
          "display" -> g.name.asJson,
          "$ref" -> s"$Base/Groups/${g.id}".asJson
        )
      ).asJson,
      Enterprise -> Json.fromFields(ent),
      SruruExt -> Json.obj("attributes" -> u.attributes, "isAdmin" -> u.isAdmin.asJson),
      "meta" -> Json.obj(
        "resourceType" -> "User".asJson,
        "created" -> u.createdAt.toString.asJson,
        "lastModified" -> u.updatedAt.toString.asJson,
        "location" -> s"$Base/Users/${u.id}".asJson,
        "version" -> s"W/\"${u.updatedAt.toEpochMilli}\"".asJson
      )
    )
  }

  private def str(j: Json, path: String*): Option[String] =
    path.foldLeft(j)((x, k) => ScimJson.get(x, k)).asString.map(_.trim).filter(_.nonEmpty)

  /** SCIM の JSON をユーザーに反映する. */
  private def applyUser(u: User, j: Json, defs: List[AttributeDef]): Either[String, User] = {
    val emails = ScimJson.get(j, "emails").asArray.map(_.toList).getOrElse(Nil)
    val email =
      emails.find(e => ScimJson.get(e, "primary").asBoolean.contains(true)).orElse(emails.headOption).flatMap(str(
        _,
        "value"
      ))
    val phone = ScimJson.get(j, "phoneNumbers").asArray.flatMap(_.headOption).flatMap(str(_, "value"))
    val ent = ScimJson.get(j, Enterprise)
    val entAttrs = defs.flatMap(d =>
      d.scimPath.filter(_.startsWith(Enterprise + ":")).map(p =>
        d.key -> ScimJson.get(ent, p.drop(Enterprise.length + 1))
      )
    )
      .filterNot(_._2.isNull)
    val extAttrs =
      ScimJson.get(ScimJson.get(j, SruruExt), "attributes").asObject.map(Json.fromJsonObject).getOrElse(Json.obj())
    // マネージャーなどオブジェクトの値は value を使う
    val flat = entAttrs.map((k, v) => k -> (if v.isObject then ScimJson.get(v, "value") else v))
    for {
      name <- str(j, "userName").toRight("userName が必要です").flatMap(dir.validUsername)
      mail <- dir.validEmail(email)
    } yield {
      val display = str(j, "displayName").orElse(str(j, "name", "formatted"))
        .orElse((str(j, "name", "familyName").toList ++ str(j, "name", "givenName").toList).reduceOption(_ + " " +
          _)).getOrElse(name)
      val active = ScimJson.get(
        j,
        "active"
      ).asBoolean.orElse(ScimJson.get(j, "active").asString.map(_.equalsIgnoreCase("true"))).getOrElse(true)
      // SCIM で入ってきたアドレスは確認済みとして扱う. こちらが出した値（確認済みのアドレス）がそのまま返ってきたときは、
      // 変更ではないので、本人が変えて確認待ちのアドレスを消さない
      val mailed = if mail == u.verifiedEmail then u else u.withEmail(mail, verified = mail.isDefined)
      mailed.copy(
        username = name,
        name = display,
        givenName = str(j, "name", "givenName"),
        familyName = str(j, "name", "familyName"),
        disabled = !active,
        externalId = str(j, "externalId").orElse(u.externalId),
        phoneNumber = phone,
        locale = str(j, "locale"),
        zoneinfo = str(j, "timezone"),
        attributes = u.attributes.deepMerge(extAttrs).deepMerge(Json.fromFields(flat)).dropNullValues
      )
    }
  }

  private def blankUser: User = {
    val now = java.time.Instant.now()
    User(
      UUID(0, 0),
      "",
      None,
      false,
      None,
      "",
      None,
      None,
      None,
      None,
      false,
      false,
      false,
      false,
      None,
      0,
      Json.obj(),
      None,
      None,
      "scim",
      None,
      None,
      None,
      None,
      now,
      now,
      None
    )
  }

  private def userOut(u: User): IO[Json] = usersOut(List(u)).map(_.head)

  /** まとめて変換する（所属・属性の定義・設定をまとめて読む）. */
  private def usersOut(us: List[User]): IO[List[Json]] =
    (dir.groups.memberships(us.map(_.id)), dir.users.attributeDefs, policies.get).mapN {
      (ms, defs, p) =>
        us.map(u => userJson(u, ms.getOrElse(u.id, Membership(Nil)), defs, dir.pictureUrl(u, p)))
    }

  private def listResponse(items: List[Json], total: Int, start: Int): Json =
    Json.obj(
      "schemas" -> List(ListSchema).asJson,
      "totalResults" -> total.asJson,
      "startIndex" -> start.asJson,
      "itemsPerPage" -> items.size.asJson,
      "Resources" -> items.asJson
    )

  private def paging(req: Request[IO]): (Int, Int) =
    (
      param(req, "startIndex").flatMap(_.toIntOption).map(math.max(1, _)).getOrElse(1),
      param(req, "count").flatMap(_.toIntOption).map(n => math.max(0, math.min(n, 1000))).getOrElse(100)
    )

  private def listUsers(req: Request[IO]): IO[Response[IO]] =
    param(req, "filter").traverse(ScimFilter.parse) match {
      case Left(e) => scimErr(ErrorCode.ScimFilterInvalid, e, Some("invalidFilter"))
      case Right(filter) =>
        val (start, count) = paging(req)
        val candidates: IO[List[User]] = filter.flatMap(ScimFilter.simpleEq) match {
          case Some(("username", v)) => dir.users.byUsername(v).map(_.toList)
          case Some(("externalid", v)) => dir.users.all.map(_.filter(_.externalId.contains(v)))
          case _ => dir.users.all
        }
        candidates.map(_.filterNot(_.isService)).flatMap(usersOut).flatMap { all =>
          val hits = filter.fold(all)(f => all.filter(ScimFilter.matches(f, _)))
          scim(Status.Ok, listResponse(hits.slice(start - 1, start - 1 + count), hits.size, start))
        }
    }

  private def saveUser(p: Principal, req: Request[IO], prev: Option[User], j: Json, action: String): IO[Response[IO]] =
    dir.users.attributeDefs.flatMap { defs =>
      applyUser(prev.getOrElse(blankUser), j, defs) match {
        case Left(e) => scimErr(ErrorCode.ScimValueInvalid, e, Some("invalidValue"))
        case Right(u) =>
          val pw = str(j, "password")
          val created: IO[Either[AppError, User]] = prev match {
            case Some(_) => dir.users.save(u)
            case None =>
              dir.users.create(NewUser(
                u.username,
                u.email,
                u.name,
                source = "scim",
                externalId = u.externalId
              )).flatMap {
                case Left(e) => IO.pure(Left(e))
                case Right(nu) => dir.users.save(u.copy(id = nu.id, source = nu.source, createdAt = nu.createdAt))
              }
          }
          created.flatMap {
            case Left(e) if e.status == 409 => scimErr(ErrorCode.ScimUniqueness, e.message, Some("uniqueness"))
            case Left(e) => scimErr(ErrorCode.ScimSaveRejected, e.message)
            case Right(saved) =>
              for {
                pwRes <- pw.traverse(x => dir.setPassword(saved, x, mustChange = false, keepLogin = None))
                _ <- IO.whenA(saved.disabled && !prev.exists(_.disabled))(
                  dir.revokeEverything(saved, None)
                )
                _ <- dir.recomputeUser(saved)
                c <- ctxOf(req)
                _ <- audit.byPrincipal(c, p, action, audit.userTarget(saved))
                out <- userOut(saved)
                res <- pwRes.flatMap(_.left.toOption) match {
                  case Some(e) => scimErr(ErrorCode.ScimPasswordInvalid, s"パスワード: $e", Some("invalidValue"))
                  case None => scim(if prev.isEmpty then Status.Created else Status.Ok, out)
                }
              } yield res
          }
      }
    }

  private def withUser(id: String)(f: User => IO[Response[IO]]): IO[Response[IO]] =
    uuidParam(id).fold(IO.pure(Option.empty[User]))(dir.users.find).flatMap {
      case Some(u) if !u.isService => f(u)
      case _ => scimErr(ErrorCode.ScimUserNotFound, s"ユーザー $id が見つかりません")
    }

  private def patch(j: Json, base: Json): Either[String, Json] =
    ScimJson.get(
      j,
      "Operations"
    ).asArray.toRight("Operations がありません").flatMap(_.toList.foldLeft[Either[String, Json]](Right(base)) {
      (acc, op) =>
        acc.flatMap(r =>
          ScimJson.applyOp(r, str(op, "op").getOrElse("").toLowerCase, str(op, "path"), ScimJson.get(op, "value"))
        )
    })

  // ------------------------------------------------------------------ グループ

  private def groupJson(g: Group, members: List[User]): Json =
    Json.obj(
      "schemas" -> List(GroupSchema).asJson,
      "id" -> g.id.toString.asJson,
      "externalId" -> g.externalId.asJson,
      "displayName" -> g.name.asJson,
      "members" -> members.map(u =>
        Json.obj(
          "value" -> u.id.toString.asJson,
          "display" -> u.username.asJson,
          "$ref" -> s"$Base/Users/${u.id}".asJson
        )
      ).asJson,
      "meta" -> Json.obj(
        "resourceType" -> "Group".asJson,
        "created" -> g.createdAt.toString.asJson,
        "lastModified" -> g.updatedAt.toString.asJson,
        "location" -> s"$Base/Groups/${g.id}".asJson
      )
    )

  private def groupOut(g: Group): IO[Json] = dir.groups.members(g.id).flatMap(dir.users.findMany).map(groupJson(g, _))

  private def memberIds(j: Json): List[UUID] =
    ScimJson.get(j, "members").asArray.toList.flatten.flatMap(m => str(m, "value")).flatMap(uuidParam)

  private def saveGroup(p: Principal,
                        req: Request[IO],
                        prev: Option[Group],
                        j: Json,
                        action: String): IO[Response[IO]] =
    str(j, "displayName") match {
      case None => scimErr(ErrorCode.ScimDisplayNameRequired, scimType = Some("invalidValue"))
      case Some(name) =>
        val saved: IO[Either[AppError, Group]] = prev match {
          case Some(g) => dir.groups.save(g.copy(name = name, externalId = str(j, "externalId").orElse(g.externalId)))
          case None => dir.groups.create(NewGroup(name, source = "scim", externalId = str(j, "externalId")))
        }
        saved.flatMap {
          case Left(e) if e.status == 409 => scimErr(ErrorCode.ScimUniqueness, e.message, Some("uniqueness"))
          case Left(e) => scimErr(ErrorCode.ScimSaveRejected, e.message)
          case Right(g) =>
            val ids = memberIds(j)
            (dir.users.findMany(ids), dir.groups.members(g.id)).tupled.flatMap {
              (requested, current) =>
                // 管理者の所属は SCIM では変えない（加えも外しもしない. 漏れた SCIM のトークンで管理者を締め出したり、権限を変えたりさせない）
                val touched = (requested.map(_.id) ++ current).distinct
                dir.users.findMany(touched).flatMap(
                  _.filterA(u => dir.membership(u).map(m => dir.isAdmin(u, m)))
                ).map(_.map(_.id).toSet).flatMap { admins =>
                  val next = requested.map(_.id).filterNot(admins) ++ current.filter(admins)
                  val us = requested.filterNot(u => admins(u.id))
                  dir.groups.setMembers(g.id, next.distinct) *> dir.groups.touch(g.id, java.time.Instant.now()) *>
                    ctxOf(req).flatMap(c =>
                      audit.byPrincipal(
                        c,
                        p,
                        action,
                        audit.groupTarget(g),
                        detail = Json.obj("members" -> us.size.asJson)
                      )
                    ) *>
                    groupOut(g).flatMap(scim(if prev.isEmpty then Status.Created else Status.Ok, _))
                }
            }
        }
    }

  /** 変更してよいユーザー（管理者は SCIM では変えない. 漏れた SCIM のトークンで管理者を乗っ取ったり締め出したりできないように）. */
  private def withWritableUser(id: String)(f: User => IO[Response[IO]]): IO[Response[IO]] =
    withUser(id)(u =>
      dir.membership(u).flatMap(m =>
        if dir.isAdmin(u, m) then scimErr(ErrorCode.ScimAdminUserImmutable, scimType = Some("mutability")) else f(u)
      )
    )

  /** 変更してよいグループ（管理者になるグループは SCIM では変えない）. */
  private def withWritableGroup(id: String)(f: Group => IO[Response[IO]]): IO[Response[IO]] =
    withGroup(id)(g =>
      dir.groups.all.flatMap(all =>
        if Membership.expand(List(g.id), all.map(x => x.id -> x).toMap).isAdmin then
          scimErr(ErrorCode.ScimAdminGroupImmutable, scimType = Some("mutability"))
        else f(g)
      )
    )

  private def withGroup(id: String)(f: Group => IO[Response[IO]]): IO[Response[IO]] =
    uuidParam(id).fold(IO.pure(Option.empty[Group]))(dir.groups.find).flatMap(_.fold(scimErr(
      ErrorCode.ScimGroupNotFound,
      s"グループ $id が見つかりません"
    ))(f))

  // ------------------------------------------------------------------ 仕様の情報

  private val serviceProviderConfig = Json.obj(
    "schemas" -> List("urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig").asJson,
    "documentationUri" -> "https://github.com/Ondeoma/sruru".asJson,
    "patch" -> Json.obj("supported" -> true.asJson),
    "bulk" -> Json.obj("supported" -> false.asJson, "maxOperations" -> 0.asJson, "maxPayloadSize" -> 0.asJson),
    "filter" -> Json.obj("supported" -> true.asJson, "maxResults" -> 1000.asJson),
    "changePassword" -> Json.obj("supported" -> true.asJson),
    "sort" -> Json.obj("supported" -> false.asJson),
    "etag" -> Json.obj("supported" -> false.asJson),
    "authenticationSchemes" -> List(Json.obj(
      "type" -> "oauthbearertoken".asJson,
      "name" -> "API トークン".asJson,
      "description" -> "Authorization: Bearer sruru_…（scim スコープ）".asJson,
      "primary" -> true.asJson
    )).asJson
  )

  private def resourceTypes = List(
    Json.obj(
      "schemas" -> List("urn:ietf:params:scim:schemas:core:2.0:ResourceType").asJson,
      "id" -> "User".asJson,
      "name" -> "User".asJson,
      "endpoint" -> "/Users".asJson,
      "schema" -> UserSchema.asJson,
      "schemaExtensions" -> List(
        Json.obj("schema" -> Enterprise.asJson, "required" -> false.asJson),
        Json.obj("schema" -> SruruExt.asJson, "required" -> false.asJson)
      ).asJson,
      "meta" -> Json.obj("resourceType" -> "ResourceType".asJson, "location" -> s"$Base/ResourceTypes/User".asJson)
    ),
    Json.obj(
      "schemas" -> List("urn:ietf:params:scim:schemas:core:2.0:ResourceType").asJson,
      "id" -> "Group".asJson,
      "name" -> "Group".asJson,
      "endpoint" -> "/Groups".asJson,
      "schema" -> GroupSchema.asJson,
      "meta" -> Json.obj("resourceType" -> "ResourceType".asJson, "location" -> s"$Base/ResourceTypes/Group".asJson)
    )
  )

  private def attr(name: String,
                   typ: String = "string",
                   multi: Boolean = false,
                   sub: List[Json] = Nil,
                   required: Boolean = false): Json =
    Json.obj(
      "name" -> name.asJson,
      "type" -> typ.asJson,
      "multiValued" -> multi.asJson,
      "required" -> required.asJson,
      "mutability" -> "readWrite".asJson,
      "returned" -> "default".asJson,
      "subAttributes" -> (if sub.isEmpty then Json.Null else sub.asJson)
    ).dropNullValues

  private def schemas: IO[List[Json]] = dir.users.attributeDefs.map { defs =>
    List(
      Json.obj(
        "id" -> UserSchema.asJson,
        "name" -> "User".asJson,
        "attributes" -> List(
          attr("userName", required = true),
          attr("name", "complex", sub = List(attr("formatted"), attr("givenName"), attr("familyName"))),
          attr("displayName"),
          attr("active", "boolean"),
          attr("emails", "complex", true, List(attr("value"), attr("type"), attr("primary", "boolean"))),
          attr("phoneNumbers", "complex", true, List(attr("value"), attr("type"))),
          attr("photos", "complex", true, List(attr("value"), attr("type"))),
          attr("locale"),
          attr("timezone"),
          attr("externalId"),
          attr("password")
        ).asJson
      ),
      Json.obj(
        "id" -> Enterprise.asJson,
        "name" -> "EnterpriseUser".asJson,
        "attributes" -> defs.flatMap(_.scimPath.filter(_.startsWith(Enterprise + ":")).map(p =>
          attr(p.drop(Enterprise.length + 1))
        )).asJson
      ),
      Json.obj(
        "id" -> SruruExt.asJson,
        "name" -> "SruruUser".asJson,
        "attributes" -> List(
          attr(
            "attributes",
            "complex",
            sub = defs.map(d =>
              attr(
                d.key,
                d.kind match {
                  case "number" =>
                    "decimal";
                  case "boolean" =>
                    "boolean";
                  case "date" =>
                    "dateTime";
                  case _ => "string"
                },
                d.kind == "list"
              )
            )
          ),
          attr("isAdmin", "boolean")
        ).asJson
      ),
      Json.obj(
        "id" -> GroupSchema.asJson,
        "name" -> "Group".asJson,
        "attributes" -> List(
          attr("displayName", required = true),
          attr("members", "complex", true, List(attr("value"), attr("display")))
        ).asJson
      )
    )
  }

  // ------------------------------------------------------------------ ルート

}
