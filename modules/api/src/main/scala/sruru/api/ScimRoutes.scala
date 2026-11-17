package sruru.api

import cats.effect.*
import cats.syntax.all.*
import io.circe.{Json, JsonObject}
import io.circe.syntax.*
import org.http4s.*
import org.http4s.circe.CirceEntityCodec.*
import org.http4s.headers.`Content-Type`
import sruru.core.*
import sruru.core.ScimFilter.{Filter, PatchPath}
import sruru.db.*

import java.util.UUID

/** SCIM の JSON の操作（PATCH の適用）. 属性名は大文字小文字を区別しない. */
object ScimJson:

  private def key(o: JsonObject, name: String): String = o.keys.find(_.equalsIgnoreCase(name)).getOrElse(name)

  def get(j: Json, name: String): Json = j.asObject.flatMap(o => o(key(o, name))).getOrElse(Json.Null)

  def set(j: Json, name: String, v: Json): Json = j.mapObject(o => o.add(key(o, name), v))

  def remove(j: Json, name: String): Json = j.mapObject(o => o.remove(key(o, name)))

  /** 複数値の属性に要素を加える（同じ value の要素は置き換える）. */
  private def addValues(cur: Json, v: Json): Json =
    val items = v.asArray.map(_.toList).getOrElse(List(v))
    val base  = cur.asArray.map(_.toList).getOrElse(if cur.isNull then Nil else List(cur))
    val merged = items.foldLeft(base) { (acc, it) =>
      val idv = get(it, "value")
      if !idv.isNull && acc.exists(x => get(x, "value") == idv) then acc.map(x => if get(x, "value") == idv then x.deepMerge(it) else x) else acc :+ it
    }
    Json.fromValues(merged)

  /** eq だけの条件から新しい要素の値を作る（emails[type eq "work"].value の追加）. */
  private def seed(f: Filter): Json = f match
    case Filter.Compare(p, "eq", v) => Json.obj(p.attr -> v)
    case Filter.And(a, b)          => seed(a).deepMerge(seed(b))
    case _                         => Json.obj()

  def applyOp(res: Json, op: String, path: Option[String], value: Json): Either[String, Json] =
    path.filter(_.trim.nonEmpty) match
      case None =>
        // パスなし: 値のオブジェクトの各キーをパスとして扱う（Entra は "name.givenName" のようなキーを送る）
        value.asObject.toRight("value はオブジェクトにしてください").flatMap(_.toList.foldLeft[Either[String, Json]](Right(res)) { case (acc, (k, v)) =>
          acc.flatMap { r =>
            if k.toLowerCase.startsWith("urn:") && v.isObject && (k.endsWith(":User") || k.endsWith(":Group")) then
              Right(set(r, k, (if get(r, k).isObject then get(r, k) else Json.obj()).deepMerge(v)))
            else applyOp(r, op, Some(k), v)
          }
        })
      case Some(p) =>
        ScimFilter.parsePatchPath(p.trim).map { pp =>
          val container = pp.attr.urn.fold(res)(u => get(res, u))
          val updated   = applyAt(container, op, pp, value)
          pp.attr.urn.fold(updated)(u => set(res, u, updated))
        }

  private def applyAt(obj: Json, op: String, pp: PatchPath, value: Json): Json =
    val attr = pp.attr.attr
    val cur  = get(obj, attr)
    (pp.filter, pp.attr.sub.orElse(pp.subAttr)) match
      case (None, None) =>
        op match
          case "remove" => remove(obj, attr)
          case "add" if cur.isArray || value.isArray => set(obj, attr, addValues(cur, value))
          case "add" if cur.isObject && value.isObject => set(obj, attr, cur.deepMerge(value))
          case _ => set(obj, attr, value)
      case (None, Some(sub)) =>
        if cur.isArray then
          // 複数値の属性の副属性: 主の要素（なければ最初の要素）に適用する
          val arr = cur.asArray.get.toList
          val idx = arr.indexWhere(x => get(x, "primary").asBoolean.contains(true)) match { case -1 => 0; case i => i }
          val next = if arr.isEmpty then List(if op == "remove" then Json.obj() else Json.obj(sub -> value))
            else arr.zipWithIndex.map((x, i) => if i == idx then (if op == "remove" then remove(x, sub) else set(x, sub, value)) else x)
          set(obj, attr, Json.fromValues(next))
        else
          val base = if cur.isObject then cur else Json.obj()
          set(obj, attr, if op == "remove" then remove(base, sub) else set(base, sub, value))
      case (Some(f), sub) =>
        val arr = cur.asArray.map(_.toList).getOrElse(Nil)
        val hit = arr.exists(ScimFilter.matches(f, _))
        val next =
          if op == "remove" then sub.fold(arr.filterNot(ScimFilter.matches(f, _)))(s => arr.map(x => if ScimFilter.matches(f, x) then remove(x, s) else x))
          else if !hit then arr :+ sub.fold(seed(f).deepMerge(value))(s => set(seed(f), s, value))
          else arr.map(x => if ScimFilter.matches(f, x) then sub.fold(x.deepMerge(value))(s => set(x, s, value)) else x)
        set(obj, attr, Json.fromValues(next))

/** SCIM 2.0（RFC 7643・7644）のサービスプロバイダ. 認証は scim（または admin）スコープの API トークン. */
final class ScimRoutes(dir: Directory, sessions: SessionStore, tokens: TokenStore, policies: PolicyService, audit: AuditService,
    val auth: SessionAuth, cfg: ApiConfig) extends RouteSupport:

  private val Base       = s"${cfg.publicUrl}/scim/v2"
  private val UserSchema = "urn:ietf:params:scim:schemas:core:2.0:User"
  private val GroupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group"
  private val Enterprise = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
  private val SruruExt   = "urn:sruru:params:scim:schemas:extension:2.0:User"
  private val ListSchema = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
  private val PatchSchema = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
  private val ScimType   = `Content-Type`(new MediaType("application", "scim+json"), Charset.`UTF-8`)

  private def scim(status: Status, j: Json): IO[Response[IO]] =
    IO.pure(Response[IO](status).withEntity(j.dropNullValues).withContentType(ScimType))

  private def scimErr(status: Status, detail: String, scimType: Option[String] = None): IO[Response[IO]] =
    scim(status, Json.obj("schemas" -> List("urn:ietf:params:scim:api:messages:2.0:Error").asJson, "status" -> status.code.toString.asJson,
      "scimType" -> scimType.asJson, "detail" -> detail.asJson))

  private def scimAuth(req: Request[IO])(f: Principal => IO[Response[IO]]): IO[Response[IO]] =
    auth.principal(req).flatMap {
      case Some(p) if p.canScim =>
        auth.adminIpAllowed(req).ifM(f(p), scimErr(Status.Forbidden, "この IP アドレスからは SCIM を使えません"))
      case Some(_)              => scimErr(Status.Forbidden, "scim スコープの API トークン（管理者）が必要です")
      case None                 => scimErr(Status.Unauthorized, "API トークンが必要です")
    }

  private def jsonBody(req: Request[IO])(f: Json => IO[Response[IO]]): IO[Response[IO]] =
    req.bodyText.compile.string.flatMap(s => io.circe.parser.parse(s) match
      case Left(_)  => scimErr(Status.BadRequest, "JSON を読めません", Some("invalidSyntax"))
      case Right(j) => f(j))

  private def ctxOf(req: Request[IO]): IO[ReqCtx] = auth.reqCtx(req)

  // ------------------------------------------------------------------ ユーザー

  private def userJson(u: User, m: Membership, defs: List[AttributeDef], pic: Option[String]): Json =
    val ent = defs.flatMap(d => d.scimPath.filter(_.startsWith(Enterprise + ":")).map(p => p.drop(Enterprise.length + 1) -> d.key))
      .flatMap((name, key) => u.attributes.hcursor.downField(key).focus.filterNot(_.isNull).map(name -> _))
    Json.obj(
      "schemas" -> (List(UserSchema, Enterprise, SruruExt)).asJson,
      "id" -> u.id.toString.asJson,
      "externalId" -> u.externalId.asJson,
      "userName" -> u.username.asJson,
      "name" -> Json.obj("formatted" -> u.name.asJson, "givenName" -> u.givenName.asJson, "familyName" -> u.familyName.asJson).dropNullValues,
      "displayName" -> u.name.asJson,
      "active" -> (!u.disabled).asJson,
      "emails" -> u.email.map(e => List(Json.obj("value" -> e.asJson, "type" -> "work".asJson, "primary" -> true.asJson))).asJson,
      "phoneNumbers" -> u.phoneNumber.map(p => List(Json.obj("value" -> p.asJson, "type" -> "work".asJson))).asJson,
      "photos" -> pic.map(p => List(Json.obj("value" -> p.asJson, "type" -> "photo".asJson))).asJson,
      "locale" -> u.locale.asJson,
      "timezone" -> u.zoneinfo.asJson,
      "groups" -> m.groups.map(g => Json.obj("value" -> g.id.toString.asJson, "display" -> g.name.asJson,
        "$ref" -> s"$Base/Groups/${g.id}".asJson)).asJson,
      Enterprise -> Json.fromFields(ent),
      SruruExt -> Json.obj("attributes" -> u.attributes, "isAdmin" -> u.isAdmin.asJson),
      "meta" -> Json.obj("resourceType" -> "User".asJson, "created" -> u.createdAt.toString.asJson, "lastModified" -> u.updatedAt.toString.asJson,
        "location" -> s"$Base/Users/${u.id}".asJson, "version" -> s"W/\"${u.updatedAt.toEpochMilli}\"".asJson)
    )

  private def str(j: Json, path: String*): Option[String] =
    path.foldLeft(j)((x, k) => ScimJson.get(x, k)).asString.map(_.trim).filter(_.nonEmpty)

  /** SCIM の JSON をユーザーに反映する. */
  private def applyUser(u: User, j: Json, defs: List[AttributeDef]): Either[String, User] =
    val emails = ScimJson.get(j, "emails").asArray.map(_.toList).getOrElse(Nil)
    val email  = emails.find(e => ScimJson.get(e, "primary").asBoolean.contains(true)).orElse(emails.headOption).flatMap(str(_, "value"))
    val phone  = ScimJson.get(j, "phoneNumbers").asArray.flatMap(_.headOption).flatMap(str(_, "value"))
    val ent    = ScimJson.get(j, Enterprise)
    val entAttrs = defs.flatMap(d => d.scimPath.filter(_.startsWith(Enterprise + ":")).map(p => d.key -> ScimJson.get(ent, p.drop(Enterprise.length + 1))))
      .filterNot(_._2.isNull)
    val extAttrs = ScimJson.get(ScimJson.get(j, SruruExt), "attributes").asObject.map(Json.fromJsonObject).getOrElse(Json.obj())
    // マネージャーなどオブジェクトの値は value を使う
    val flat = entAttrs.map((k, v) => k -> (if v.isObject then ScimJson.get(v, "value") else v))
    for
      name <- str(j, "userName").toRight("userName が必要です").flatMap(dir.validUsername)
      mail <- dir.validEmail(email)
    yield
      val display = str(j, "displayName").orElse(str(j, "name", "formatted"))
        .orElse((str(j, "name", "familyName").toList ++ str(j, "name", "givenName").toList).reduceOption(_ + " " + _)).getOrElse(name)
      val active = ScimJson.get(j, "active").asBoolean.orElse(ScimJson.get(j, "active").asString.map(_.equalsIgnoreCase("true"))).getOrElse(true)
      u.copy(username = name, name = display, givenName = str(j, "name", "givenName"), familyName = str(j, "name", "familyName"), email = mail,
        emailVerified = mail.isDefined, disabled = !active, externalId = str(j, "externalId").orElse(u.externalId),
        phoneNumber = phone, locale = str(j, "locale"), zoneinfo = str(j, "timezone"),
        attributes = u.attributes.deepMerge(extAttrs).deepMerge(Json.fromFields(flat)).dropNullValues)

  private def blankUser: User =
    val now = java.time.Instant.now()
    User(UUID(0, 0), "", None, false, "", None, None, None, None, false, false, false, false, None, 0, Json.obj(), None, None, "scim", None, None,
      None, None, now, now, None)

  private def userOut(u: User): IO[Json] = usersOut(List(u)).map(_.head)

  /** まとめて変換する（所属・属性の定義・設定をまとめて読む）. */
  private def usersOut(us: List[User]): IO[List[Json]] =
    (dir.groups.memberships(us.map(_.id)), dir.users.attributeDefs, policies.get).mapN { (ms, defs, p) =>
      us.map(u => userJson(u, ms.getOrElse(u.id, Membership(Nil)), defs, dir.pictureUrl(u, p.branding.gravatar)))
    }

  private def listResponse(items: List[Json], total: Int, start: Int): Json =
    Json.obj("schemas" -> List(ListSchema).asJson, "totalResults" -> total.asJson, "startIndex" -> start.asJson,
      "itemsPerPage" -> items.size.asJson, "Resources" -> items.asJson)

  private def paging(req: Request[IO]): (Int, Int) =
    (q(req, "startIndex").flatMap(_.toIntOption).map(math.max(1, _)).getOrElse(1), q(req, "count").flatMap(_.toIntOption).map(n => math.max(0, math.min(n, 1000))).getOrElse(100))

  private def listUsers(req: Request[IO]): IO[Response[IO]] =
    q(req, "filter").traverse(ScimFilter.parse) match
      case Left(e) => scimErr(Status.BadRequest, e, Some("invalidFilter"))
      case Right(filter) =>
        val (start, count) = paging(req)
        val candidates: IO[List[User]] = filter.flatMap(ScimFilter.simpleEq) match
          case Some(("username", v)) => dir.users.byUsername(v).map(_.toList)
          case Some(("externalid", v)) => dir.users.all.map(_.filter(_.externalId.contains(v)))
          case _ => dir.users.all
        candidates.map(_.filterNot(_.isService)).flatMap(usersOut).flatMap { all =>
          val hits = filter.fold(all)(f => all.filter(ScimFilter.matches(f, _)))
          scim(Status.Ok, listResponse(hits.slice(start - 1, start - 1 + count), hits.size, start))
        }

  private def saveUser(p: Principal, req: Request[IO], prev: Option[User], j: Json, action: String): IO[Response[IO]] =
    dir.users.attributeDefs.flatMap { defs =>
      applyUser(prev.getOrElse(blankUser), j, defs) match
        case Left(e) => scimErr(Status.BadRequest, e, Some("invalidValue"))
        case Right(u) =>
          val pw = str(j, "password")
          val created: IO[Either[StoreError, User]] = prev match
            case Some(_) => dir.users.save(u)
            case None =>
              dir.users.create(NewUser(u.username, u.email, u.name, source = "scim", externalId = u.externalId)).flatMap {
                case Left(e)   => IO.pure(Left(e))
                case Right(nu) => dir.users.save(u.copy(id = nu.id, source = nu.source, createdAt = nu.createdAt))
              }
          created.flatMap {
            case Left(StoreError.Conflict(m)) => scimErr(Status.Conflict, m, Some("uniqueness"))
            case Left(e) => scimErr(Status.BadRequest, e.message)
            case Right(saved) =>
              for
                pwRes <- pw.traverse(x => dir.setPassword(saved, x, mustChange = false, keepLogin = None))
                _     <- IO.whenA(saved.disabled && !prev.exists(_.disabled))(
                           dir.revokeEverything(saved, None))
                _     <- dir.recomputeUser(saved)
                c     <- ctxOf(req)
                _     <- audit.byPrincipal(c, p, action, audit.userTarget(saved))
                out   <- userOut(saved)
                res   <- pwRes.flatMap(_.left.toOption) match
                           case Some(e) => scimErr(Status.BadRequest, s"パスワード: $e", Some("invalidValue"))
                           case None    => scim(if prev.isEmpty then Status.Created else Status.Ok, out)
              yield res
          }
    }

  private def withUser(id: String)(f: User => IO[Response[IO]]): IO[Response[IO]] =
    uuidParam(id).fold(IO.pure(Option.empty[User]))(dir.users.find).flatMap {
      case Some(u) if !u.isService => f(u)
      case _                       => scimErr(Status.NotFound, s"ユーザー $id が見つかりません")
    }

  private def patch(j: Json, base: Json): Either[String, Json] =
    ScimJson.get(j, "Operations").asArray.toRight("Operations がありません").flatMap(_.toList.foldLeft[Either[String, Json]](Right(base)) { (acc, op) =>
      acc.flatMap(r => ScimJson.applyOp(r, str(op, "op").getOrElse("").toLowerCase, str(op, "path"), ScimJson.get(op, "value")))
    })

  // ------------------------------------------------------------------ グループ

  private def groupJson(g: Group, members: List[User]): Json =
    Json.obj(
      "schemas" -> List(GroupSchema).asJson,
      "id" -> g.id.toString.asJson,
      "externalId" -> g.externalId.asJson,
      "displayName" -> g.name.asJson,
      "members" -> members.map(u => Json.obj("value" -> u.id.toString.asJson, "display" -> u.username.asJson, "$ref" -> s"$Base/Users/${u.id}".asJson)).asJson,
      "meta" -> Json.obj("resourceType" -> "Group".asJson, "created" -> g.createdAt.toString.asJson, "lastModified" -> g.updatedAt.toString.asJson,
        "location" -> s"$Base/Groups/${g.id}".asJson)
    )

  private def groupOut(g: Group): IO[Json] = dir.groups.members(g.id).flatMap(dir.users.findMany).map(groupJson(g, _))

  private def memberIds(j: Json): List[UUID] =
    ScimJson.get(j, "members").asArray.toList.flatten.flatMap(m => str(m, "value")).flatMap(uuidParam)

  private def saveGroup(p: Principal, req: Request[IO], prev: Option[Group], j: Json, action: String): IO[Response[IO]] =
    str(j, "displayName") match
      case None => scimErr(Status.BadRequest, "displayName が必要です", Some("invalidValue"))
      case Some(name) =>
        val saved: IO[Either[StoreError, Group]] = prev match
          case Some(g) => dir.groups.save(g.copy(name = name, externalId = str(j, "externalId").orElse(g.externalId)))
          case None    => dir.groups.create(NewGroup(name, source = "scim", externalId = str(j, "externalId")))
        saved.flatMap {
          case Left(StoreError.Conflict(m)) => scimErr(Status.Conflict, m, Some("uniqueness"))
          case Left(e) => scimErr(Status.BadRequest, e.message)
          case Right(g) =>
            val ids = memberIds(j)
            (dir.users.findMany(ids), dir.groups.members(g.id)).tupled.flatMap { (requested, current) =>
              // 管理者の所属は SCIM では変えない（加えも外しもしない. 漏れた SCIM のトークンで管理者を締め出したり、権限を変えたりさせない）
              val touched = (requested.map(_.id) ++ current).distinct
              dir.users.findMany(touched).flatMap(_.filterA(u => dir.membership(u).map(m => dir.isAdmin(u, m)))).map(_.map(_.id).toSet).flatMap { admins =>
              val next = requested.map(_.id).filterNot(admins) ++ current.filter(admins)
              val us   = requested.filterNot(u => admins(u.id))
              dir.groups.setMembers(g.id, next.distinct) *> dir.groups.touch(g.id, java.time.Instant.now()) *>
                ctxOf(req).flatMap(c => audit.byPrincipal(c, p, action, audit.groupTarget(g), detail = Json.obj("members" -> us.size.asJson))) *>
                groupOut(g).flatMap(scim(if prev.isEmpty then Status.Created else Status.Ok, _))
              }
            }
        }

  /** 変更してよいユーザー（管理者は SCIM では変えない. 漏れた SCIM のトークンで管理者を乗っ取ったり締め出したりできないように）. */
  private def withWritableUser(id: String)(f: User => IO[Response[IO]]): IO[Response[IO]] =
    withUser(id)(u => dir.membership(u).flatMap(m =>
      if dir.isAdmin(u, m) then scimErr(Status.Forbidden, "管理者のアカウントは SCIM では変更できません", Some("mutability")) else f(u)))

  /** 変更してよいグループ（管理者になるグループは SCIM では変えない）. */
  private def withWritableGroup(id: String)(f: Group => IO[Response[IO]]): IO[Response[IO]] =
    withGroup(id)(g => dir.groups.all.flatMap(all =>
      if Membership.expand(List(g.id), all.map(x => x.id -> x).toMap).isAdmin then
        scimErr(Status.Forbidden, "管理者のグループは SCIM では変更できません", Some("mutability"))
      else f(g)))

  private def withGroup(id: String)(f: Group => IO[Response[IO]]): IO[Response[IO]] =
    uuidParam(id).fold(IO.pure(Option.empty[Group]))(dir.groups.find).flatMap(_.fold(scimErr(Status.NotFound, s"グループ $id が見つかりません"))(f))

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
    "authenticationSchemes" -> List(Json.obj("type" -> "oauthbearertoken".asJson, "name" -> "API トークン".asJson,
      "description" -> "Authorization: Bearer sruru_…（scim スコープ）".asJson, "primary" -> true.asJson)).asJson
  )

  private def resourceTypes = List(
    Json.obj("schemas" -> List("urn:ietf:params:scim:schemas:core:2.0:ResourceType").asJson, "id" -> "User".asJson, "name" -> "User".asJson,
      "endpoint" -> "/Users".asJson, "schema" -> UserSchema.asJson,
      "schemaExtensions" -> List(Json.obj("schema" -> Enterprise.asJson, "required" -> false.asJson),
        Json.obj("schema" -> SruruExt.asJson, "required" -> false.asJson)).asJson,
      "meta" -> Json.obj("resourceType" -> "ResourceType".asJson, "location" -> s"$Base/ResourceTypes/User".asJson)),
    Json.obj("schemas" -> List("urn:ietf:params:scim:schemas:core:2.0:ResourceType").asJson, "id" -> "Group".asJson, "name" -> "Group".asJson,
      "endpoint" -> "/Groups".asJson, "schema" -> GroupSchema.asJson,
      "meta" -> Json.obj("resourceType" -> "ResourceType".asJson, "location" -> s"$Base/ResourceTypes/Group".asJson))
  )

  private def attr(name: String, typ: String = "string", multi: Boolean = false, sub: List[Json] = Nil, required: Boolean = false): Json =
    Json.obj("name" -> name.asJson, "type" -> typ.asJson, "multiValued" -> multi.asJson, "required" -> required.asJson,
      "mutability" -> "readWrite".asJson, "returned" -> "default".asJson, "subAttributes" -> (if sub.isEmpty then Json.Null else sub.asJson)).dropNullValues

  private def schemas: IO[List[Json]] = dir.users.attributeDefs.map { defs =>
    List(
      Json.obj("id" -> UserSchema.asJson, "name" -> "User".asJson, "attributes" -> List(
        attr("userName", required = true), attr("name", "complex", sub = List(attr("formatted"), attr("givenName"), attr("familyName"))),
        attr("displayName"), attr("active", "boolean"), attr("emails", "complex", true, List(attr("value"), attr("type"), attr("primary", "boolean"))),
        attr("phoneNumbers", "complex", true, List(attr("value"), attr("type"))), attr("photos", "complex", true, List(attr("value"), attr("type"))),
        attr("locale"), attr("timezone"), attr("externalId"), attr("password")).asJson),
      Json.obj("id" -> Enterprise.asJson, "name" -> "EnterpriseUser".asJson,
        "attributes" -> defs.flatMap(_.scimPath.filter(_.startsWith(Enterprise + ":")).map(p => attr(p.drop(Enterprise.length + 1)))).asJson),
      Json.obj("id" -> SruruExt.asJson, "name" -> "SruruUser".asJson, "attributes" -> List(attr("attributes", "complex",
        sub = defs.map(d => attr(d.key, d.kind match { case "number" => "decimal"; case "boolean" => "boolean"; case "date" => "dateTime"; case _ => "string" },
          d.kind == "list"))), attr("isAdmin", "boolean")).asJson),
      Json.obj("id" -> GroupSchema.asJson, "name" -> "Group".asJson, "attributes" -> List(attr("displayName", required = true),
        attr("members", "complex", true, List(attr("value"), attr("display")))).asJson)
    )
  }

  // ------------------------------------------------------------------ ルート

  val routes: HttpRoutes[IO] = HttpRoutes.of[IO] {
    case req @ GET -> Root / "scim" / "v2" / "ServiceProviderConfig" => scimAuth(req)(_ => scim(Status.Ok, serviceProviderConfig))
    case req @ GET -> Root / "scim" / "v2" / "ResourceTypes" =>
      scimAuth(req)(_ => scim(Status.Ok, listResponse(resourceTypes, resourceTypes.size, 1)))
    case req @ GET -> Root / "scim" / "v2" / "Schemas" => scimAuth(req)(_ => schemas.flatMap(s => scim(Status.Ok, listResponse(s, s.size, 1))))

    case req @ GET -> Root / "scim" / "v2" / "Users" => scimAuth(req)(_ => listUsers(req))
    case req @ POST -> Root / "scim" / "v2" / "Users" => scimAuth(req)(p => jsonBody(req)(j => saveUser(p, req, None, j, "scim.user.create")))
    case req @ GET -> Root / "scim" / "v2" / "Users" / id => scimAuth(req)(_ => withUser(id)(u => userOut(u).flatMap(scim(Status.Ok, _))))
    case req @ PUT -> Root / "scim" / "v2" / "Users" / id =>
      scimAuth(req)(p => withWritableUser(id)(u => jsonBody(req)(j => saveUser(p, req, Some(u), j, "scim.user.replace"))))
    case req @ PATCH -> Root / "scim" / "v2" / "Users" / id =>
      scimAuth(req)(p => withWritableUser(id)(u => jsonBody(req) { j =>
        userOut(u).flatMap(cur => patch(j, cur) match
          case Left(e)  => scimErr(Status.BadRequest, e, Some("invalidSyntax"))
          case Right(n) => saveUser(p, req, Some(u), n, "scim.user.patch"))
      }))
    case req @ DELETE -> Root / "scim" / "v2" / "Users" / id =>
      scimAuth(req)(p => withWritableUser(id)(u =>
        dir.revokeSessions(u.id) *> dir.users.delete(u.id) *>
          ctxOf(req).flatMap(c => audit.byPrincipal(c, p, "scim.user.delete", audit.userTarget(u))) *> NoContent()))

    case req @ GET -> Root / "scim" / "v2" / "Groups" =>
      scimAuth(req) { _ =>
        q(req, "filter").traverse(ScimFilter.parse) match
          case Left(e) => scimErr(Status.BadRequest, e, Some("invalidFilter"))
          case Right(filter) =>
            val (start, count) = paging(req)
            val excluded = q(req, "excludedAttributes").exists(_.toLowerCase.contains("members"))
            (dir.groups.all, if excluded then IO.pure(Map.empty[UUID, List[UUID]]) else dir.groups.allMembers).flatMapN { (gs, members) =>
              dir.users.findMany(members.values.flatten.toList.distinct).map { us =>
                val byId = us.map(u => u.id -> u).toMap
                gs.map(g => if excluded then groupJson(g, Nil).mapObject(_.remove("members")) else groupJson(g, members.getOrElse(g.id, Nil).flatMap(byId.get)))
              }
            }.flatMap { all =>
              val hits = filter.fold(all)(f => all.filter(ScimFilter.matches(f, _)))
              scim(Status.Ok, listResponse(hits.slice(start - 1, start - 1 + count), hits.size, start))
            }
      }
    case req @ POST -> Root / "scim" / "v2" / "Groups" => scimAuth(req)(p => jsonBody(req)(j => saveGroup(p, req, None, j, "scim.group.create")))
    case req @ GET -> Root / "scim" / "v2" / "Groups" / id => scimAuth(req)(_ => withGroup(id)(g => groupOut(g).flatMap(scim(Status.Ok, _))))
    case req @ PUT -> Root / "scim" / "v2" / "Groups" / id =>
      scimAuth(req)(p => withWritableGroup(id)(g => jsonBody(req)(j => saveGroup(p, req, Some(g), j, "scim.group.replace"))))
    case req @ PATCH -> Root / "scim" / "v2" / "Groups" / id =>
      scimAuth(req)(p => withWritableGroup(id)(g => jsonBody(req) { j =>
        groupOut(g).flatMap(cur => patch(j, cur) match
          case Left(e)  => scimErr(Status.BadRequest, e, Some("invalidSyntax"))
          case Right(n) => saveGroup(p, req, Some(g), n, "scim.group.patch"))
      }))
    case req @ DELETE -> Root / "scim" / "v2" / "Groups" / id =>
      scimAuth(req)(p => withWritableGroup(id)(g => dir.groups.delete(g.id) *>
        ctxOf(req).flatMap(c => audit.byPrincipal(c, p, "scim.group.delete", audit.groupTarget(g))) *> NoContent()))
  }
