package sruru.api

import sruru.core.ErrorCode

import sbirds.shared.AppError

import sbirds.http.Errors

import cats.effect.*
import cats.syntax.all.*
import io.circe.{ACursor, Json}
import io.circe.syntax.*
import org.http4s.*
import org.typelevel.ci.CIString
import org.http4s.circe.CirceEntityCodec.*
import org.http4s.headers.Authorization
import sbirds.mcp.{McpCaller, McpServer, McpTool}
import sbirds.mcp.McpSchema.*

/**
 * MCP（Model Context Protocol）のサーバー. POST /mcp に JSON-RPC を送る（Streamable HTTP. 応答は JSON）.
 * 認証は API トークン（Bearer）だけ. 各ツールは REST API をそのトークンで内部から呼ぶので、権限・スコープ・監査ログは REST API と同じ.
 */
final class McpRoutes(api: HttpRoutes[IO], auth: SessionAuth, cfg: ApiConfig) {

  // POST /mcp（JSON-RPC）と GET・DELETE /mcp（405）は sbirds.mcp.McpServer
  lazy val routes: HttpRoutes[IO] = McpServer.routes(host)

  // ------------------------------------------------------------------ REST API の内部呼び出し

  /** 内部の要求に引き継がないヘッダー（認証は Bearer を付け直す. 本文は内部の要求のもの）. */
  private val NotForwarded =
    Set("Authorization", "Cookie", "Content-Type", "Content-Length", "Transfer-Encoding", "Host").map(CIString(_))

  /**
   * 内部の要求（外側の要求の接続元と、X-Forwarded-For・利用者のアドレスのヘッダー（ポリシーで決めた名前. CloudFront-Viewer-Address など）・
   * User-Agent を引き継ぎ、IP 制限と監査ログを外側の要求と同じにする）.
   */
  private def inner(outer: Request[IO], authz: Authorization, method: Method, uri: Uri): Request[IO] = {
    val fwd = outer.headers.headers.filterNot(h => NotForwarded(h.name))
    Request[IO](
      method,
      uri,
      attributes = outer.attributes.insert(SessionAuth.McpCall, ())
    ).putHeaders(authz).transformHeaders(_ ++ Headers(fwd))
  }

  /** REST API の内部呼び出し（外側の要求の接続元などを引き継ぐ. 本文のない成功は "OK" にする）. */
  private final class Caller(outer: Request[IO], authz: Authorization) {
    private val call = new McpCaller(
      api,
      authz,
      build = (method, uri, body) => {
        val req = inner(outer, authz, method, uri)
        body.fold(req)(req.withEntity(_))
      }
    )
    def apply(method: Method, uri: Uri, body: Option[Json] = None): IO[Either[String, Json]] =
      call(method, uri, body).map(_.map(j => if j.isNull then Json.fromString("OK") else j))
  }

  private def path(segments: String*): Uri = McpCaller.path(segments*)

  // ------------------------------------------------------------------ ツール

  private type Result = McpTool.Result
  private type Tool = McpTool[Caller]
  private def Tool(name: String, description: String, schema: Json, readOnly: Boolean, destructive: Boolean = false)(
    run: (Caller, ACursor) => Result): Tool = McpTool(name, description, schema, readOnly, destructive)(run)

  private def opt(a: ACursor, k: String): Option[String] = a.get[String](k).toOption.map(_.trim).filter(_.nonEmpty)

  /** ユーザー名・メールアドレス・ID からユーザーの ID を引く. */
  private def userId(call: Caller, who: String): IO[Either[String, String]] =
    if scala.util.Try(java.util.UUID.fromString(who)).isSuccess then IO.pure(Right(who))
    else
      call(
        Method.GET,
        path("api", "admin", "users").withQueryParam("q", who).withQueryParam("limit", "50")
      ).map(_.flatMap { j =>
        val us = j.hcursor.downField("users").as[List[Json]].getOrElse(Nil)
        us.find(u =>
          u.hcursor.get[String]("username").toOption.exists(_.equalsIgnoreCase(who)) ||
            u.hcursor.get[String]("email").toOption.exists(_.equalsIgnoreCase(who))
        )
          .flatMap(_.hcursor.get[String]("id").toOption).toRight(s"ユーザー「$who」が見つかりません")
      })

  private def groupId(call: Caller, name: String): IO[Either[String, String]] =
    if scala.util.Try(java.util.UUID.fromString(name)).isSuccess then IO.pure(Right(name))
    else
      call(Method.GET, path("api", "admin", "groups")).map(_.flatMap(_.asArray.toList.flatten
        .find(
          _.hcursor.get[String]("name").toOption.exists(_.equalsIgnoreCase(name))
        ).flatMap(_.hcursor.get[String]("id").toOption)
        .toRight(s"グループ「$name」が見つかりません")))

  /** ユーザーを読み、変更を重ねて PUT する. */
  private def patchUser(call: Caller, who: String)(f: Json => Json): IO[Either[String, Json]] =
    userId(call, who).flatMap(_.fold(
      e => IO.pure(Left(e)),
      id =>
        call(Method.GET, path("api", "admin", "users", id)).flatMap(_.fold(
          e => IO.pure(Left(e)),
          d => {
            val u = d.hcursor.downField("user").focus.getOrElse(Json.obj())
            val req = Json.obj(List(
              "username",
              "name",
              "email",
              "emailVerified",
              "givenName",
              "familyName",
              "isAdmin",
              "isService",
              "disabled",
              "mustChangePassword",
              "attributes",
              "locale",
              "zoneinfo",
              "phoneNumber"
            ).flatMap(k => u.hcursor.downField(k).focus.map(k -> _))*)
            call(Method.PUT, path("api", "admin", "users", id), Some(f(req)))
          }
        ))
    ))

  private val tools: List[Tool] = List(
    Tool("get_me", "このトークンの持ち主の情報（名前・所属グループ・多要素認証の状態）。", schema(Nil), readOnly = true) {
      (call, _) =>
        call(Method.GET, path("api", "me")).asText
    },
    Tool(
      "search_users",
      "ユーザーを探す（管理者）。q は名前・ユーザー名・メールの一部。status は active|disabled|locked|service|admin。",
      schema(Nil, "q" -> str("検索語"), "status" -> str("状態"), "group" -> str("グループ名で絞る"), "limit" -> int("件数（既定 50）")),
      readOnly = true
    ) {
      (call, a) =>
        {
          val base = path("api", "admin", "users").withQueryParam("limit", a.get[Int]("limit").getOrElse(50).toString)
          val withQ = List("q", "status").foldLeft(base)((u, k) => opt(a, k).fold(u)(v => u.withQueryParam(k, v)))
          opt(a, "group").fold(call(Method.GET, withQ))(g =>
            groupId(call, g).flatMap(_.fold(
              e => IO.pure(Left(e)),
              id => call(Method.GET, withQ.withQueryParam("groupId", id))
            ))
          ).asText
        }
    },
    Tool(
      "get_user",
      "ユーザーの詳細（所属・ログイン中の端末・トークン・外部 IdP との結び付き）。user はユーザー名・メール・ID。",
      schema(List("user"), "user" -> str("ユーザー名・メールアドレス・ID")),
      readOnly = true
    ) {
      (call, a) =>
        need(a, "user").withArgs(u =>
          userId(
            call,
            u
          ).flatMap(_.fold(e => IO.pure(Left(e)), id => call(Method.GET, path("api", "admin", "users", id)))).asText
        )
    },
    Tool(
      "create_user",
      "ユーザーを作る（管理者）。password を省くとパスワードなし（パスワードの再設定のメールや外部 IdP でログインする）。",
      schema(
        List("username", "name"),
        "username" -> str("ユーザー名"),
        "name" -> str("表示名"),
        "email" -> str("メールアドレス"),
        "password" -> str("初期パスワード"),
        "mustChangePassword" -> bool("初回ログインで変更させる"),
        "groups" -> strs("所属させるグループ名"),
        "attributes" -> obj("カスタム属性 {キー: 値}"),
        "isAdmin" -> bool("管理者にする")
      ),
      readOnly = false
    ) {
      (call, a) =>
        (need(a, "username"), need(a, "name")).tupled.withArgs {
          (un, nm) =>
            a.get[List[String]]("groups").getOrElse(Nil).traverse(groupId(call, _)).flatMap(_.sequence match {
              case Left(e) => IO.pure(Left(e))
              case Right(gids) =>
                call(
                  Method.POST,
                  path("api", "admin", "users"),
                  Some(Json.obj(
                    "username" -> un.asJson,
                    "name" -> nm.asJson,
                    "email" -> opt(a, "email").asJson,
                    "password" -> opt(a, "password").asJson,
                    "mustChangePassword" -> a.get[Boolean]("mustChangePassword").getOrElse(false).asJson,
                    "groupIds" -> gids.asJson,
                    "attributes" -> a.downField("attributes").focus.filter(_.isObject).getOrElse(Json.obj()),
                    "isAdmin" -> a.get[Boolean]("isAdmin").getOrElse(false).asJson
                  ).dropNullValues)
                ).asText
            })
        }
    },
    Tool(
      "update_user",
      "ユーザーを変える（指定した項目だけ）。attributes は既存の属性に重ねる。",
      schema(
        List("user"),
        "user" -> str("ユーザー名・メール・ID"),
        "name" -> str("表示名"),
        "email" -> str("メールアドレス"),
        "givenName" -> str("名"),
        "familyName" -> str("姓"),
        "phoneNumber" -> str("電話番号"),
        "attributes" -> obj("カスタム属性"),
        "isAdmin" -> bool("管理者"),
        "disabled" -> bool("無効にする")
      ),
      readOnly = false
    ) {
      (call, a) =>
        need(a, "user").withArgs(who =>
          patchUser(call, who) { cur =>
            val simple = List("name", "email", "givenName", "familyName", "phoneNumber").flatMap(k =>
              opt(a, k).map(k -> _.asJson)
            ) ++
              List("isAdmin", "disabled").flatMap(k => a.get[Boolean](k).toOption.map(k -> _.asJson))
            val attrs = a.downField("attributes").focus.filter(_.isObject)
              .map(x =>
                "attributes" -> cur.hcursor.downField("attributes").focus.getOrElse(Json.obj()).deepMerge(x)
              ).toList
            cur.deepMerge(Json.fromFields(simple ++ attrs))
          }.asText
        )
    },
    Tool(
      "set_user_disabled",
      "ユーザーを無効・有効にする（無効にするとログイン中の端末とトークンも失効）。",
      schema(List("user", "disabled"), "user" -> str("ユーザー名・メール・ID"), "disabled" -> bool("true で無効")),
      readOnly = false,
      destructive = true
    ) {
      (call, a) =>
        need(a, "user").withArgs(who =>
          patchUser(call, who)(_.deepMerge(Json.obj("disabled" ->
            a.get[Boolean]("disabled").getOrElse(true).asJson))).asText
        )
    },
    Tool(
      "unlock_user",
      "ログインの失敗でロックされたユーザーを解除する。",
      schema(List("user"), "user" -> str("ユーザー名・メール・ID")),
      readOnly = false
    ) {
      (call, a) =>
        need(a, "user").withArgs(who =>
          userId(call, who).flatMap(_.fold(
            e => IO.pure(Left(e)),
            id => call(Method.POST, path("api", "admin", "users", id, "unlock"))
          )).asText
        )
    },
    Tool(
      "reset_password",
      "パスワードをリセットする。sendMail=true なら再設定のメールを送る。そうでなければ新しいパスワードを作って返す（次回ログインで変更）。",
      schema(List("user"), "user" -> str("ユーザー名・メール・ID"), "sendMail" -> bool("再設定のメールを送る")),
      readOnly = false,
      destructive = true
    ) {
      (call, a) =>
        need(a, "user").withArgs(who =>
          userId(call, who).flatMap(_.fold(
            e => IO.pure(Left(e)),
            id =>
              call(
                Method.POST,
                path("api", "admin", "users", id, "password"),
                Some(Json.obj(
                  "mustChange" -> true.asJson,
                  "sendResetMail" -> a.get[Boolean]("sendMail").getOrElse(false).asJson
                ))
              )
          )).asText
        )
    },
    Tool("list_groups", "グループの一覧（親子・メンバー数・動的なルール）。", schema(Nil), readOnly = true) {
      (call, _) =>
        call(Method.GET, path("api", "admin", "groups")).asText
    },
    Tool("get_group_members", "グループのメンバー（手動・動的）。", schema(List("group"), "group" -> str("グループ名・ID")), readOnly = true) {
      (call, a) =>
        need(a, "group").withArgs(g =>
          groupId(call, g).flatMap(_.fold(
            e => IO.pure(Left(e)),
            id => call(Method.GET, path("api", "admin", "groups", id, "members"))
          )).asText
        )
    },
    Tool(
      "add_group_member",
      "グループにユーザーを加える。",
      schema(List("group", "user"), "group" -> str("グループ名・ID"), "user" -> str("ユーザー名・メール・ID")),
      readOnly = false
    ) {
      (call, a) =>
        (need(a, "group"), need(a, "user")).tupled.withArgs((g, u) =>
          (groupId(call, g), userId(call, u)).flatMapN((ge, ue) =>
            (ge, ue).tupled match {
              case Left(e) => IO.pure(Left(e))
              case Right((gid, uid)) => call(
                  Method.POST,
                  path("api", "admin", "groups", gid, "members"),
                  Some(Json.obj("userIds" -> List(uid).asJson))
                )
            }
          ).asText
        )
    },
    Tool(
      "remove_group_member",
      "グループからユーザーを外す。",
      schema(List("group", "user"), "group" -> str("グループ名・ID"), "user" -> str("ユーザー名・メール・ID")),
      readOnly = false,
      destructive = true
    ) {
      (call, a) =>
        (need(a, "group"), need(a, "user")).tupled.withArgs((g, u) =>
          (groupId(call, g), userId(call, u)).flatMapN((ge, ue) =>
            (ge, ue).tupled match {
              case Left(e) => IO.pure(Left(e))
              case Right((gid, uid)) =>
                call(Method.DELETE, path("api", "admin", "groups", gid, "members", uid))
            }
          ).asText
        )
    },
    Tool("list_applications", "連携しているアプリケーション（OIDC・SAML）の一覧。", schema(Nil), readOnly = true) {
      (call, _) =>
        call(Method.GET, path("api", "admin", "apps")).asText
    },
    Tool(
      "search_audit_log",
      "監査ログを探す。action は前方一致（例: login. / user. / app.authorize）。from・to は ISO 8601。",
      schema(
        Nil,
        "q" -> str("自由語（操作者・対象・IP など）"),
        "action" -> str("操作の前方一致"),
        "success" -> str("true か false"),
        "from" -> str("開始日時"),
        "to" -> str("終了日時"),
        "limit" -> int("件数（既定 50）")
      ),
      readOnly = true
    ) {
      (call, a) =>
        val base = path("api", "admin", "audit").withQueryParam("limit", a.get[Int]("limit").getOrElse(50).toString)
        call(
          Method.GET,
          List("q", "action", "success", "from", "to").foldLeft(base)((u, k) =>
            opt(a, k).fold(u)(v => u.withQueryParam(k, v))
          )
        ).asText
    },
    Tool(
      "list_api_endpoints",
      "REST API の一覧。専用のツールがない操作（ポリシー・外部 IdP・属性の定義など）は call_api で行える。",
      schema(Nil),
      readOnly = true
    ) {
      (_, _) =>
        IO.pure(Right(ApiCatalog.all.map(e => s"${e.method} ${e.path} — ${e.description}").mkString("\n")))
    },
    Tool(
      "call_api",
      "任意の REST API を呼ぶ（list_api_endpoints を参照）。権限はこのトークンの持ち主と同じ。",
      schema(
        List("method", "path"),
        "method" -> str("GET / POST / PUT / DELETE"),
        "path" -> str("/api/ で始まるパス（クエリを含めてよい）"),
        "body" -> obj("JSON の本文")
      ),
      readOnly = false
    ) {
      (call, a) =>
        (need(a, "method").map(_.toUpperCase), need(a, "path")).tupled.withArgs {
          (m, p) =>
            (
              Method.fromString(m).toOption.filter(x => Set("GET", "POST", "PUT", "PATCH", "DELETE")(x.name)),
              Uri.fromString(p).toOption.filter { u =>
                // 復号した後のセグメントで判定する（/api/%6Cogin のような書き方で除外をすり抜けられないように）
                val segs = u.path.segments.map(_.decoded()).toList
                u.path.absolute && segs.headOption.contains("api") && !segs.lift(1).contains("login") &&
                !segs.contains("..")
              }
            ) match {
              case (Some(method), Some(uri)) => call(method, uri, a.downField("body").focus.filterNot(_.isNull)).asText
              case (None, _) => IO.pure(Left("method は GET / POST / PUT / PATCH / DELETE です"))
              case _ => IO.pure(Left("path は /api/ で始めてください（ログインの API は使えません）"))
            }
        }
    }
  )

  // ------------------------------------------------------------------ 枠（sbirds.mcp.McpServer）に渡す部分

  private lazy val host = new McpServer.Host[Principal, Caller] {
    val settings = McpServer.Settings(
      "sruru",
      toolFailed = ErrorCode.McpToolFailed,
      version = cfg.version,
      maxBatch = 50,
      batchTooLarge = n => s"バッチは${n}件までです",
      readOnlyDenied = "参照専用のトークンでは変更できません",
      hideDenied = false
    )
    val tools = McpRoutes.this.tools

    /** API トークンの持ち主（画面のセッションは使えない）. IP 制限を外側の要求と同じにするため、転送のヘッダーを引き継いで確かめる. */
    def session(req: Request[IO], authz: Authorization) =
      auth.principal(inner(req, authz, Method.GET, Uri.unsafeFromString("/mcp")))
        .map(_.filter(_.via.isInstanceOf[Via.Token]))
    def unauthorized = Errors.respond(AppError(ErrorCode.McpTokenRequired))
    def context(req: Request[IO], authz: Authorization, p: Principal) = new Caller(req, authz)
    def canWrite(p: Principal) = p.canWrite
    def instructions(p: Principal) =
      "sruru（認証基盤・IdP）のユーザー・グループ・アプリケーション・監査ログを扱うツールです。" +
        "ユーザーはユーザー名・メールアドレス・ID のどれでも指定できます。管理の操作には admin スコープのトークンが必要です。" +
        "専用のツールがない操作は list_api_endpoints で REST API を調べ、call_api で行えます。"
  }
}
