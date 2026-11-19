package sruru.api

import cats.effect.*
import cats.syntax.all.*
import io.circe.Json
import io.circe.syntax.*
import sruru.core.*
import sruru.db.*

/** クレーム（ID トークン・UserInfo）を作る. */
object Claims {
  def sub(u: User, c: OidcClientConfig): String = c.subMode match {
    case "username" => u.username
    // 確認済みのアドレスだけ（未確認のアドレスは本人が自由に書けるので、他人の sub を名乗れてしまう）
    case "email" => u.email.filter(_ => u.emailVerified).getOrElse(u.id.toString)
    case _ => u.id.toString
  }
}

final class Claims(
  dir: Directory,
  apps: AppStore,
  /** ロゴの URL を作るときの sruru の公開 URL */
  publicUrl: String = "") {
  def sub(u: User, c: OidcClientConfig): String = Claims.sub(u, c)

  def build(u: User, m: Membership, app: Application, c: OidcClientConfig, scopes: Set[String]): IO[Json] =
    (apps.mappings(app.id), appNames(m, app, c)).mapN {
      (ms, sbirds) =>
        val pic = dir.claimPicture(u)
        val base = List("sub" -> sub(u, c).asJson)
        val profile = if scopes("profile") then
          List(
            "name" -> u.name.asJson,
            "given_name" -> u.givenName.asJson,
            "family_name" -> u.familyName.asJson,
            "preferred_username" -> u.username.asJson,
            "picture" -> pic.asJson,
            "locale" -> u.locale.asJson,
            "zoneinfo" -> u.zoneinfo.asJson,
            "updated_at" -> u.updatedAt.getEpochSecond.asJson
          )
        else Nil
        val email =
          if scopes("email") then List("email" -> u.email.asJson, "email_verified" -> u.emailVerified.asJson) else Nil
        val phone = if scopes("phone") then List("phone_number" -> u.phoneNumber.asJson) else Nil
        val groups = if scopes("groups") || c.includeGroups then List("groups" -> m.names.asJson) else Nil
        val ctx = Context.of(Context.user(u, m, Some(pic)), Some(app))
        val custom = ms.filter(x => x.scope.forall(scopes.contains)).flatMap { x =>
          val v = Expr.eval(x.expression, ctx)
          Option.when(!Expr.isEmpty(v))(x.name -> (if x.multi && !v.isArray then Json.arr(v) else v))
        }
        Json.fromFields((base ++ profile ++ email ++ phone ++ groups ++ custom ++ sbirds).filterNot(_._2.isNull))
    }

  /**
   * sbirds のサービス向けのアプリケーションの表示名（includeAppNames のクライアントだけ）.
   * sbirds_apps: 使えるアプリケーションの slug → 表示名、sbirds_app: このアプリケーション自身の表示名（グループの上書きを反映）.
   */
  private def appNames(m: Membership, app: Application, c: OidcClientConfig): IO[List[(String, Json)]] =
    if (!c.includeAppNames) IO.pure(Nil)
    else
      (apps.all, apps.allAccessGroups, apps.displayNames(m.ids), apps.displayLogos(m.ids)).mapN {
        (as, access, names, logos) =>
          val usable =
            as.filter(a => a.enabled && (!a.restrictAccess || access.getOrElse(a.id, Nil).exists(m.ids.contains)))
          List(
            "sbirds_apps" -> usable.map(a => a.slug -> names.getOrElse(a.id, a.name)).toMap.asJson,
            "sbirds_app" -> names.getOrElse(app.id, app.name).asJson,
            // ロゴ: グループの上書き（brand_logos）、なければアプリケーションのアイコン. どちらもなければ入れない
            "sbirds_logos" -> usable.flatMap(a => logoUrl(a, logos).map(a.slug -> _)).toMap.asJson,
            "sbirds_app_logo" -> logoUrl(app, logos).asJson
          )
      }

  private def logoUrl(a: Application, logos: Map[java.util.UUID, String]): Option[String] =
    logos.get(a.id).map(id => s"$publicUrl/brand-logos/$id")
      .orElse(a.iconUpdatedAt.map(t => s"$publicUrl/app-icons/${a.id}?v=${t.getEpochSecond}"))
}
