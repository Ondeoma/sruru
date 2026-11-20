package sruru.api

import sbirds.db.*
import cats.effect.*
import cats.syntax.all.*
import io.circe.Json
import io.circe.syntax.*
import org.http4s.client.Client
import sruru.core.*
import sruru.db.*
import sruru.federation.*
import sruru.security.*

import java.time.Instant
import java.util.UUID
import scala.concurrent.duration.*

/**
 * 外部の IdP（Google Workspace・Microsoft Entra ID・汎用 OIDC）でのログインと、ディレクトリの同期.
 * 同期したユーザーは source = プロバイダのスラッグ、external_id = ディレクトリの ID（Google の sub・Entra の oid と同じ）なので、
 * 外部の IdP でのログインと自動で結び付く.
 */
final class FederationService(store: FederationStore,
                              dir: Directory,
                              audit: AuditService,
                              box: SecretBox,
                              http: Client[IO],
                              lock: JobLock,
                              cfg: ApiConfig) {

  private val upstream = new UpstreamOidc(http)

  def callbackUrl(slug: String): String = s"${cfg.publicUrl}/auth/fed/$slug/callback"

  def upstreamConfig(p: FederationProvider): UpstreamConfig = {
    val extra = p.kind match {
      case "google" => Presets.googleParams(p.allowedDomains.headOption.filter(_ => p.allowedDomains.size == 1))
      case "entra" => Presets.entraParams(true)
      case _ => Map.empty[String, String]
    }
    UpstreamConfig(
      p.issuer,
      p.clientId,
      box.decrypt(p.clientSecretEnc).getOrElse(""),
      callbackUrl(p.slug),
      p.scopes.split(' ').filter(_.nonEmpty).toList,
      p.subjectClaim,
      extra
    )
  }

  // ------------------------------------------------------------------ ログイン

  /** 認可の URL と、callback で確かめる値（state・nonce・PKCE の verifier）. */
  def start(p: FederationProvider, flowId: UUID): IO[(org.http4s.Uri, Json)] = {
    val state = flowId.toString + "." + Crypto.randomToken(16)
    val nonce = Crypto.randomToken(16)
    val verifier = Crypto.randomToken(32)
    upstream.authorizationUri(upstreamConfig(p), state, nonce, verifier)
      .map(_ -> Json.obj(
        "slug" -> p.slug.asJson,
        "state" -> state.asJson,
        "nonce" -> nonce.asJson,
        "verifier" -> verifier.asJson
      ))
  }

  def exchange(p: FederationProvider, code: String, verifier: String, nonce: String): IO[UpstreamIdentity] =
    Time.now.flatMap(now => upstream.exchange(upstreamConfig(p), code, verifier, nonce, now))

  private def allowed(p: FederationProvider): List[String] = p.allowedDomains.map(_.trim.toLowerCase).filter(_.nonEmpty)

  /** Entra のテナントが許可リストにあるか（テナントの ID かテナントのドメインを書く）. */
  private def tenantAllowed(p: FederationProvider, id: UpstreamIdentity): Boolean =
    id.tenantId.exists(t => allowed(p).contains(t.toLowerCase))

  /**
   * ログインを許すドメインか.
   * Entra はテナント（tid）だけで判定する（マルチテナントでは、他のテナントの管理者がメールの属性を自由に書けるため）.
   * Google は Workspace のドメイン（hd）だけで判定する（会社のアドレスで作った個人の Google アカウントは Workspace の管理外のため）.
   * そのほかは確認済みのメールアドレスのドメインで判定する.
   */
  private def domainOk(p: FederationProvider, id: UpstreamIdentity): Boolean =
    allowed(p).isEmpty || (
      p.kind match {
        case "entra" => tenantAllowed(p, id)
        case "google" => id.hostedDomain.exists(h => allowed(p).contains(h.toLowerCase))
        case _ => id.emailVerified &&
          id.email.exists(e => allowed(p).contains(e.dropWhile(_ != '@').drop(1).toLowerCase))
      }
    )

  /**
   * メールアドレスを信頼してよいか. 上流が確認済みとしたもの. Entra は email_verified を出さないので、
   * 許可リストに書いたテナント（自組織が管理するテナント）のときだけ信頼する.
   */
  private def emailTrusted(p: FederationProvider, id: UpstreamIdentity): Boolean =
    id.emailVerified || (p.kind == "entra" && tenantAllowed(p, id))

  private def uniqueUsername(base: String): IO[String] = {
    def go(n: Int): IO[String] = {
      val name = if n == 0 then base else s"$base$n"
      dir.users.byUsername(name).flatMap(_.fold(IO.pure(name))(_ => go(n + 1)))
    }
    go(0)
  }

  /** 外部のアカウントに対応するユーザー（結び付け・自動作成を含む）. Left は利用者に見せる文. */
  def resolve(p: FederationProvider, id: UpstreamIdentity): IO[Either[String, User]] =
    if !domainOk(p, id) then IO.pure(Left("このアカウントのドメインではログインできません"))
    else
      store.identity(p.id, id.subject).flatMap {
        case Some(link) => dir.users.find(link.userId).map(_.toRight("ユーザーが見つかりません"))
        case None =>
          dir.users.byExternal(p.slug, id.subject).flatMap {
            case Some(u) => IO.pure(Right(u))
            case None =>
              val byEmail: IO[Option[User]] =
                // 結び付けるのは、こちらでもメールアドレスが確認済みのユーザーだけ（未確認のアドレスで先に登録しておく乗っ取りを防ぐ）
                if p.linkByEmail && emailTrusted(p, id) then
                  id.email.fold(IO.pure(None))(e =>
                    dir.users.byEmail(e).map {
                      case List(u) if u.emailVerified => Some(u)
                      case _ => None
                    }
                  )
                else IO.pure(None)
              byEmail.flatMap {
                case Some(u) => IO.pure(Right(u))
                case None if p.jit =>
                  val base = id.email.filter(_ => emailTrusted(p, id)).orElse(
                    id.claims.hcursor.get[String]("preferred_username").toOption
                  )
                    .getOrElse(s"${p.slug}-${id.subject.take(12)}")
                  uniqueUsername(base.trim.toLowerCase).flatMap { name =>
                    dir.users.create(NewUser(
                      name,
                      id.email,
                      id.name.getOrElse(name),
                      id.givenName,
                      id.familyName,
                      emailVerified = emailTrusted(p, id) && id.email.isDefined,
                      source = p.slug,
                      externalId = Some(id.subject),
                      pictureUrl = id.picture
                    )).flatMap {
                      case Left(e) => IO.pure(Left(e.message))
                      case Right(u) => p.defaultGroups.traverse_(g => dir.groups.addMember(g, u.id)).as(Right(u))
                    }
                  }
                case None => IO.pure(Left("このアカウントは登録されていません。管理者に連絡してください"))
              }
          }
      }.flatMap {
        case Right(u) =>
          // 外部の IdP の情報で名前・アイコンを更新する（そのプロバイダから作ったユーザーだけ）
          val upd =
            if u.source == p.slug then
              dir.users.save(u.copy(
                name = id.name.getOrElse(u.name),
                givenName = id.givenName.orElse(u.givenName),
                familyName = id.familyName.orElse(u.familyName),
                pictureUrl = id.picture.orElse(u.pictureUrl),
                email = id.email.orElse(u.email),
                emailVerified =
                  if id.email.isDefined && id.email != u.email then emailTrusted(p, id) else u.emailVerified
              )).map(_.getOrElse(u))
            else IO.pure(u)
          upd.flatTap(x => store.link(p.id, id.subject, x.id, id.email)).map(Right(_))
        case l => IO.pure(l)
      }

  def amr(p: FederationProvider, id: UpstreamIdentity): List[String] =
    List(Amr.Fed) ++
      (if p.trustMfa && (id.amr.contains("mfa") || id.amr.contains("otp") || id.amr.contains("hwk")) then List(Amr.Mfa)
       else Nil)

  // ------------------------------------------------------------------ ディレクトリの同期

  def syncConfig(p: FederationProvider): Option[Json] =
    p.syncConfigEnc.flatMap(box.decrypt).flatMap(s => io.circe.parser.parse(s).toOption)

  /** 同期する. 結果の文を返す（監査ログ・管理画面に出す）. */
  def sync(p: FederationProvider, actor: Option[User], c: ReqCtx): IO[String] =
    syncConfig(p).toRight("同期の設定がありません").flatMap(j => DirectorySources.from(p.kind, j, http)) match {
      case Left(e) => store.recordSync(p.id, s"失敗: $e") *> IO.pure(s"失敗: $e")
      case Right(src) =>
        val run = for {
          snap <- src.fetch
          r <- apply(p, src, snap)
          _ <- dir.recomputeAll
          msg = s"成功: ユーザー ${snap.users.size} 件（作成 ${r._1}・更新 ${r._2}・無効化 ${r._3}）、グループ ${snap.groups.size} 件" +
            (if r._4.nonEmpty then s"。問題: ${r._4.take(5).mkString("; ")}" else "")
        } yield msg
        run.handleError(e => s"失敗: ${e.getMessage}").flatTap { msg =>
          store.recordSync(p.id, msg.take(1000)) *>
            audit.log(
              c,
              actor,
              if actor.isDefined then "web" else "system",
              "federation.sync",
              Some(("federation", p.id.toString, p.slug)),
              success = msg.startsWith("成功"),
              detail = Json.obj("result" -> msg.take(1000).asJson)
            )
        }
    }

  /** (作成, 更新, 無効化, 問題). */
  private def apply(p: FederationProvider, src: DirectorySource, snap: DirSnapshot): IO[(Int, Int, Int, List[String])] =
    for {
      existing <- dir.users.list(UserQuery(source = Some(p.slug), limit = 1000000), Instant.now()).map(_._1)
      byExt = existing.flatMap(u => u.externalId.map(_ -> u)).toMap
      results <- snap.users.traverse { du =>
        val attrs = du.attributes
        byExt.get(du.externalId) match {
          case Some(u) =>
            val next = u.copy(
              username = u.username,
              email = du.email.orElse(u.email),
              emailVerified = du.email.isDefined || u.emailVerified,
              name = du.name,
              givenName = du.givenName,
              familyName = du.familyName,
              disabled = !du.active,
              attributes = u.attributes.deepMerge(attrs)
            )
            if next == u then IO.pure((u.id, 0, 0, Option.empty[String]))
            else dir.users.save(next).map(r => (u.id, 0, 1, r.left.toOption.map(_.message)))
          case None =>
            dir.users.byUsername(du.username).flatMap {
              // 同じユーザー名のローカルユーザーがいて、確認済みのメールアドレスも同じなら引き取る
              // （未確認なら、他人がその社員のアドレスで先に自己登録したアカウントかもしれない）
              case Some(u)
                  if u.source == "local" && u.emailVerified &&
                    u.email.exists(e => du.email.exists(_.equalsIgnoreCase(e))) =>
                dir.users.save(u.copy(
                  source = p.slug,
                  externalId = Some(du.externalId),
                  disabled = !du.active,
                  attributes = u.attributes.deepMerge(attrs)
                )).map(r => (u.id, 0, 1, r.left.toOption.map(_.message)))
              case Some(_) => IO.pure((UUID(0, 0), 0, 0, Some(s"ユーザー名「${du.username}」が使われているため取り込めません")))
              case None =>
                dir.users.create(NewUser(
                  du.username,
                  du.email,
                  du.name,
                  du.givenName,
                  du.familyName,
                  emailVerified = du.email.isDefined,
                  attributes = attrs,
                  source = p.slug,
                  externalId = Some(du.externalId)
                )).flatMap {
                  case Left(e) => IO.pure((UUID(0, 0), 0, 0, Some(e.message)))
                  case Right(u) =>
                    p.defaultGroups.traverse_(g => dir.groups.addMember(g, u.id)) *>
                      IO.whenA(!du.active)(dir.users.save(u.copy(disabled = true)).void) *>
                      // 写真（失敗しても続ける）
                      src.photo(du).attempt.flatMap {
                        case Right(Some(img)) => dir.users.setAvatar(u.id, Some(img))
                        case _ => IO.unit
                      }.as((u.id, 1, 0, None))
                }
            }
        }
      }
      // ディレクトリから消えたユーザーは無効にする
      seen = snap.users.map(_.externalId).toSet
      gone = existing.filter(u => u.externalId.exists(e => !seen(e)) && !u.disabled)
      _ <- gone.traverse_(u => dir.users.save(u.copy(disabled = true)))
      idByExt <- dir.users.list(UserQuery(source = Some(p.slug), limit = 1000000), Instant.now()).map(_._1.flatMap(u =>
        u.externalId.map(_ -> u.id)
      ).toMap)
      gProblems <- snap.groups.traverse { dg =>
        dir.groups.byExternal(p.slug, dg.externalId).flatMap {
          case Some(g) =>
            dir.groups.save(g.copy(
              name = g.name,
              description = dg.description
            )).map(_.left.toOption.map(_.message)).map(_ -> Some(g.id))
          case None =>
            dir.groups.byName(dg.name).flatMap(clash =>
              dir.groups.create(NewGroup(
                if clash.isDefined then s"${dg.name} (${p.slug})" else dg.name,
                dg.description,
                source = p.slug,
                externalId = Some(dg.externalId)
              ))
            )
              .map {
                case Left(e) => (Some(e.message), None)
                case Right(g) => (None, Some(g.id))
              }
        }.flatMap {
          (problem, gid) =>
            gid.traverse_(id => dir.groups.setMembers(id, dg.memberUserIds.flatMap(idByExt.get))).as(problem)
        }
      }
      // ディレクトリから消えたグループは削除する
      allGroups <- dir.groups.all
      gSeen = snap.groups.map(_.externalId).toSet
      _ <- allGroups.filter(g => g.source == p.slug && g.externalId.exists(e => !gSeen(e))).traverse_(g =>
        dir.groups.delete(g.id)
      )
    } yield (results.map(_._2).sum, results.map(_._3).sum, gone.size, results.flatMap(_._4) ++ gProblems.flatten)

  /** 定期的な同期（間隔が過ぎたプロバイダだけ. 複数ノードでも1つだけが動く）. */
  def loop: IO[Nothing] =
    Loops.every(1.minute, 5.minutes, ErrorCode.DirectorySyncFailed) {
      (store.all, Time.now).flatMapN {
        (ps, now) =>
          ps.filter(p =>
            p.enabled && p.syncEnabled &&
              p.lastSyncAt.forall(_.plusSeconds(p.syncIntervalMin.toLong * 60).isBefore(now))
          )
            .traverse_(p => lock.exclusive(s"sync:${p.id}", 30.minutes)(sync(p, None, ReqCtx.system).void))
      }
    }
}
