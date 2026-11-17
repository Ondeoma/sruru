package sruru.api

import cats.effect.*
import cats.syntax.all.*
import io.circe.Json
import io.circe.syntax.*
import sruru.core.*
import sruru.db.*
import sruru.notify.{Mail, Mailer}
import sruru.security.*
import sruru.shared.*

import java.time.Instant
import java.util.UUID
import scala.concurrent.duration.*

/** 署名鍵（RS256・ES256）. DB に暗号化して保存し、各ノードは1分ごとに読み直す（鍵の入れ替えをほかのノードにも反映する）. */
final class KeyService(store: TokenStore, box: SecretBox, cache: Ref[IO, Option[(Long, List[(StoredKey, SigningKey)])]], cn: String):

  private def generate(alg: String): StoredKey =
    val kp   = Jose.generate(alg)
    val kid  = Jose.newKid()
    val cert = Option.when(alg == "RS256")(Jose.selfSignedCert(kp, cn))
    StoredKey(kid, alg, box.encrypt(Jose.encodePrivate(kp.getPrivate)), Jose.publicJwk(kid, alg, kp.getPublic), cert.map(Jose.certPem), true,
      Instant.now(), None)

  /** 使用中の鍵がなければ作る（複数ノードが同時に起動しても1つだけ）. */
  def ensure: IO[Unit] =
    store.withKeyLock(store.keysC.flatMap { ks =>
      List("RS256", "ES256").filterNot(a => ks.exists(k => k.alg == a && k.active && k.retiredAt.isEmpty))
        .traverse_(a => store.addKeyC(generate(a)))
    }) *> cache.set(None)

  private def decode(k: StoredKey): Option[SigningKey] =
    for
      enc  <- box.decrypt(k.privateEnc)
      priv <- scala.util.Try(Jose.decodePrivate(k.alg, enc)).toOption
      pub  <- Jose.publicKey(k.publicJwk).toOption
    yield SigningKey(k.kid, k.alg, priv, pub, k.certPem.flatMap(p => Jose.parseCerts(p).toOption.flatMap(_.headOption)))

  def all: IO[List[(StoredKey, SigningKey)]] =
    (cache.get, IO.monotonic).flatMapN { (c, now) =>
      c match
        case Some((at, ks)) if now.toMillis - at < 60000 => IO.pure(ks)
        case _ =>
          store.keys.map(_.filter(_.retiredAt.isEmpty).flatMap(k => decode(k).map(k -> _))).flatTap { ks =>
            IO.whenA(ks.isEmpty)(IO.println("[sruru] WARNING: 署名鍵を復号できません（APP_SECRET が違う可能性があります）")) *>
              cache.set(Some(now.toMillis -> ks))
          }
    }

  def active(alg: String): IO[SigningKey] =
    all.flatMap { ks =>
      ks.find((s, _) => s.active && s.alg == alg).orElse(ks.find((s, _) => s.active && s.alg == "RS256")).map(_._2) match
        case Some(k) => IO.pure(k)
        case None    => ensure *> all.flatMap(_.find(_._1.active).map(_._2).liftTo[IO](new IllegalStateException("署名鍵を用意できません")))
    }

  /** SAML の署名に使う鍵（証明書つきの RS256）. */
  def saml: IO[SigningKey] = active("RS256")

  def jwks: IO[Json] = all.map(ks => Json.obj("keys" -> ks.map(_._1.publicJwk).asJson))

  def publicJwks: IO[List[Json]] = all.map(_.map(_._1.publicJwk))

  def rotate(alg: String): IO[StoredKey] =
    val k = generate(alg)
    store.addKey(k) *> cache.set(None).as(k)

  def retire(kid: String): IO[Boolean] = store.retireKey(kid).flatTap(_ => cache.set(None))

object KeyService:
  def create(store: TokenStore, box: SecretBox, cn: String): IO[KeyService] =
    Ref.of[IO, Option[(Long, List[(StoredKey, SigningKey)])]](None).map(new KeyService(store, box, _, cn))

/** メールの送信（送信待ちの表に入れ、定期処理で送る. SMTP が未設定なら標準出力に出す）. */
final class MailService(store: MailStore, mailer: Option[Mailer], cfg: ApiConfig):
  def send(to: String, subject: String, body: String): IO[Unit] =
    mailer match
      case Some(_) => store.enqueue(to, subject, body)
      // 本文にはワンタイムコードなどが入るので、ログに出すのは開発用のときだけ
      case None if cfg.devMode => IO.println(s"[sruru] mail (SMTP 未設定のため送信しません) to=$to subject=$subject\n$body")
      case None                => IO.println(s"[sruru] WARNING: SMTP が未設定のため、メールを送れません（to=$to）")

  def loop: IO[Nothing] =
    Loops.every(5.seconds, 5.seconds, "mail") {
      mailer.fold(IO.unit)(m =>
        store.process(20)(om => m.send(Mail(om.to, om.to, om.subject, om.body)).as(OutboxResult.Sent).handleError(e => OutboxResult.Retry(e.getMessage))).void)
    }

object Directory:
  /** パスワードのハッシュ（Argon2id は重いので blocking のスレッドで計算する）. */
  def hash(pw: String): IO[String] = IO.blocking(Passwords.hash(pw))

/** ユーザー・グループの業務ロジック（所属・管理者の判定・アイコン・パスワードの条件・動的なグループ）. */
final class Directory(val users: UserStore, val groups: GroupStore, factors: FactorStore, sessions: SessionStore, tokens: TokenStore,
    policies: PolicyService, logout: LogoutNotifier, cfg: ApiConfig):

  def membership(u: User): IO[Membership] = groups.membership(u.id)

  /**
   * ユーザーに効くポリシー: 全体のポリシーに、所属するグループ（親を含む）の上書きを重ねたもの.
   * セキュリティの項目は厳しい方、表示の項目は優先度の高いグループのもの（GroupPolicy.effective）.
   */
  def policyFor(u: User, m: Membership): IO[PoliciesDto] =
    policies.get.map(p => GroupPolicy.effective(p, m.groups.distinctBy(_.id).flatMap(g => g.policy.map(x => (g.priority, g.name, x)))))

  def policyFor(u: User): IO[PoliciesDto] = membership(u).flatMap(policyFor(u, _))

  def isAdmin(u: User, m: Membership): Boolean = u.isAdmin || m.isAdmin

  /** アイコンの URL（自分の画像 → 外部 IdP の画像 → Gravatar（設定で有効なとき））. */
  def pictureUrl(u: User, gravatar: Boolean): Option[String] =
    if u.hasAvatar then Some(s"${cfg.publicUrl}/avatars/${u.id}?v=${u.avatarUpdatedAt.map(_.getEpochSecond).getOrElse(0L)}")
    else u.pictureUrl.orElse(Option.when(gravatar)(u.email).flatten.map(e =>
      s"https://www.gravatar.com/avatar/${Crypto.hex(Crypto.sha256(e.trim.toLowerCase))}?d=identicon&s=256"))

  def picture(u: User): IO[Option[String]] = policies.get.map(p => pictureUrl(u, p.branding.gravatar))

  /** 式で使う値（{{user.…}}）. */
  def context(u: User): IO[(Json, Membership)] =
    (membership(u), picture(u)).mapN((m, pic) => (Context.user(u, m, pic), m))

  def brief(u: User, gravatar: Boolean): UserBrief = UserBrief(u.id, u.username, u.name, pictureUrl(u, gravatar))

  // ------------------------------------------------------------------ 名前の確認

  def validUsername(s: String): Either[String, String] =
    val t = s.trim
    if t.isEmpty then Left("ユーザー名を入力してください")
    else if t.length > 128 then Left("ユーザー名は128文字以内にしてください")
    else if t.exists(c => c.isWhitespace || c.isControl || "/\\\"'<>".contains(c)) then Left("ユーザー名に空白や記号（/ \\ \" ' < >）は使えません")
    else Right(t)

  def validEmail(s: Option[String]): Either[String, Option[String]] =
    s.map(_.trim).filter(_.nonEmpty) match
      case None => Right(None)
      case Some(e) if e.matches("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$") && e.length <= 254 => Right(Some(e))
      case Some(e) => Left(s"メールアドレスの形式が正しくありません: $e")

  // ------------------------------------------------------------------ パスワード

  /** 新しいパスワードがポリシーと履歴の条件を満たすか. */
  def checkPassword(u: Option[User], pw: String): IO[Either[String, Unit]] =
    u.fold(policies.get)(policyFor).flatMap { p =>
      val info = u.toList.flatMap(x => List(x.username, x.name) ++ x.email.map(_.takeWhile(_ != '@')))
      PasswordCheck.violations(pw, p.password, info) match
        case v :: _ => IO.pure(Left(v))
        case Nil =>
          u.filter(_ => p.password.historyCount > 0).fold(IO.pure(Right(()))) { x =>
            users.passwordHistory(x.id, p.password.historyCount).map { hs =>
              Either.cond(!hs.exists(h => Passwords.verify(pw, h)), (), s"直近${p.password.historyCount}回に使ったパスワードは使えません")
            }
          }
    }

  /** パスワードを設定する（条件を確かめ、ほかのログインと発行済みのトークンを無効にする）. keepLogin は残すログイン. */
  def setPassword(u: User, pw: String, mustChange: Boolean, keepLogin: Option[UUID]): IO[Either[String, Unit]] =
    checkPassword(Some(u), pw).flatMap {
      case Left(e) => IO.pure(Left(e))
      case Right(_) =>
        (policyFor(u), Directory.hash(pw)).flatMapN((p, h) => users.setPassword(u.id, Some(h), mustChange, p.password.historyCount)) *>
          revokeEverything(u, keepLogin).as(Right(()))
    }

  /** パスワードの期限が切れているか. */
  def passwordExpired(u: User, p: PoliciesDto, now: Instant): Boolean =
    u.passwordHash.isDefined && p.password.maxAgeDays > 0 &&
      u.passwordChangedAt.exists(_.plusSeconds(p.password.maxAgeDays.toLong * 86400).isBefore(now))

  def passwordRules: IO[List[String]] = policies.get.map(p => PasswordCheck.describe(p.password))

  /** そのユーザーのパスワードの条件（グループの上書きを含む）. */
  def passwordRulesFor(u: User): IO[List[String]] = policyFor(u).map(p => PasswordCheck.describe(p.password))

  /** ランダムなパスワード（管理者がリセットするとき）. */
  def randomPassword: String = Crypto.randomCode(6) + "-" + Crypto.randomCode(6) + "-" + Crypto.randomCode(6).toUpperCase + "7"

  // ------------------------------------------------------------------ 多要素認証

  def hasTotp(userId: UUID): IO[Boolean] = factors.usersWithTotp(Some(List(userId))).map(_.nonEmpty)

  /**
   * 消したログインの後始末: そのログインで発行したトークンの失効と、RP へのバックチャネルの通知.
   * ログインを消すところ（ログアウト・無操作・期限切れ・管理者の操作）は必ずこれを通す.
   */
  def endLogin(userId: UUID, loginId: UUID): IO[Unit] =
    tokens.revokeLogin(loginId) *> users.find(userId).flatMap(_.traverse_(u => logout.send(u, Some(loginId))))

  /** ユーザーのログインを終わらせ、そのログインで発行したトークンを失効させる（except は残すログイン）. */
  def revokeSessions(userId: UUID, except: Option[UUID] = None): IO[Unit] =
    sessions.deleteLoginsOfUser(userId, except).flatMap(_.traverse_(endLogin(userId, _)))

  /**
   * ほかのログインと、offline_access を含むすべてのトークンを無効にする（パスワードの変更・乗っ取りの疑い）. except のログインの分は残す.
   * except がなければ、トークンを出したすべてのアプリへバックチャネルで通知する.
   */
  def revokeEverything(u: User, except: Option[UUID]): IO[Unit] =
    revokeSessions(u.id, except) *> tokens.revokeUserExcept(u.id, except) *> IO.whenA(except.isEmpty)(logout.send(u, None))

  /** API トークンを作る. 平文のトークン（この1回だけ表示する）と保存した内容. */
  def createApiToken(owner: UUID, name: String, scopes: List[String], days: Option[Int]): IO[Either[String, (String, ApiToken)]] =
    val sc = scopes.filter(TokenScopes.all.contains).distinct
    if name.trim.isEmpty then IO.pure(Left("名前を入力してください"))
    else if sc.isEmpty then IO.pure(Left("スコープを選んでください"))
    else
      Time.now.flatMap { now =>
        val (t, prefix) = ApiTokens.generate()
        factors.createToken(owner, name.trim.take(100), prefix, Crypto.sha256(t), sc, days.filter(_ > 0).map(d => now.plusSeconds(d.toLong * 86400)))
          .map(tk => Right((t, tk)))
      }

  /** 多要素認証が必須か（ポリシー）. */
  def mfaRequired(u: User, m: Membership, p: PoliciesDto): Boolean =
    p.mfa.mode match
      case "required" => true
      case "off"      => false
      case _ => (p.mfa.requiredForAdmins && isAdmin(u, m)) || m.names.exists(n => p.mfa.requiredGroups.exists(_.equalsIgnoreCase(n)))

  // ------------------------------------------------------------------ 動的なグループ

  /**
   * ルールで所属を決めてよいグループか. 管理者になるグループ（自身か親が管理者のグループ）は手動の所属だけにする
   * （本人が書き換えられる項目を条件にされると、自分で管理者になれてしまうため）.
   */
  private def ruleUsable(g: Group, all: Map[UUID, Group]): Boolean = !Membership.expand(List(g.id), all).isAdmin

  /** 条件の評価に使う値. 未確認のメールアドレスは本人が自由に書けるので使わない. */
  private def ruleContext(u: User, m: Membership, pic: Option[String]): Json =
    Json.obj("user" -> Context.user(u.copy(email = u.email.filter(_ => u.emailVerified)), m, pic))

  /** ルールのあるグループのうち、ユーザーが条件を満たすもの. */
  private def dynamicMatches(u: User, ruled: List[Group], direct: List[UUID], all: Map[UUID, Group], pic: Option[String]): List[UUID] =
    val ctx = ruleContext(u, Membership.expand(direct, all), pic)
    ruled.filter(g => ruleUsable(g, all) && g.rule.exists(r => GroupRule.matches(r, ctx))).map(_.id)

  /** ユーザー1人分の動的なメンバーを計算し直す. */
  def recomputeUser(u: User): IO[Unit] =
    for
      all    <- groups.all
      ruled   = all.filter(_.rule.isDefined)
      direct <- groups.staticGroupIds(u.id)
      pic    <- picture(u)
      _      <- groups.setDynamicForUser(u.id, dynamicMatches(u, ruled, direct, all.map(g => g.id -> g).toMap, pic))
    yield ()

  /** グループ1つ分の動的なメンバーを計算し直す（ルールがなければ空にする）. */
  def recomputeGroup(g: Group): IO[Unit] =
    g.rule match
      case None => groups.setDynamicForGroup(g.id, Nil)
      case Some(rule) =>
        for
          all    <- groups.all
          byId    = all.map(x => x.id -> x).toMap
          us     <- users.all
          p      <- policies.get
          static <- groups.allStatic
          ids     = if !ruleUsable(g, byId) then Nil else us.filterNot(_.isService).filter { u =>
                      GroupRule.matches(rule, ruleContext(u, Membership.expand(static.getOrElse(u.id, Nil), byId), pictureUrl(u, p.branding.gravatar)))
                    }
          _    <- groups.setDynamicForGroup(g.id, ids.map(_.id))
        yield ()

  /** すべての動的なグループを計算し直す（定期処理）. */
  def recomputeAll: IO[Unit] = groups.all.flatMap(_.filter(_.rule.isDefined).traverse_(recomputeGroup))

  // ------------------------------------------------------------------ 画面の型

  def userDto(u: User, m: Membership, mfa: Boolean, gravatar: Boolean, now: Instant, direct: List[UUID] = Nil): UserDto =
    UserDto(u.id, u.username, u.name, u.email, u.emailVerified, u.givenName, u.familyName, pictureUrl(u, gravatar), u.isAdmin, isAdmin(u, m),
      u.isService, u.disabled, u.locked(now), u.lockedUntil.filter(_.isAfter(now)), u.failedAttempts, u.attributes, u.source, u.externalId,
      m.groups.map(g => GroupBrief(g.id, g.name)), direct, mfa, u.passwordHash.isDefined, u.mustChangePassword, u.locale, u.zoneinfo,
      u.phoneNumber, Some(u.createdAt), Some(u.updatedAt), u.lastLoginAt)

  def groupDto(g: Group, count: Int): GroupDto =
    GroupDto(g.id, g.name, g.description, g.parentIds, g.attributes, g.isAdmin, g.rule.map(_.asJson), g.source, g.externalId, count, Some(g.createdAt),
      g.priority, g.policy.getOrElse(GroupPolicy()))
