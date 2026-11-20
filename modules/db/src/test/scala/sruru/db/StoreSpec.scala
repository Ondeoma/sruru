package sruru.db

import sbirds.db.*
import cats.effect.*
import cats.syntax.all.*
import doobie.implicits.*
import io.circe.Json
import munit.CatsEffectSuite

import java.time.Instant
import java.util.UUID

/** DB を使うテスト. TEST_DATABASE_URL がなければ飛ばす（例: jdbc:postgresql://localhost:54360/sruru_test）. */
class StoreSpec extends CatsEffectSuite {

  private val cfg: Option[DbConfig] = sys.env.get("TEST_DATABASE_URL").map(url =>
    DbConfig(
      url,
      sys.env.getOrElse("TEST_DATABASE_USER", "sruru"),
      sys.env.getOrElse("TEST_DATABASE_PASSWORD", "sruru")
    )
  )

  private val xaFixture = ResourceSuiteLocalFixture(
    "xa",
    cfg.fold(Resource.eval(IO.raiseError[doobie.Transactor[IO]](new RuntimeException("no db"))))(c =>
      Resource.eval(Database.migrate(c)) *> Database.transactor(c)
    )
  )

  override def munitFixtures = if cfg.isDefined then List(xaFixture) else Nil

  private def withDb(name: String)(body: doobie.Transactor[IO] => IO[Unit]): Unit =
    test(name)(if cfg.isEmpty then IO(assume(false, "TEST_DATABASE_URL が未設定")) else body(xaFixture()))

  private def user(xa: doobie.Transactor[IO]): IO[sruru.core.User] =
    new UserStore(xa).create(NewUser("t-" + UUID.randomUUID().toString.take(8), None, "テスト")).map(_.toOption.get)

  withDb("監査ログ: ハッシュの鎖と改ざんの検出") { xa =>
    val a = new AuditStore(xa)
    for {
      _ <- a.append(AuditEntry(None, Some("x"), "web", "test.one", detail = Json.obj("n" -> Json.fromInt(1))))
      id <- a.append(AuditEntry(None, Some("x"), "web", "test.two"))
      _ <- a.append(AuditEntry(None, Some("x"), "web", "test.three"))
      r1 <- a.verify
      _ = assertEquals(r1._2, None)
      _ <- sql"update audit_log set action = 'test.forged' where id = $id".update.run.transact(xa)
      r2 <- a.verify
      _ = assertEquals(r2._2, Some(id))
      _ <- sql"delete from audit_log".update.run.transact(xa)
    } yield ()
  }

  withDb("ユーザー: 連続の失敗でロック・名前の重複") { xa =>
    val us = new UserStore(xa)
    val until = Instant.now().plusSeconds(600)
    for {
      u <- user(xa)
      r1 <- us.recordFailure(u.id, 3, until)
      r2 <- us.recordFailure(u.id, 3, until)
      r3 <- us.recordFailure(u.id, 3, until)
      _ = assertEquals((r1._2, r2._2, r3._1), (None, None, 3))
      _ = assert(r3._2.isDefined)
      dup <- us.create(NewUser(u.username.toUpperCase, None, "重複"))
      _ = assert(dup.isLeft)
      _ <- us.unlock(u.id)
      u2 <- us.find(u.id)
      _ = assertEquals(u2.map(_.locked(Instant.now())), Some(false))
    } yield ()
  }

  withDb("認可コード: 1回だけ使え、持ち主のクライアントにだけ見える") { xa =>
    val ts = new TokenStore(xa)
    val as = new AppStore(xa)
    val now = Instant.now()
    val id = UUID.randomUUID()
    val app = sruru.core.Application(
      id,
      "t-" + id.toString.take(8),
      "t",
      "",
      "oidc",
      true,
      None,
      true,
      None,
      false,
      Nil,
      false,
      now,
      now
    )
    for {
      u <- user(xa)
      _ <- as.create(app, None, None)
      h = Array.fill[Byte](32)(scala.util.Random.nextInt().toByte)
      _ <- ts.createCode(
        h,
        AuthCode(id, u.id, None, "http://x/cb", List("openid"), None, None, None, now, Nil, now.plusSeconds(60), None)
      )
      r0 <- ts.useCode(h, UUID.randomUUID(), Instant.now()) // 別のクライアントには見えない（使用済みにもならない）
      r1 <- ts.useCode(h, id, Instant.now())
      r2 <- ts.useCode(h, id, Instant.now())
      _ = assert(r0.isEmpty)
      _ = assert(r1.exists(_.isRight))
      _ = assert(r2.exists(_.isLeft))
    } yield ()
  }

  withDb("グループ: 親をたどる所属と循環の禁止") { xa =>
    val gs = new GroupStore(xa)
    val sfx = UUID.randomUUID().toString.take(6)
    for {
      u <- user(xa)
      a <- gs.create(NewGroup(s"親-$sfx")).map(_.toOption.get)
      b <- gs.create(NewGroup(s"子-$sfx", parentIds = List(a.id))).map(_.toOption.get)
      _ <- gs.addMember(b.id, u.id)
      m <- gs.membership(u.id)
      _ = assertEquals(m.ids, Set(a.id, b.id))
      cyc <- gs.save(a.copy(parentIds = List(b.id)))
      _ = assert(cyc.isLeft)
      eff <- gs.effectiveMembers(a.id)
      _ = assertEquals(eff, List(u.id))
      // 親を2つ: 両方の親（とその親）のメンバーになる. 菱形でも重ならない
      c <- gs.create(NewGroup(s"親2-$sfx")).map(_.toOption.get)
      d <- gs.create(NewGroup(s"孫-$sfx", parentIds = List(b.id, c.id))).map(_.toOption.get)
      _ = assertEquals(d.parentIds.toSet, Set(b.id, c.id))
      u2 <- user(xa)
      _ <- gs.addMember(d.id, u2.id)
      m2 <- gs.membership(u2.id)
      _ = assertEquals(m2.ids, Set(a.id, b.id, c.id, d.id))
      effC <- gs.effectiveMembers(c.id)
      _ = assertEquals(effC, List(u2.id))
      cyc2 <- gs.save(c.copy(parentIds = List(d.id)))
      _ = assert(cyc2.isLeft)
    } yield ()
  }

  withDb("アプリの表示名: グループの優先度の大きい上書きが使われる") { xa =>
    val as = new AppStore(xa)
    val gs = new GroupStore(xa)
    val now = Instant.now()
    val id = UUID.randomUUID()
    val sfx = id.toString.take(8)
    val app =
      sruru.core.Application(id, "n-" + sfx, "元の名前", "", "oidc", true, None, true, None, false, Nil, false, now, now)
    for {
      _ <- as.create(app, None, None)
      low <- gs.create(NewGroup(s"低-$sfx", priority = 1)).map(_.toOption.get)
      high <- gs.create(NewGroup(s"高-$sfx", priority = 5)).map(_.toOption.get)
      _ <- as.setGroupNames(
        id,
        List((low.id, Some("低い方の名前"), Some("logo-low")), (high.id, Some("高い方の名前"), None))
      )
      both <- as.displayNames(Set(low.id, high.id))
      onlyLow <- as.displayNames(Set(low.id))
      none <- as.displayNames(Set.empty)
      logos <- as.displayLogos(Set(low.id, high.id))
      listed <- as.groupNames(id)
      _ = assertEquals(both.get(id), Some("高い方の名前"))
      _ = assertEquals(onlyLow.get(id), Some("低い方の名前"))
      _ = assert(none.isEmpty)
      _ = assertEquals(listed.map(_._3), List(Some("高い方の名前"), Some("低い方の名前")))
      // ロゴは、ロゴを上書きしているグループのうち優先度の大きいもの（優先度の大きいグループに無ければ低い方）
      _ = assertEquals(logos.get(id), Some("logo-low"))
    } yield ()
  }

  withDb("ポリシーを編集できる人: 本人か、所属するグループに付与されたものだけ") { xa =>
    val gs = new GroupStore(xa)
    val sfx = UUID.randomUUID().toString.take(8)
    for {
      u <- user(xa)
      target <- gs.create(NewGroup(s"対象-$sfx")).map(_.toOption.get)
      other <- gs.create(NewGroup(s"別-$sfx")).map(_.toOption.get)
      editors <- gs.create(NewGroup(s"編集者-$sfx")).map(_.toOption.get)
      _ <- gs.setPolicyEditors(target.id, List(u.id), Nil)
      _ <- gs.setPolicyEditors(other.id, Nil, List(editors.id))
      byUser <- gs.policyEditableBy(u.id, Set.empty)
      byGroup <- gs.policyEditableBy(UUID.randomUUID(), Set(editors.id))
      ed <- gs.policyEditors(other.id)
      _ <- gs.setPolicyEditors(target.id, Nil, Nil)
      cleared <- gs.policyEditableBy(u.id, Set.empty)
      _ = assertEquals(byUser, List(target.id))
      _ = assertEquals(byGroup, List(other.id))
      _ = assertEquals(ed, (Nil, List(editors.id)))
      _ = assert(cleared.isEmpty)
    } yield ()
  }
}
