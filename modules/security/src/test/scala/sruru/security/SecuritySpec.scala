package sruru.security

import io.circe.Json
import io.circe.syntax.*

class SecuritySpec extends munit.FunSuite {

  test("Argon2id") {
    val h = Passwords.hash("correct horse")
    assert(h.startsWith("$argon2id$v=19$"))
    assert(Passwords.verify("correct horse", h))
    assert(!Passwords.verify("wrong", h))
    assert(!Passwords.verify("x", "garbage"))
  }

  test("bcrypt（jBCrypt の $2a$）も照合でき、作り直しの対象になる") {
    val pws = List("correct horse", "パスワード🔑日本語", "a" * 100, "")
    pws.foreach { pw =>
      val h = org.mindrot.jbcrypt.BCrypt.hashpw(pw, org.mindrot.jbcrypt.BCrypt.gensalt(4))
      assert(h.startsWith("$2a$04$"))
      assert(Passwords.isBcrypt(h))
      assert(Passwords.verify(pw, h), pw)
      assert(!Passwords.verify(pw + "x", h) || pw.getBytes("UTF-8").length >= 72, pw)
      assert(Passwords.needsRehash(h))
    }
    // 72 バイトを超える部分は jBCrypt と同じく使わない
    val long = org.mindrot.jbcrypt.BCrypt.hashpw("b" * 80, org.mindrot.jbcrypt.BCrypt.gensalt(4))
    assert(Passwords.verify("b" * 72 + "zzz", long))
    assert(!Passwords.verify("b" * 71, long))
    // $2b$・$2y$ も同じ計算
    val h = org.mindrot.jbcrypt.BCrypt.hashpw("pw", org.mindrot.jbcrypt.BCrypt.gensalt(4))
    assert(Passwords.verify("pw", "$2b$" + h.drop(4)))
    assert(Passwords.verify("pw", "$2y$" + h.drop(4)))
    assert(!Passwords.verify("pw2", "$2y$" + h.drop(4)))
  }

  test("取り込みで受け付けるハッシュの形") {
    val bc = org.mindrot.jbcrypt.BCrypt.hashpw("pw", org.mindrot.jbcrypt.BCrypt.gensalt(10))
    assert(Passwords.acceptable(bc))
    assert(Passwords.acceptable(Passwords.hash("pw")))
    assert(!Passwords.needsRehash(Passwords.hash("pw")))
    assert(!Passwords.acceptable("$2a$03$" + bc.drop(7))) // コストが小さすぎる
    assert(!Passwords.acceptable(bc.dropRight(1))) // 長さが違う
    assert(!Passwords.acceptable("$2x$10$" + bc.drop(7))) // 知らない版
    assert(!Passwords.acceptable("plain-password"))
    assert(!Passwords.acceptable("$argon2i$v=19$m=1,t=1,p=1$c2FsdA$aGFzaA"))
    // パラメータの違う Argon2id は照合でき、作り直しの対象
    val weak = "$argon2id$v=19$m=1024,t=1,p=1$c2FsdHNhbHRzYWx0$" + "A" * 43
    assert(Passwords.acceptable(weak) && Passwords.needsRehash(weak))
  }

  test("TOTP（RFC 6238 の試験値）") {
    // 秘密 "12345678901234567890"（ASCII）、時刻 59 → 94287082 の下6桁
    val secret = Totp.base32("12345678901234567890".getBytes)
    assertEquals(Totp.code(secret, Totp.step(59)), "287082")
    assertEquals(Totp.code(secret, Totp.step(1111111109)), "081804")
    assertEquals(Totp.verify(secret, "287082", 59, 0), Some(1L))
    assertEquals(Totp.verify(secret, "287082", 59, 1), None) // 使ったステップは再利用できない
    assertEquals(Totp.base32Decode(secret).toList, "12345678901234567890".getBytes.toList)
  }

  test("JWS RS256・ES256 の署名と検証") {
    List("RS256", "ES256").foreach { alg =>
      val kp = Jose.generate(alg)
      val key = SigningKey("k1", alg, kp.getPrivate, kp.getPublic, None)
      val jwt = Jose.sign(key, Json.obj("sub" -> "u".asJson))
      assertEquals(Jose.verify(jwt, List(key.jwk)).map(_.hcursor.get[String]("sub").toOption), Right(Some("u")))
      val other = SigningKey("k1", alg, Jose.generate(alg).getPrivate, Jose.generate(alg).getPublic, None)
      assert(Jose.verify(jwt, List(other.jwk)).isLeft)
      // 秘密鍵の保存と復元
      val back = Jose.decodePrivate(alg, Jose.encodePrivate(kp.getPrivate))
      assertEquals(back.getEncoded.toList, kp.getPrivate.getEncoded.toList)
    }
  }

  test("自己署名証明書と PEM") {
    val kp = Jose.generate("RS256")
    val cert = Jose.selfSignedCert(kp, "sruru")
    val back = Jose.parseCerts(Jose.certPem(cert)).toOption.get.head
    assertEquals(back, cert)
    assertEquals(ClientCerts.info(cert).cn, Some("sruru"))
  }

  test("クライアント証明書の検証") {
    import org.bouncycastle.asn1.x500.X500Name
    import org.bouncycastle.asn1.x509.{Extension, GeneralName, GeneralNames}
    import org.bouncycastle.cert.jcajce.{JcaX509CertificateConverter, JcaX509v3CertificateBuilder}
    import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
    import java.util.Date
    val caKp = Jose.generate("RS256")
    val ca = {
      val b = new JcaX509v3CertificateBuilder(
        new X500Name("CN=Test CA"),
        java.math.BigInteger.ONE,
        new Date(System.currentTimeMillis() - 100000),
        new Date(System.currentTimeMillis() + 86400000L),
        new X500Name("CN=Test CA"),
        caKp.getPublic
      )
      b.addExtension(Extension.basicConstraints, true, new org.bouncycastle.asn1.x509.BasicConstraints(true))
      new JcaX509CertificateConverter().getCertificate(
        b.build(new JcaContentSignerBuilder("SHA256withRSA").build(caKp.getPrivate))
      )
    }
    val kp = Jose.generate("RS256")
    val leaf = {
      val b = new JcaX509v3CertificateBuilder(
        new X500Name("CN=Test CA"),
        java.math.BigInteger.TWO,
        new Date(System.currentTimeMillis() - 100000),
        new Date(System.currentTimeMillis() + 86400000L),
        new X500Name("CN=taro"),
        kp.getPublic
      )
      b.addExtension(
        Extension.subjectAlternativeName,
        false,
        new GeneralNames(new GeneralName(GeneralName.rfc822Name, "taro@example.com"))
      )
      new JcaX509CertificateConverter().getCertificate(
        b.build(new JcaContentSignerBuilder("SHA256withRSA").build(caKp.getPrivate))
      )
    }
    val now = java.time.Instant.now()
    assert(ClientCerts.validate(List(leaf), List(ca), now).isRight)
    assert(ClientCerts.validate(List(leaf), List(Jose.selfSignedCert(Jose.generate("RS256"), "other")), now).isLeft)
    val info = ClientCerts.info(leaf)
    assertEquals(info.emails, List("taro@example.com"))
    assertEquals(info.cn, Some("taro"))
    // ヘッダー（URL エンコード）から読む
    val enc = java.net.URLEncoder.encode(Jose.certPem(leaf), "UTF-8")
    assertEquals(ClientCerts.fromHeader(enc).map(ClientCerts.fingerprint), Right(ClientCerts.fingerprint(leaf)))
  }

  test("SecretBox") {
    val b = new SecretBox("0123456789abcdef")
    assertEquals(b.decrypt(b.encrypt("秘密")), Some("秘密"))
    assertEquals(new SecretBox("other-secret-0000").decrypt(b.encrypt("秘密")), None)
  }
}
