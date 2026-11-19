package sruru.saml

import org.w3c.dom.{Document, Element}
import sruru.security.Jose

import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.security.{PrivateKey, Signature}
import java.time.Instant
import java.util.Base64
import javax.xml.crypto.dsig.*
import javax.xml.crypto.dsig.dom.DOMSignContext
import javax.xml.crypto.dsig.spec.{C14NMethodParameterSpec, TransformParameterSpec}
import scala.jdk.CollectionConverters.*

class SamlSpec extends munit.FunSuite {

  private val kp = Jose.generate("RS256")
  private val cert = Jose.selfSignedCert(kp, "sruru-test")
  private val now = Instant.parse("2026-11-16T10:00:00Z")

  private val authnXml =
    """<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
      | ID="_req1" Version="2.0" IssueInstant="2026-11-16T09:59:58Z" Destination="https://idp.example/saml/sso"
      | AssertionConsumerServiceURL="https://sp.example/acs" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" ForceAuthn="true">
      | <saml:Issuer>https://sp.example/metadata</saml:Issuer>
      | <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/>
      |</samlp:AuthnRequest>""".stripMargin

  private def enc(s: String) = URLEncoder.encode(s, StandardCharsets.UTF_8)

  private def find(doc: Document, ns: String, local: String): List[Element] = {
    val nl = doc.getElementsByTagNameNS(ns, local)
    (0 until nl.getLength).map(i => nl.item(i).asInstanceOf[Element]).toList
  }

  /** テスト用: JDK の API で要素に enveloped 署名（inclusive C14N）を付ける. */
  private def signWithJdk(target: Element, key: PrivateKey): Unit = {
    val f = XMLSignatureFactory.getInstance("DOM")
    val id = target.getAttribute("ID")
    target.setIdAttributeNS(null, "ID", true)
    val ref = f.newReference(
      "#" + id,
      f.newDigestMethod(DigestMethod.SHA256, null),
      List(f.newTransform(Transform.ENVELOPED, null.asInstanceOf[TransformParameterSpec])).asJava,
      null,
      null
    )
    val si = f.newSignedInfo(
      f.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, null.asInstanceOf[C14NMethodParameterSpec]),
      f.newSignatureMethod(SignatureMethod.RSA_SHA256, null),
      List(ref).asJava
    )
    val issuer = Xml.child(target, Xml.Assertion, "Issuer").get
    f.newXMLSignature(si, null).sign(new DOMSignContext(key, target, issuer.getNextSibling))
  }

  test("HTTP-Redirect の往復と AuthnRequest の解析") {
    val back = Saml.decodeRedirect(Saml.encodeRedirect(authnXml))
    assertEquals(back, Right(authnXml))
    val r = Saml.parseAuthnRequest(back.toOption.get).toOption.get
    assertEquals(r.id, "_req1")
    assertEquals(r.issuer, "https://sp.example/metadata")
    assertEquals(r.acsUrl, Some("https://sp.example/acs"))
    assertEquals(r.protocolBinding, Some(Saml.BindingPost))
    assertEquals(r.nameIdFormat, Some(Saml.NameIdFormat.Email))
    assert(r.forceAuthn)
    assert(!r.isPassive)
    assertEquals(r.destination, Some("https://idp.example/saml/sso"))
    assertEquals(r.issueInstant, Instant.parse("2026-11-16T09:59:58Z"))
    // POST バインディング
    val post = Base64.getEncoder.encodeToString(authnXml.getBytes(StandardCharsets.UTF_8))
    assertEquals(Saml.decodePost(post), Right(authnXml))
    // 壊れた入力・別の要素
    assert(Saml.decodeRedirect("!!!notbase64").isLeft)
    assert(Saml.decodeRedirect(Base64.getEncoder.encodeToString("plain".getBytes)).isLeft)
    assert(Saml.parseAuthnRequest(authnXml.replace("urn:oasis:names:tc:SAML:2.0:protocol", "urn:x")).isLeft)
    assert(Saml.parseAuthnRequest(
      """<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="a" Version="2.0"/>"""
    ).isLeft)
  }

  private def params(signResponse: Boolean, signAssertion: Boolean) = AssertionParams(
    idpEntityId = "https://idp.example",
    spEntityId = "https://sp.example/metadata",
    acsUrl = "https://sp.example/acs",
    inResponseTo = Some("_req1"),
    nameId = "alice@example.com",
    nameIdFormat = Saml.NameIdFormat.Email,
    sessionIndex = "_sess1",
    authnInstant = now,
    authnContextClassRef = Saml.PasswordProtectedTransport,
    attributes = List(
      SamlAttribute("email", None, List("alice@example.com")),
      SamlAttribute("http://schemas.xmlsoap.org/claims/Group", Some("groups"), List("admins", "a&b <c>"))
    ),
    now = now,
    validSeconds = 300,
    sessionNotOnOrAfter = Some(now.plusSeconds(3600)),
    signResponse = signResponse,
    signAssertion = signAssertion
  )

  test("Response と Assertion の署名") {
    val xml = Saml.buildResponse(params(true, true), kp.getPrivate, cert)
    val doc = Xml.parse(xml).toOption.get
    val resp = doc.getDocumentElement
    val a = find(doc, Xml.Assertion, "Assertion").head
    assertEquals(Saml.verifyElementSignature(a, cert), Right(()))
    assertEquals(Saml.verifyElementSignature(resp, cert), Right(()))
    assertEquals(Saml.verifyPostSignature(xml, cert), Right(()))
    // 署名は Issuer の直後
    val sig = Xml.child(resp, Xml.DSig, "Signature").get
    assertEquals(sig.getPreviousSibling.getLocalName, "Issuer")
    assertEquals(Xml.child(a, Xml.DSig, "Signature").get.getPreviousSibling.getLocalName, "Issuer")
    // 別の証明書では通らない
    val other = Jose.selfSignedCert(Jose.generate("RS256"), "other")
    assert(Saml.verifyElementSignature(a, other).isLeft)
    // 中身
    assertEquals(resp.getAttribute("Destination"), "https://sp.example/acs")
    assertEquals(resp.getAttribute("InResponseTo"), "_req1")
    assertEquals(Xml.text(find(doc, Xml.Assertion, "Audience").head), "https://sp.example/metadata")
    val scd = find(doc, Xml.Assertion, "SubjectConfirmationData").head
    assertEquals(scd.getAttribute("Recipient"), "https://sp.example/acs")
    assertEquals(scd.getAttribute("InResponseTo"), "_req1")
    assertEquals(scd.getAttribute("NotOnOrAfter"), "2026-11-16T10:05:00Z")
    assertEquals(Xml.text(find(doc, Xml.Assertion, "NameID").head), "alice@example.com")
    assertEquals(find(doc, Xml.Assertion, "AuthnStatement").head.getAttribute("SessionIndex"), "_sess1")
    val attrs = find(doc, Xml.Assertion, "Attribute").map(e => e.getAttribute("Name") -> e).toMap
    assertEquals(attrs("email").getAttribute("NameFormat"), "urn:oasis:names:tc:SAML:2.0:attrname-format:basic")
    val g = attrs("http://schemas.xmlsoap.org/claims/Group")
    assertEquals(g.getAttribute("NameFormat"), "urn:oasis:names:tc:SAML:2.0:attrname-format:uri")
    assertEquals(g.getAttribute("FriendlyName"), "groups")
    val vals = Xml.children(g, Xml.Assertion, "AttributeValue")
    assertEquals(vals.map(Xml.text), List("admins", "a&b <c>"))
    assertEquals(vals.head.getAttributeNS(Xml.XSI, "type"), "xs:string")
  }

  test("署名後の改ざんは検証に失敗する") {
    val xml = Saml.buildResponse(params(true, true), kp.getPrivate, cert)
    assert(xml.contains(">alice@example.com</saml:NameID>"))
    val bad = xml.replace(">alice@example.com</saml:NameID>", ">mallory@example.com</saml:NameID>")
    val doc = Xml.parse(bad).toOption.get
    assert(Saml.verifyElementSignature(find(doc, Xml.Assertion, "Assertion").head, cert).isLeft)
    assert(Saml.verifyPostSignature(bad, cert).isLeft)
    // Assertion だけの署名
    val onlyA = Saml.buildResponse(params(false, true), kp.getPrivate, cert)
    assert(Saml.verifyPostSignature(onlyA, cert).isLeft) // Response には署名がない
    val d2 = Xml.parse(onlyA).toOption.get
    assertEquals(Saml.verifyElementSignature(find(d2, Xml.Assertion, "Assertion").head, cert), Right(()))
  }

  test("ECDSA の鍵でも署名できる") {
    val ec = Jose.generate("ES256")
    val ecc = Jose.selfSignedCert(ec, "ec")
    val xml = Saml.buildResponse(params(true, false), ec.getPrivate, ecc)
    assertEquals(Saml.verifyPostSignature(xml, ecc), Right(()))
  }

  test("HTTP-Redirect の署名") {
    val req = enc(Saml.encodeRedirect(authnXml))
    val relay = enc("https://sp.example/page?x=1&y=2")
    val sigAlg = enc("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
    val signed = s"SAMLRequest=$req&RelayState=$relay&SigAlg=$sigAlg"
    val s = Signature.getInstance("SHA256withRSA")
    s.initSign(kp.getPrivate)
    s.update(signed.getBytes(StandardCharsets.UTF_8))
    val sig = enc(Base64.getEncoder.encodeToString(s.sign()))
    // 順序が違っても元の値で検証する
    val q = s"SigAlg=$sigAlg&Signature=$sig&SAMLRequest=$req&RelayState=$relay"
    assertEquals(Saml.verifyRedirectSignature(q, cert), Right(()))
    assert(Saml.verifyRedirectSignature(q.replace(relay, enc("https://evil.example/")), cert).isLeft)
    assert(Saml.verifyRedirectSignature(s"SAMLRequest=$req&RelayState=$relay&SigAlg=$sigAlg", cert).isLeft)
    assert(Saml.verifyRedirectSignature(q + s"&SAMLRequest=$req", cert).isLeft)
    // 符号化したキーで、検証する値と使う値をすり替えられない
    val forged = s"SAML%52equest=${enc(Saml.encodeRedirect("<x/>"))}&" + q
    assert(Saml.verifyRedirectSignature(forged, cert).isLeft)
    assert(Saml.redirectParams(forged).isLeft)
    assertEquals(Saml.redirectParams(q).map(_.get("RelayState")), Right(Some("https://sp.example/page?x=1&y=2")))
    // SHA-1 は受け付けない
    assert(Saml.verifyRedirectSignature(
      q.replace(sigAlg, enc("http://www.w3.org/2000/09/xmldsig#rsa-sha1")),
      cert
    ).isLeft)
    // 自前の署名関数（ECDSA も）
    assertEquals(
      Saml.verifyRedirectSignature(Saml.signRedirectQuery(s"SAMLRequest=$req", kp.getPrivate), cert),
      Right(())
    )
    val ec = Jose.generate("ES256")
    assertEquals(
      Saml.verifyRedirectSignature(
        Saml.signRedirectQuery(s"SAMLResponse=$req&RelayState=r", ec.getPrivate),
        Jose.selfSignedCert(ec, "ec")
      ),
      Right(())
    )
  }

  test("HTTP-POST の署名と署名ラッピング攻撃") {
    val doc = Xml.parse(authnXml).toOption.get
    signWithJdk(doc.getDocumentElement, kp.getPrivate)
    val signed = Xml.serialize(doc)
    assertEquals(Saml.verifyPostSignature(signed, cert), Right(()))
    assert(Saml.verifyPostSignature(signed.replace("https://sp.example/acs", "https://evil.example/acs"), cert).isLeft)

    // 署名済みの要求を子に入れ、署名をルートへ移す（参照先がルートではない）
    val d1 = Xml.parse(signed).toOption.get
    val orig = d1.getDocumentElement
    val sig = Xml.child(orig, Xml.DSig, "Signature").get
    val evil = Xml.parse(authnXml.replace(
      "_req1",
      "_evil"
    ).replace("https://sp.example/acs", "https://evil.example/acs")).toOption.get
    val root = evil.getDocumentElement
    root.appendChild(evil.importNode(sig, true))
    val inner = evil.importNode(orig, true)
    Xml.child(inner.asInstanceOf[Element], Xml.DSig, "Signature").foreach(inner.removeChild)
    root.appendChild(inner)
    assert(Saml.verifyPostSignature(Xml.serialize(evil), cert).isLeft)

    // 同じ ID の偽のルートが、署名済みの本物を子に持つ
    val evil2 = Xml.parse(authnXml.replace("https://sp.example/acs", "https://evil.example/acs")).toOption.get
    evil2.getDocumentElement.appendChild(evil2.importNode(d1.getDocumentElement, true))
    assert(Saml.verifyPostSignature(Xml.serialize(evil2), cert).isLeft)

    // 署名のない要求
    assert(Saml.verifyPostSignature(authnXml, cert).isLeft)
  }

  test("メタデータと DOCTYPE の拒否") {
    val spMeta =
      s"""<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://sp.example/metadata">
         | <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" AuthnRequestsSigned="true">
         |  <md:KeyDescriptor use="encryption"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>AAAA</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
         |  <md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>
         |${Base64.getMimeEncoder.encodeToString(cert.getEncoded)}
         |  </ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
         |  <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://sp.example/slo"/>
         |  <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact" Location="https://sp.example/art" index="0"/>
         |  <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example/acs" index="1"/>
         | </md:SPSSODescriptor>
         |</md:EntityDescriptor>""".stripMargin
    val m = Saml.parseSpMetadata(spMeta).toOption.get
    assertEquals(m.entityId, "https://sp.example/metadata")
    assertEquals(m.acsUrl, Some("https://sp.example/acs"))
    assertEquals(m.acsBinding, Some("post"))
    assertEquals(m.sloUrl, Some("https://sp.example/slo"))
    assertEquals(Jose.parseCerts(m.certificatePem.get).map(_.head), Right(cert))

    val idp = Saml.idpMetadata("https://idp.example", "https://idp.example/sso", "https://idp.example/slo", cert)
    assert(idp.contains(Jose.certBase64(cert)))
    assert(idp.contains("""Location="https://idp.example/sso""""))
    assert(idp.contains(Saml.BindingRedirect) && idp.contains(Saml.BindingPost))
    assert(idp.contains("WantAuthnRequestsSigned=\"false\""))
    assert(Xml.parse(idp).isRight)

    val xxe =
      """<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>
        |<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="a" Version="2.0">&x;</samlp:AuthnRequest>""".stripMargin
    assert(Xml.parse(xxe).isLeft)
    assert(Saml.parseAuthnRequest(xxe).isLeft)
    assert(Saml.parseSpMetadata(xxe).isLeft)
  }

  test("IssueInstant のない要求は拒否する") {
    val noTime =
      """<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        | ID="_lo2" Version="2.0"><saml:Issuer>https://sp.example/metadata</saml:Issuer></samlp:LogoutRequest>""".stripMargin
    assert(Saml.parseLogoutRequest(noTime).isLeft)
    val noTimeAuthn =
      """<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        | ID="_a2" Version="2.0"><saml:Issuer>https://sp.example/metadata</saml:Issuer></samlp:AuthnRequest>""".stripMargin
    assert(Saml.parseAuthnRequest(noTimeAuthn).isLeft)
  }

  test("ログアウトの要求と応答") {
    val lr =
      """<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        | ID="_lo1" Version="2.0" IssueInstant="2026-11-16T10:00:00Z" Destination="https://idp.example/slo">
        | <saml:Issuer>https://sp.example/metadata</saml:Issuer>
        | <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">alice@example.com</saml:NameID>
        | <samlp:SessionIndex>_s1</samlp:SessionIndex><samlp:SessionIndex>_s2</samlp:SessionIndex>
        |</samlp:LogoutRequest>""".stripMargin
    val r = Saml.decodeRedirect(Saml.encodeRedirect(lr)).flatMap(Saml.parseLogoutRequest).toOption.get
    assertEquals(
      r,
      LogoutRequest(
        "_lo1",
        "https://sp.example/metadata",
        Some("alice@example.com"),
        List("_s1", "_s2"),
        Some("https://idp.example/slo"),
        Instant.parse("2026-11-16T10:00:00Z")
      )
    )

    val xml = Saml.buildLogoutResponse(
      "https://idp.example",
      "https://sp.example/slo",
      "_lo1",
      Saml.StatusSuccess,
      now,
      kp.getPrivate,
      cert
    )
    assertEquals(Saml.verifyPostSignature(xml, cert), Right(()))
    val d = Xml.parse(xml).toOption.get.getDocumentElement
    assertEquals(d.getLocalName, "LogoutResponse")
    assertEquals(d.getAttribute("InResponseTo"), "_lo1")
    assertEquals(d.getAttribute("IssueInstant"), "2026-11-16T10:00:00Z")
    assert(xml.contains(Saml.StatusSuccess))

    val err = Saml.buildErrorResponse(
      "https://idp.example",
      "https://sp.example/acs",
      Some("_req1"),
      Saml.StatusResponder,
      Some("urn:oasis:names:tc:SAML:2.0:status:RequestDenied"),
      Some("許可されていません"),
      now,
      kp.getPrivate,
      cert
    )
    assertEquals(Saml.verifyPostSignature(err, cert), Right(()))
    assert(err.contains("RequestDenied") && !err.contains("Assertion"))
  }

  test("POST のフォームはエスケープする") {
    val h = Saml.postForm("https://sp.example/acs?a=1&b=\"2\"", "SAMLResponse", "<x/>", Some("<script>"), "n0nce")
    assert(h.contains("""action="https://sp.example/acs?a=1&amp;b=&quot;2&quot;""""))
    assert(h.contains("&lt;script&gt;"))
    assert(h.contains("""<script nonce="n0nce">document.forms[0].submit()</script>"""))
    assert(h.contains(Base64.getEncoder.encodeToString("<x/>".getBytes)))
    assert(h.contains("<noscript>"))
  }
}
