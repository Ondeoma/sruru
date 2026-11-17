package sruru.saml

import org.w3c.dom.{Document, Element}
import sruru.security.{Crypto, Jose}

import java.io.ByteArrayOutputStream
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.security.{PrivateKey, Signature}
import java.security.cert.X509Certificate
import java.time.Instant
import java.util.Base64
import java.util.zip.{Deflater, Inflater}
import scala.util.Try

import Xml.*

final case class AuthnRequest(id: String, issuer: String, acsUrl: Option[String], protocolBinding: Option[String],
  forceAuthn: Boolean, isPassive: Boolean, nameIdFormat: Option[String], destination: Option[String], issueInstant: Instant)

final case class LogoutRequest(id: String, issuer: String, nameId: Option[String], sessionIndexes: List[String], destination: Option[String],
  issueInstant: Instant)

final case class SamlAttribute(name: String, friendlyName: Option[String], values: List[String])

final case class AssertionParams(
  idpEntityId: String, spEntityId: String, acsUrl: String, inResponseTo: Option[String],
  nameId: String, nameIdFormat: String, sessionIndex: String, authnInstant: Instant,
  authnContextClassRef: String,
  attributes: List[SamlAttribute], now: Instant, validSeconds: Int,
  sessionNotOnOrAfter: Option[Instant], signResponse: Boolean, signAssertion: Boolean)

final case class SpMetadata(entityId: String, acsUrl: Option[String], acsBinding: Option[String], sloUrl: Option[String], certificatePem: Option[String])

/** SAML 2.0 の IdP の処理（HTTP には依存しない）. */
object Saml:
  val BindingRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
  val BindingPost     = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
  val StatusSuccess   = "urn:oasis:names:tc:SAML:2.0:status:Success"
  val StatusRequester = "urn:oasis:names:tc:SAML:2.0:status:Requester"
  val StatusResponder = "urn:oasis:names:tc:SAML:2.0:status:Responder"
  val Bearer          = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
  val PasswordProtectedTransport = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"

  object NameIdFormat:
    val Email       = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    val Persistent  = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
    val Transient   = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
    val Unspecified = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
    val all         = List(Email, Persistent, Transient, Unspecified)

  private val AttrUri   = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
  private val AttrBasic = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"

  /** 展開後の上限. */
  private val MaxInflated = 256 * 1024

  /** 応答などの ID（"_" + 乱数の16進）. */
  def newId(): String = "_" + Crypto.hex(Crypto.randomBytes(20))

  // ------------------------------------------------------------------ バインディング

  private def b64decode(s: String): Either[String, Array[Byte]] =
    if s.length > MaxXmlChars * 2 then Left("SAMLRequest が大きすぎます")
    else Try(Base64.getMimeDecoder.decode(s.trim.replace(' ', '+'))).toEither.left.map(_ => "SAMLRequest を読めません")

  /** HTTP-Redirect: base64 を戻して DEFLATE を展開する（値は URL デコード済みのもの）. */
  def decodeRedirect(param: String): Either[String, String] =
    b64decode(param).flatMap { bytes =>
      Try {
        val inf = new Inflater(true)
        try
          inf.setInput(bytes)
          val out = new ByteArrayOutputStream()
          val buf = new Array[Byte](8192)
          while !inf.finished() && !inf.needsInput() && out.size() <= MaxInflated do
            val n = inf.inflate(buf)
            if n == 0 && inf.needsDictionary() then throw new IllegalArgumentException("dictionary")
            out.write(buf, 0, n)
          if out.size() > MaxInflated || !inf.finished() then throw new IllegalArgumentException("invalid")
          out.toString(StandardCharsets.UTF_8)
        finally inf.end()
      }.toEither.left.map(_ => "SAMLRequest を読めません").filterOrElse(_.nonEmpty, "SAMLRequest を読めません")
    }

  /** HTTP-POST: base64 を戻す. */
  def decodePost(param: String): Either[String, String] =
    b64decode(param).map(b => new String(b, StandardCharsets.UTF_8)).filterOrElse(_.nonEmpty, "SAMLRequest を読めません")

  /** DEFLATE して base64 にする（URL エンコードは呼び出し側で行う）. */
  def encodeRedirect(xml: String): String =
    val d = new Deflater(Deflater.DEFLATED, true)
    try
      d.setInput(xml.getBytes(StandardCharsets.UTF_8))
      d.finish()
      val out = new ByteArrayOutputStream()
      val buf = new Array[Byte](8192)
      while !d.finished() do out.write(buf, 0, d.deflate(buf))
      Base64.getEncoder.encodeToString(out.toByteArray)
    finally d.end()

  // ------------------------------------------------------------------ 要求の解析

  private def root(xml: String, local: String): Either[String, Element] =
    parse(xml).flatMap { doc =>
      val r = doc.getDocumentElement
      if r.getNamespaceURI == Protocol && r.getLocalName == local then Right(r)
      else Left(s"$local ではありません")
    }

  private def issuerOf(r: Element): Either[String, String] =
    child(r, Assertion, "Issuer").map(text).filter(_.nonEmpty).toRight("Issuer がありません")

  /** ID と発行時刻（どちらも必須）. */
  private def common(r: Element): Either[String, (String, Instant)] =
    for
      id <- attr(r, "ID").toRight("ID がありません")
      _  <- Either.cond(attr(r, "Version").contains("2.0"), (), "SAML 2.0 ではありません")
      ii <- attr(r, "IssueInstant").flatMap(parseInstant).toRight("IssueInstant がないか不正です")
    yield (id, ii)

  private def bool(r: Element, name: String): Boolean = attr(r, name).exists(v => v == "true" || v == "1")

  def parseAuthnRequest(xml: String): Either[String, AuthnRequest] =
    for
      r      <- root(xml, "AuthnRequest")
      idIi     <- common(r)
      (id, ii)  = idIi
      issuer   <- issuerOf(r)
    yield AuthnRequest(
      id = id,
      issuer = issuer,
      acsUrl = attr(r, "AssertionConsumerServiceURL"),
      protocolBinding = attr(r, "ProtocolBinding"),
      forceAuthn = bool(r, "ForceAuthn"),
      isPassive = bool(r, "IsPassive"),
      nameIdFormat = child(r, Protocol, "NameIDPolicy").flatMap(attr(_, "Format")),
      destination = attr(r, "Destination"),
      issueInstant = ii
    )

  def parseLogoutRequest(xml: String): Either[String, LogoutRequest] =
    for
      r      <- root(xml, "LogoutRequest")
      idIi     <- common(r)
      (id, ii)  = idIi
      issuer   <- issuerOf(r)
    yield LogoutRequest(
      id = id,
      issuer = issuer,
      nameId = child(r, Assertion, "NameID").map(text).filter(_.nonEmpty),
      sessionIndexes = children(r, Protocol, "SessionIndex").map(text).filter(_.nonEmpty),
      destination = attr(r, "Destination"),
      issueInstant = ii
    )

  // ------------------------------------------------------------------ 署名の検証

  private def redirectAlg(uri: String): Option[List[String]] = uri match
    case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"   => Some(List("SHA256withRSA"))
    case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"   => Some(List("SHA384withRSA"))
    case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"   => Some(List("SHA512withRSA"))
    // ECDSA は DER と r||s のどちらもありうる
    case "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256" => Some(List("SHA256withECDSA", "SHA256withECDSAinP1363Format"))
    case _                                                     => None

  private def urlDecode(s: String): String = URLDecoder.decode(s, StandardCharsets.UTF_8)

  /**
   * HTTP-Redirect のクエリを (復号したキー, 受け取ったままの値) に分ける. キーの重複は拒否する
   * （SAML%52equest のように符号化したキーで、検証する値と処理する値をすり替えられないように）.
   */
  private def rawPairs(rawQuery: String): Either[String, List[(String, String)]] =
    val pairs = rawQuery.split('&').toList.filter(_.nonEmpty).map { p =>
      val i = p.indexOf('=')
      if i < 0 then (p, "") else (p.take(i), p.drop(i + 1))
    }
    Try(pairs.map((k, v) => (urlDecode(k), v))).toEither.left.map(_ => "クエリを読めません").flatMap { ps =>
      ps.groupBy(_._1).collectFirst { case (k, vs) if vs.size > 1 => k }.toLeft(ps)
        .left.map(k => s"$k が重複しています")
    }

  /** HTTP-Redirect のクエリの値（キーの重複は拒否する）. 署名を検証した値と同じものを使うこと. */
  def redirectParams(rawQuery: String): Either[String, Map[String, String]] =
    rawPairs(rawQuery).flatMap(ps => Try(ps.map((k, v) => k -> urlDecode(v)).toMap).toEither.left.map(_ => "クエリを読めません"))

  /** HTTP-Redirect の署名を検証する（クエリは受け取ったままの URL エンコードされた文字列）. */
  def verifyRedirectSignature(rawQuery: String, cert: X509Certificate): Either[String, Unit] =
    def one(pairs: List[(String, String)], k: String): Either[String, Option[String]] = Right(pairs.find(_._1 == k).map(_._2))
    for
      pairs  <- rawPairs(rawQuery)
      req    <- one(pairs, "SAMLRequest")
      res    <- one(pairs, "SAMLResponse")
      msg    <- (req, res) match
                  case (Some(v), None) => Right("SAMLRequest" -> v)
                  case (None, Some(v)) => Right("SAMLResponse" -> v)
                  case _               => Left("SAMLRequest がありません")
      relay  <- one(pairs, "RelayState")
      sigAlg <- one(pairs, "SigAlg").flatMap(_.toRight("SigAlg がありません"))
      sigRaw <- one(pairs, "Signature").flatMap(_.toRight("署名がありません"))
      algs   <- Try(urlDecode(sigAlg)).toOption.flatMap(redirectAlg).toRight("対応していない署名方式です")
      sig    <- Try(Base64.getMimeDecoder.decode(urlDecode(sigRaw).replace(' ', '+'))).toEither.left.map(_ => "署名を読めません")
      signed  = (s"${msg._1}=${msg._2}" + relay.fold("")(r => s"&RelayState=$r") + s"&SigAlg=$sigAlg").getBytes(StandardCharsets.UTF_8)
      ok      = algs.exists { a =>
                  Try {
                    val s = Signature.getInstance(a)
                    s.initVerify(cert.getPublicKey)
                    s.update(signed)
                    s.verify(sig)
                  }.getOrElse(false)
                }
      _      <- Either.cond(ok, (), "署名が一致しません")
    yield ()

  /** HTTP-POST の XML のルート要素の enveloped 署名を検証する（KeyInfo は使わない）. */
  def verifyPostSignature(xml: String, cert: X509Certificate): Either[String, Unit] =
    parse(xml).flatMap(d => verifyElementSignature(d.getDocumentElement, cert))

  /** 要素の直下の enveloped 署名を検証する（参照先はその要素自身に限る）. */
  def verifyElementSignature(el: Element, cert: X509Certificate): Either[String, Unit] = Xml.verify(el, cert)

  // ------------------------------------------------------------------ 応答の作成

  private def issuer(doc: Document, entityId: String): Element = el(doc, Assertion, "saml:Issuer", text = Some(entityId))()

  private def status(doc: Document, code: String, sub: Option[String] = None, message: Option[String] = None): Element =
    val sc = el(doc, Protocol, "samlp:StatusCode", Seq("Value" -> code))(sub.map(s => el(doc, Protocol, "samlp:StatusCode", Seq("Value" -> s))()).toList*)
    val st = el(doc, Protocol, "samlp:Status")(sc)
    message.foreach(m => st.appendChild(el(doc, Protocol, "samlp:StatusMessage", text = Some(m))()))
    st

  /** samlp:Response 等のルートを作る. */
  private def protocolRoot(doc: Document, local: String, destination: String, inResponseTo: Option[String], now: Instant): Element =
    val r = el(doc, Protocol, s"samlp:$local",
      Seq("ID" -> newId(), "Version" -> "2.0", "IssueInstant" -> instant(now), "Destination" -> destination) ++
        inResponseTo.map("InResponseTo" -> _).toList)()
    declare(r, "samlp", Protocol)
    declare(r, "saml", Assertion)
    doc.appendChild(r)
    r

  private def assertion(doc: Document, p: AssertionParams): Element =
    val until = instant(p.now.plusSeconds(p.validSeconds.toLong))
    val a = el(doc, Assertion, "saml:Assertion", Seq("ID" -> newId(), "Version" -> "2.0", "IssueInstant" -> instant(p.now)))(
      issuer(doc, p.idpEntityId),
      el(doc, Assertion, "saml:Subject")(
        el(doc, Assertion, "saml:NameID", Seq("Format" -> p.nameIdFormat), Some(p.nameId))(),
        el(doc, Assertion, "saml:SubjectConfirmation", Seq("Method" -> Bearer))(
          el(doc, Assertion, "saml:SubjectConfirmationData",
            Seq("NotOnOrAfter" -> until, "Recipient" -> p.acsUrl) ++ p.inResponseTo.map("InResponseTo" -> _).toList)()
        )
      ),
      el(doc, Assertion, "saml:Conditions", Seq("NotBefore" -> instant(p.now), "NotOnOrAfter" -> until))(
        el(doc, Assertion, "saml:AudienceRestriction")(
          el(doc, Assertion, "saml:Audience", text = Some(p.spEntityId))()
        )
      ),
      el(doc, Assertion, "saml:AuthnStatement",
        Seq("AuthnInstant" -> instant(p.authnInstant), "SessionIndex" -> p.sessionIndex) ++
          p.sessionNotOnOrAfter.map(i => "SessionNotOnOrAfter" -> instant(i)).toList)(
        el(doc, Assertion, "saml:AuthnContext")(
          el(doc, Assertion, "saml:AuthnContextClassRef", text = Some(p.authnContextClassRef))()
        )
      )
    )
    declare(a, "saml", Assertion)
    declare(a, "xs", XS)
    declare(a, "xsi", XSI)
    val attrs = p.attributes.filter(_.values.nonEmpty)
    if attrs.nonEmpty then
      a.appendChild(el(doc, Assertion, "saml:AttributeStatement")(attrs.map { at =>
        val fmt = if at.name.startsWith("urn:") || at.name.contains("://") then AttrUri else AttrBasic
        el(doc, Assertion, "saml:Attribute", Seq("Name" -> at.name, "NameFormat" -> fmt) ++ at.friendlyName.map("FriendlyName" -> _).toList)(
          at.values.map { v =>
            val e = el(doc, Assertion, "saml:AttributeValue", text = Some(v))()
            e.setAttributeNS(XSI, "xsi:type", "xs:string")
            e
          }*
        )
      }*))
    a

  /** 認証の応答（Assertion を1つ含む samlp:Response）. */
  def buildResponse(p: AssertionParams, key: PrivateKey, cert: X509Certificate): String =
    val doc = newDocument()
    val r   = protocolRoot(doc, "Response", p.acsUrl, p.inResponseTo, p.now)
    val iss = r.appendChild(issuer(doc, p.idpEntityId)).asInstanceOf[Element]
    r.appendChild(status(doc, StatusSuccess))
    val a = r.appendChild(assertion(doc, p)).asInstanceOf[Element]
    // Assertion を先に署名し、その後で Response 全体を署名する
    if p.signAssertion then Xml.sign(a, child(a, Assertion, "Issuer").get, key, cert)
    if p.signResponse then Xml.sign(r, iss, key, cert)
    serialize(doc)

  /** エラーの応答（署名付き）. */
  def buildErrorResponse(idpEntityId: String, acsUrl: String, inResponseTo: Option[String], statusCode: String, subStatus: Option[String],
    message: Option[String], now: Instant, key: PrivateKey, cert: X509Certificate): String =
    val doc = newDocument()
    val r   = protocolRoot(doc, "Response", acsUrl, inResponseTo, now)
    val iss = r.appendChild(issuer(doc, idpEntityId)).asInstanceOf[Element]
    r.appendChild(status(doc, statusCode, subStatus, message))
    Xml.sign(r, iss, key, cert)
    serialize(doc)

  /** ログアウトの応答（成功・署名付き）. */
  def buildLogoutResponse(idpEntityId: String, destination: String, inResponseTo: String, statusCode: String, now: Instant, key: PrivateKey,
    cert: X509Certificate): String =
    val doc = newDocument()
    val r   = protocolRoot(doc, "LogoutResponse", destination, Some(inResponseTo), now)
    val iss = r.appendChild(issuer(doc, idpEntityId)).asInstanceOf[Element]
    r.appendChild(status(doc, statusCode))
    Xml.sign(r, iss, key, cert)
    serialize(doc)

  /** HTTP-Redirect で送る応答のクエリに署名を付ける（rsa-sha256 または ecdsa-sha256）.
    * query は "SAMLResponse=...&RelayState=..." の URL エンコード済みの文字列.
    */
  def signRedirectQuery(query: String, key: PrivateKey): String =
    val (uri, alg) =
      if key.getAlgorithm == "EC" then ("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", "SHA256withECDSA")
      else ("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", "SHA256withRSA")
    val signed = query + "&SigAlg=" + java.net.URLEncoder.encode(uri, StandardCharsets.UTF_8)
    val s      = Signature.getInstance(alg)
    s.initSign(key)
    s.update(signed.getBytes(StandardCharsets.UTF_8))
    signed + "&Signature=" + java.net.URLEncoder.encode(Base64.getEncoder.encodeToString(s.sign()), StandardCharsets.UTF_8)

  // ------------------------------------------------------------------ HTML

  private def html(s: String): String =
    s.flatMap {
      case '&'  => "&amp;"
      case '<'  => "&lt;"
      case '>'  => "&gt;"
      case '"'  => "&quot;"
      case '\'' => "&#39;"
      case c    => c.toString
    }

  /** 自動で POST するページ. */
  def postForm(action: String, field: String, xml: String, relayState: Option[String], nonce: String): String =
    val value = Base64.getEncoder.encodeToString(xml.getBytes(StandardCharsets.UTF_8))
    autoPost(action, (field -> value) :: relayState.map("RelayState" -> _).toList, nonce)

  /** 値をそのまま POST し直すページ（任意のフィールド）. */
  def autoPost(action: String, fields: List[(String, String)], nonce: String): String =
    val inputs = fields.map((k, v) => s"""<input type="hidden" name="${html(k)}" value="${html(v)}">""").mkString
    s"""<!DOCTYPE html>
       |<html><head><meta charset="utf-8"><title>sruru</title></head><body>
       |<form method="post" action="${html(action)}">$inputs
       |<noscript><p>JavaScript が無効です。ボタンを押して続けてください。</p><button type="submit">続ける</button></noscript>
       |</form>
       |<script nonce="${html(nonce)}">document.forms[0].submit()</script>
       |</body></html>
       |""".stripMargin

  // ------------------------------------------------------------------ メタデータ

  /** IdP のメタデータ. */
  def idpMetadata(entityId: String, ssoUrl: String, sloUrl: String, cert: X509Certificate): String =
    val doc = newDocument()
    def svc(local: String, binding: String, url: String) =
      el(doc, Metadata, s"md:$local", Seq("Binding" -> binding, "Location" -> url))()
    val idp = el(doc, Metadata, "md:IDPSSODescriptor",
      Seq("WantAuthnRequestsSigned" -> "false", "protocolSupportEnumeration" -> Protocol))(
      (List(
        el(doc, Metadata, "md:KeyDescriptor", Seq("use" -> "signing"))(
          el(doc, DSig, "ds:KeyInfo")(
            el(doc, DSig, "ds:X509Data")(
              el(doc, DSig, "ds:X509Certificate", text = Some(Jose.certBase64(cert)))()
            )
          )
        ),
        svc("SingleLogoutService", BindingRedirect, sloUrl),
        svc("SingleLogoutService", BindingPost, sloUrl)
      ) ++ NameIdFormat.all.map(f => el(doc, Metadata, "md:NameIDFormat", text = Some(f))()) ++ List(
        svc("SingleSignOnService", BindingRedirect, ssoUrl),
        svc("SingleSignOnService", BindingPost, ssoUrl)
      ))*
    )
    val ed = el(doc, Metadata, "md:EntityDescriptor", Seq("entityID" -> entityId))(idp)
    declare(ed, "md", Metadata)
    declare(ed, "ds", DSig)
    doc.appendChild(ed)
    serialize(doc)

  /** SP のメタデータを読む（アプリの設定の入力補助）. */
  def parseSpMetadata(xml: String): Either[String, SpMetadata] =
    parse(xml).flatMap { doc =>
      val r = doc.getDocumentElement
      val ed =
        if r.getNamespaceURI == Metadata && r.getLocalName == "EntityDescriptor" then Some(r)
        else if r.getNamespaceURI == Metadata && r.getLocalName == "EntitiesDescriptor" then descendants(r, Metadata, "EntityDescriptor").headOption
        else None
      for
        e        <- ed.toRight("SP のメタデータではありません")
        entityId <- attr(e, "entityID").toRight("entityID がありません")
        sp       <- child(e, Metadata, "SPSSODescriptor").toRight("SPSSODescriptor がありません")
        pem      <- signingCert(sp)
      yield
        val acs = children(sp, Metadata, "AssertionConsumerService")
        val chosen = acs.find(a => attr(a, "Binding").contains(BindingPost))
          .orElse(acs.find(a => attr(a, "Binding").contains(BindingRedirect)))
          .orElse(acs.headOption)
        SpMetadata(
          entityId = entityId,
          acsUrl = chosen.flatMap(attr(_, "Location")),
          acsBinding = chosen.flatMap(attr(_, "Binding")).collect {
            case BindingPost     => "post"
            case BindingRedirect => "redirect"
          },
          sloUrl = children(sp, Metadata, "SingleLogoutService").flatMap(attr(_, "Location")).headOption,
          certificatePem = pem
        )
    }

  private def signingCert(sp: Element): Either[String, Option[String]] =
    val kd = children(sp, Metadata, "KeyDescriptor").filter(k => attr(k, "use").forall(_ == "signing"))
    kd.flatMap(descendants(_, DSig, "X509Certificate")).map(text).find(_.nonEmpty) match
      case None => Right(None)
      case Some(b64) =>
        val body = b64.filterNot(_.isWhitespace)
        val pem  = "-----BEGIN CERTIFICATE-----\n" + body.grouped(64).mkString("\n") + "\n-----END CERTIFICATE-----\n"
        Jose.parseCerts(pem).map(cs => Some(Jose.certPem(cs.head)))
