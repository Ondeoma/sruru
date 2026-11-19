package sruru.saml

import org.w3c.dom.{Document, Element, Node}

import java.io.{ByteArrayInputStream, StringWriter}
import java.nio.charset.StandardCharsets
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.time.temporal.ChronoUnit
import java.time.{Instant, OffsetDateTime}
import java.time.format.DateTimeFormatter
import javax.xml.XMLConstants
import javax.xml.crypto.dsig.*
import javax.xml.crypto.dsig.dom.{DOMSignContext, DOMValidateContext}
import javax.xml.crypto.dsig.spec.{C14NMethodParameterSpec, ExcC14NParameterSpec, TransformParameterSpec}
import javax.xml.crypto.KeySelector
import javax.xml.parsers.DocumentBuilderFactory
import javax.xml.transform.{OutputKeys, TransformerFactory}
import javax.xml.transform.dom.DOMSource
import javax.xml.transform.stream.StreamResult
import scala.jdk.CollectionConverters.*
import scala.util.Try

/** XML の安全な読み書きと、XML 署名（enveloped）. */
object Xml {
  val Protocol = "urn:oasis:names:tc:SAML:2.0:protocol"
  val Assertion = "urn:oasis:names:tc:SAML:2.0:assertion"
  val Metadata = "urn:oasis:names:tc:SAML:2.0:metadata"
  val DSig = XMLSignature.XMLNS
  val XS = XMLConstants.W3C_XML_SCHEMA_NS_URI
  val XSI = XMLConstants.W3C_XML_SCHEMA_INSTANCE_NS_URI
  private val XmlnsNs = XMLConstants.XMLNS_ATTRIBUTE_NS_URI

  /** 読める XML の上限（文字数）. */
  val MaxXmlChars: Int = 1024 * 1024

  private def factory(): DocumentBuilderFactory = {
    val f = DocumentBuilderFactory.newDefaultInstance()
    f.setNamespaceAware(true)
    f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)
    f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
    f.setFeature("http://xml.org/sax/features/external-general-entities", false)
    f.setFeature("http://xml.org/sax/features/external-parameter-entities", false)
    f.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false)
    f.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "")
    f.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "")
    f.setXIncludeAware(false)
    f.setExpandEntityReferences(false)
    f.setValidating(false)
    f
  }

  /** 安全な設定で XML を読む（DOCTYPE・外部実体・XInclude は使えない）. */
  def parse(
    xml: String
  ): Either[String, Document] =
    if xml.length > MaxXmlChars then Left("XML が大きすぎます")
    else
      Try {
        val b = factory().newDocumentBuilder()
        b.setErrorHandler(null)
        b.parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)))
      }.toEither.left.map(_ => "XML を読めません")

  def newDocument(): Document = factory().newDocumentBuilder().newDocument()

  /** XML 宣言なしで文字列にする. */
  def serialize(
    n: Node
  ): String = {
    val tf = TransformerFactory.newDefaultInstance()
    tf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)
    tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "")
    tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "")
    val t = tf.newTransformer()
    t.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes")
    t.setOutputProperty(OutputKeys.ENCODING, "UTF-8")
    t.setOutputProperty(OutputKeys.INDENT, "no")
    val w = new StringWriter()
    t.transform(new DOMSource(n), new StreamResult(w))
    w.toString
  }

  // ------------------------------------------------------------------ DOM

  def children(
    e: Element,
    ns: String,
    local: String
  ): List[Element] = {
    val nl = e.getChildNodes
    (0 until nl.getLength).iterator.map(nl.item).collect {
      case c: Element if c.getNamespaceURI == ns && c.getLocalName == local => c
    }.toList
  }

  def child(
    e: Element,
    ns: String,
    local: String
  ): Option[Element] = children(e, ns, local).headOption

  /** 子孫（自分を含まない）. */
  def descendants(
    e: Element,
    ns: String,
    local: String
  ): List[Element] = {
    val nl = e.getElementsByTagNameNS(ns, local)
    (0 until nl.getLength).iterator.map(i => nl.item(i).asInstanceOf[Element]).toList
  }

  def text(
    e: Element
  ): String = Option(e.getTextContent).getOrElse("").trim

  def attr(
    e: Element,
    name: String
  ): Option[String] =
    Option(e.getAttributeNS(null, name)).map(_.trim).filter(_.nonEmpty)

  /** 要素を作る（属性は名前空間なし。値は DOM がエスケープする）. */
  def el(
    doc: Document,
    ns: String,
    qname: String,
    attrs: Seq[(String, String)] = Nil,
    text: Option[String] = None
  )(
    kids: Element*
  ): Element = {
    val e = doc.createElementNS(ns, qname)
    attrs.foreach(
      (
        k,
        v
      ) => e.setAttributeNS(null, k, v)
    )
    text.foreach(t => e.appendChild(doc.createTextNode(t)))
    kids.foreach(e.appendChild)
    e
  }

  def declare(
    e: Element,
    prefix: String,
    ns: String
  ): Unit =
    e.setAttributeNS(XmlnsNs, s"xmlns:$prefix", ns)

  // ------------------------------------------------------------------ 日時

  def instant(
    i: Instant
  ): String = DateTimeFormatter.ISO_INSTANT.format(i.truncatedTo(ChronoUnit.SECONDS))

  def parseInstant(
    s: String
  ): Option[Instant] = Try(OffsetDateTime.parse(s.trim).toInstant).toOption

  // ------------------------------------------------------------------ 署名

  private def sigFactory = XMLSignatureFactory.getInstance("DOM")

  private val AllowedTransforms = Set(
    Transform.ENVELOPED,
    CanonicalizationMethod.EXCLUSIVE,
    CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS,
    CanonicalizationMethod.INCLUSIVE,
    CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS
  )

  /** 要素に enveloped 署名を付ける（署名は after の直後に置く）. */
  def sign(
    target: Element,
    after: Element,
    key: PrivateKey,
    cert: X509Certificate
  ): Unit = {
    val f = sigFactory
    val id = target.getAttributeNS(null, "ID")
    target.setIdAttributeNS(null, "ID", true)
    val transforms = List(
      f.newTransform(Transform.ENVELOPED, null.asInstanceOf[TransformParameterSpec]),
      // xsi:type="xs:string" の xs を正規化で落とさない
      f.newTransform(CanonicalizationMethod.EXCLUSIVE, new ExcC14NParameterSpec(List("xs").asJava))
    )
    val ref = f.newReference("#" + id, f.newDigestMethod(DigestMethod.SHA256, null), transforms.asJava, null, null)
    val method = if key.getAlgorithm == "EC" then SignatureMethod.ECDSA_SHA256 else SignatureMethod.RSA_SHA256
    val si = f.newSignedInfo(
      f.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE, null.asInstanceOf[C14NMethodParameterSpec]),
      f.newSignatureMethod(method, null),
      List(ref).asJava
    )
    val kif = f.getKeyInfoFactory
    val ki = kif.newKeyInfo(List(kif.newX509Data(List(cert).asJava)).asJava)
    val ctx = new DOMSignContext(key, target, after.getNextSibling)
    ctx.setDefaultNamespacePrefix("ds")
    f.newXMLSignature(si, ki).sign(ctx)
  }

  /** 要素の直下にある enveloped 署名を、指定の証明書の鍵だけで検証する（参照先は要素自身に限る）. */
  def verify(
    target: Element,
    cert: X509Certificate
  ): Either[String, Unit] = {
    val id = target.getAttributeNS(null, "ID")
    if id == null || id.isEmpty then Left("ID がありません")
    else
      children(target, DSig, "Signature") match {
        case Nil => Left("署名がありません")
        case sig :: Nil =>
          val doc = target.getOwnerDocument
          val dups = descendants(doc.getDocumentElement, "*", "*").count(_.getAttributeNS(null, "ID") == id) +
            (if doc.getDocumentElement.getAttributeNS(null, "ID") == id then 1 else 0)
          if dups != 1 then Left("ID が重複しています")
          else {
            target.setIdAttributeNS(null, "ID", true)
            Try {
              val ctx = new DOMValidateContext(KeySelector.singletonKeySelector(cert.getPublicKey), sig)
              ctx.setProperty("org.jcp.xml.dsig.secureValidation", java.lang.Boolean.TRUE)
              ctx.setIdAttributeNS(target, null, "ID")
              val s = sigFactory.unmarshalXMLSignature(ctx)
              val refs = s.getSignedInfo.getReferences.asScala.toList.map(_.asInstanceOf[Reference])
              val refOk = refs match {
                case r :: Nil =>
                  r.getURI == "#" + id &&
                  r.getTransforms.asScala.forall(t => AllowedTransforms(t.asInstanceOf[Transform].getAlgorithm))
                case _ => false
              }
              if !refOk then Left("署名の参照先が不正です")
              else if s.validate(ctx) then Right(())
              else Left("署名が一致しません")
            }.toEither.left.map(_ => "署名を検証できません").flatten
          }
        case _ => Left("署名が複数あります")
      }
  }
}
