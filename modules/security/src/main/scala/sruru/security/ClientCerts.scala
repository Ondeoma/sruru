package sruru.security

import cats.syntax.all.*

import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.security.cert.*
import java.time.Instant
import javax.naming.ldap.LdapName
import scala.jdk.CollectionConverters.*

/** クライアント証明書の検証と、ユーザーとの対応付けに使う値. */
final case class CertInfo(fingerprint: String,
                          subject: String,
                          issuer: String,
                          notAfter: Instant,
                          cn: Option[String],
                          emails: List[String],
                          upns: List[String])

object ClientCerts {

  private val UpnOid = "1.3.6.1.4.1.311.20.2.3"

  def fingerprint(c: X509Certificate): String = Crypto.hex(Crypto.sha256(c.getEncoded))

  /**
   * リバースプロキシが渡すヘッダーの値（PEM. nginx の $ssl_client_escaped_cert のように URL エンコードされていてもよい.
   * 改行がスペースになっている形も受け付ける）.
   */
  def fromHeader(v: String): Either[String, X509Certificate] = {
    val decoded = if v.contains("%") then URLDecoder.decode(v, StandardCharsets.UTF_8) else v
    val body =
      decoded.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").replaceAll("\\s+", "")
    val pem = "-----BEGIN CERTIFICATE-----\n" + body.grouped(64).mkString("\n") + "\n-----END CERTIFICATE-----\n"
    Jose.parseCerts(pem).map(_.head)
  }

  def info(c: X509Certificate): CertInfo = {
    val sans = Option(c.getSubjectAlternativeNames).map(_.asScala.toList.map(_.asScala.toList)).getOrElse(Nil)
    val emails = sans.collect { case (t: Integer) :: (v: String) :: Nil if t.intValue == 1 => v.toLowerCase }
    // otherName（UPN）は DER のまま返るので、UTF8String を取り出す
    val upns =
      sans.collect { case (t: Integer) :: (v: Array[Byte]) :: Nil if t.intValue == 0 => v }.flatMap(otherNameUpn)
    val subject = c.getSubjectX500Principal.getName
    val cn = scala.util.Try(
      new LdapName(subject).getRdns.asScala.reverse.find(_.getType.equalsIgnoreCase("CN")).map(_.getValue.toString)
    ).toOption.flatten
    val subjectEmail = scala.util.Try(new LdapName(subject).getRdns.asScala.find(r =>
      r.getType.equalsIgnoreCase("EMAILADDRESS") || r.getType == "1.2.840.113549.1.9.1"
    )
      .map(_.getValue.toString.toLowerCase)).toOption.flatten
    CertInfo(
      fingerprint(c),
      subject,
      c.getIssuerX500Principal.getName,
      c.getNotAfter.toInstant,
      cn,
      (emails ++ subjectEmail).distinct,
      upns
    )
  }

  private def otherNameUpn(der: Array[Byte]): Option[String] =
    scala.util.Try {
      import org.bouncycastle.asn1.*
      val seq = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(der))
      val oid = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0))
      if oid.getId != UpnOid then None
      else {
        var obj: ASN1Encodable = seq.getObjectAt(1)
        while obj.isInstanceOf[ASN1TaggedObject] do obj = obj.asInstanceOf[ASN1TaggedObject].getBaseObject
        Some(obj.toString.toLowerCase)
      }
    }.toOption.flatten

  /** 信頼する CA から証明書のチェーンを検証する（失効の確認はしない. 期限・署名・用途を確かめる）. */
  def validate(chain: List[X509Certificate],
               cas: List[X509Certificate],
               now: Instant): Either[String, X509Certificate] =
    chain.headOption.toRight("証明書がありません").flatMap { leaf =>
      if cas.isEmpty then Left("信頼する認証局が登録されていません")
      else
        Either.catchNonFatal {
          val anchors = cas.map(c => new TrustAnchor(c, null)).toSet.asJava
          val params = new PKIXParameters(anchors)
          params.setRevocationEnabled(false)
          params.setDate(java.util.Date.from(now))
          val cf = CertificateFactory.getInstance("X.509")
          // チェーンの末尾が CA 自身なら除く（CertPath には含めない）
          val path = cf.generateCertPath(chain.filterNot(c => cas.exists(_.equals(c))).asJava)
          CertPathValidator.getInstance("PKIX").validate(path, params)
          // TLS クライアント認証の用途（拡張鍵用途があれば clientAuth を含むこと）
          Option(leaf.getExtendedKeyUsage).map(_.asScala.toList).foreach { eku =>
            if !eku.contains("1.3.6.1.5.5.7.3.2") && !eku.contains("2.5.29.37.0") then
              throw new CertificateException("クライアント認証に使えない証明書です")
          }
          leaf
        }.leftMap(e => s"証明書を検証できません: ${e.getMessage}")
    }
}
