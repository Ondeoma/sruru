package sruru.api

import cats.effect.*
import org.http4s.*
import sruru.core.*
import sruru.db.*
import sruru.shared.*

import java.util.UUID

/** 共通の変換と画像の受け取り. */
object Conv {

  /** ロゴの画像の大きさの上限 */
  val MaxLogoBytes: Int = 512 * 1024

  def token(
    t: ApiToken,
    owner: Option[UserBrief] = None
  ): ApiTokenDto =
    ApiTokenDto(t.id, t.name, t.prefix, t.scopes, t.expiresAt, t.lastUsedAt, t.createdAt, owner, t.oauthClient)

  def session(
    l: Login,
    current: Option[UUID]
  ): LoginSessionDto =
    LoginSessionDto(l.id, l.ip, l.userAgent, l.createdAt, l.lastSeenAt, l.amr, current.contains(l.id))

  def cert(
    c: UserCert
  ): UserCertDto = UserCertDto(c.id, c.fingerprint, c.subject, c.issuer, c.notAfter, c.createdAt)

  def attrDef(
    d: AttributeDef
  ): AttributeDefDto =
    AttributeDefDto(d.key, d.label, d.kind, d.description, d.userEditable, d.required, d.scimPath, d.sort)

  private val imageTypes = Set("image/png", "image/jpeg", "image/webp", "image/gif")

  val Svg = "image/svg+xml"

  /**
   * 本文の画像を読む（種類と大きさを確かめる）. allowSvg はロゴだけ（配信のときに CSP でスクリプトを止める）.
   * SVG は中身が SVG であることと、スクリプト・外部の参照を含まないことも確かめる.
   */
  def readImage(
    req: Request[IO],
    max: Int,
    allowSvg: Boolean = false
  ): IO[Either[String, (Array[Byte], String)]] = {
    val ct = req.contentType.map(c => s"${c.mediaType.mainType}/${c.mediaType.subType}").getOrElse("")
    if !imageTypes(ct) && !(allowSvg && ct == Svg) then
      IO.pure(Left(if allowSvg then "PNG・JPEG・WebP・GIF・SVG の画像を送ってください" else "PNG・JPEG・WebP・GIF の画像を送ってください"))
    else
      req.body.take(max.toLong + 1).compile.to(Array).map { b =>
        if b.length > max then Left(s"画像は ${max / 1024}KB 以下にしてください")
        else if b.isEmpty then Left("画像が空です")
        else if ct == Svg && !safeSvg(new String(b, java.nio.charset.StandardCharsets.UTF_8)) then
          Left("SVG にスクリプト・イベントの属性・外部の参照は含められません")
        else Right((b, ct))
      }
  }

  /** SVG にスクリプト・イベントの属性・外部の参照がないか. */
  def safeSvg(
    s: String
  ): Boolean = {
    val t = s.toLowerCase
    t.contains("<svg") &&
    !List("<script", "javascript:", "<foreignobject", "<!entity", "<iframe", "<embed", "<object").exists(t.contains) &&
    !"""\son[a-z]+\s*=""".r.findFirstIn(t).isDefined &&
    !"""(href|src)\s*=\s*["']?\s*(https?:|//|data:)""".r.findFirstIn(t).isDefined
  }
}
