package sruru.core

import java.net.InetAddress

/** IP アドレスの範囲（CIDR）. IPv4 と IPv6 を扱う（IPv4 射影の IPv6 アドレスは IPv4 として比べる）. */
final case class Cidr(
  network: Array[Byte],
  prefix: Int) {
  def contains(
    addr: Array[Byte]
  ): Boolean =
    addr.length == network.length && {
      val full = prefix / 8
      val rest = prefix % 8
      (0 until full).forall(i => addr(i) == network(i)) &&
      (rest == 0 || {
        val mask = (0xff << (8 - rest)) & 0xff
        (addr(full) & mask) == (network(full) & mask)
      })
    }
  override def toString: String = s"${InetAddress.getByAddress(network).getHostAddress}/$prefix"
}

object IpRules {

  /** 数値のアドレスだけを受け付ける（ホスト名を引かない）. */
  def parseAddress(
    s: String
  ): Option[Array[Byte]] = {
    val t = s.trim.stripPrefix("[").stripSuffix("]")
    val looksIp = t.nonEmpty && (t.contains(':') || t.forall(c => c.isDigit || c == '.'))
    if !looksIp then None
    else scala.util.Try(InetAddress.getByName(t).getAddress).toOption.map(normalize)
  }

  /** ポリシーの IP 制限（全体の allow・deny と、グループの上書きの allow のすべて）. */
  def allowedBy(
    ip: String,
    p: sruru.shared.IpPolicy
  ): Boolean = allowed(ip, p.allow, p.deny) && p.allowAlso.forall(matches(ip, _))

  /** 試行の回数を数える単位. IPv6 は /64 にまとめる（1つの /64 の中でアドレスを替えて制限を逃れられないように）. */
  def throttleKey(
    ip: String
  ): String =
    parseAddress(ip) match {
      case Some(a) if a.length == 16 => Cidr(a.take(8) ++ Array.fill[Byte](8)(0), 64).toString
      case Some(a) => java.net.InetAddress.getByAddress(a).getHostAddress
      case None => ip
    }

  /** ::ffff:1.2.3.4 → 1.2.3.4 */
  private def normalize(
    a: Array[Byte]
  ): Array[Byte] =
    if a.length == 16 && a.take(10).forall(_ == 0) && a(10) == -1 && a(11) == -1 then a.drop(12) else a

  def parseCidr(
    s: String
  ): Either[String, Cidr] =
    s.trim.split('/') match {
      case Array(a) => parseAddress(a).map(b => Cidr(b, b.length * 8)).toRight(s"IP アドレスではありません: $s")
      case Array(a, p) =>
        for {
          b <- parseAddress(a).toRight(s"IP アドレスではありません: $s")
          n <- p.toIntOption.filter(n => n >= 0 && n <= b.length * 8).toRight(s"プレフィックス長が不正です: $s")
        } yield Cidr(b, n)
      case _ => Left(s"CIDR ではありません: $s")
    }

  def parseAll(
    xs: List[String]
  ): Either[String, List[Cidr]] =
    xs.map(_.trim).filter(_.nonEmpty).foldRight[Either[String, List[Cidr]]](Right(Nil))(
      (
        s,
        acc
      ) => acc.flatMap(l => parseCidr(s).map(_ :: l))
    )

  /** 範囲のどれかに含まれるか（解釈できない範囲は無視する）. */
  def matches(
    ip: String,
    ranges: List[String]
  ): Boolean =
    parseAddress(ip).exists(a => ranges.flatMap(r => parseCidr(r).toOption).exists(_.contains(a)))

  /** allow が空ならどこからでも、deny に含まれれば拒否. */
  def allowed(
    ip: String,
    allow: List[String],
    deny: List[String]
  ): Boolean = {
    val allowOk = allow.forall(_.trim.isEmpty) || matches(ip, allow)
    allowOk && !matches(ip, deny)
  }

  /**
   * 利用者の IP アドレス. 接続元が信頼するプロキシのときだけ X-Forwarded-For を右からたどり、
   * 信頼するプロキシでない最初のアドレスを使う.
   */
  def clientIp(
    remote: String,
    forwardedFor: Option[String],
    trusted: List[String]
  ): String =
    if !matches(remote, trusted) then remote
    else {
      val chain = forwardedFor.toList.flatMap(_.split(',').map(_.trim).filter(_.nonEmpty))
      // すべて信頼するプロキシなら、いちばん左（利用者が書ける値）ではなく、もっとも近いプロキシのアドレスを使う
      chain.reverse.find(ip => !matches(ip, trusted)).orElse(chain.lastOption).getOrElse(remote)
    }
}
