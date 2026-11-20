package sruru.core

import cats.syntax.all.*
import sruru.shared.DomainPolicy

import java.util.UUID

/** ドメインのポリシーの上書きの確認（値の範囲・IP の書き方・ロゴの指定）. */
object DomainPolicyCheck {
  def validate(p: DomainPolicy): Either[String, DomainPolicy] =
    for {
      _ <- p.ip.traverse_(x => IpRules.parseAll(x.allow ++ x.deny))
      pol <- DomainPolicy.validate(p)
      _ <- pol.branding.logo.traverse_(l => scala.util.Try(UUID.fromString(l)).toEither.left.map(_ => "ロゴの指定が正しくありません"))
    } yield pol
}
