package sruru.core

import cats.syntax.all.*
import sruru.shared.GroupPolicy

import java.util.UUID

/** グループのポリシーの上書きの確認（管理画面と、編集を任された人の画面で同じ確認をする）. 空なら None. */
object GroupPolicyCheck {
  def validate(
    p: GroupPolicy
  ): Either[String, Option[GroupPolicy]] =
    for {
      _ <- IpRules.parseAll(p.ip.allow ++ p.ip.deny)
      pol <- GroupPolicy.validate(p)
      _ <- pol.branding.logo.traverse_(l => scala.util.Try(UUID.fromString(l)).toEither.left.map(_ => "ロゴの指定が正しくありません"))
    } yield Option.when(!pol.isEmpty)(pol)
}
