package sruru.api

import io.circe.Json
import sruru.core.*
import sruru.saml.*

/** SAML の属性（対応の式から作る. 対応がなければ既定の属性）. */
object SamlMapping {
  val defaults: List[AttrMapping] = List(
    ("email", "{{user.email}}", false),
    ("name", "{{user.name}}", false),
    ("username", "{{user.username}}", false),
    ("givenName", "{{user.given_name}}", false),
    ("surname", "{{user.family_name}}", false),
    ("groups", "{{user.groups}}", true)
  ).map(
    (
      n,
      e,
      m
    ) => AttrMapping(java.util.UUID(0, 0), java.util.UUID(0, 0), n, e, None, None, m, 0)
  )

  def attributes(
    ms: List[AttrMapping],
    ctx: Json
  ): List[SamlAttribute] =
    (if ms.isEmpty then defaults else ms).flatMap { m =>
      val v = Expr.eval(m.expression, ctx)
      val values = v.asArray.map(_.toList.map(Expr.render)).getOrElse(if v.isNull then Nil
      else List(Expr.render(v))).filter(_.nonEmpty)
      Option.when(values.nonEmpty)(SamlAttribute(m.name, m.friendlyName, if m.multi then values else values.take(1)))
    }
}
