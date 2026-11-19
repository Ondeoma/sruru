package sruru.federation

import cats.syntax.all.*
import io.circe.{HCursor, Json}
import io.circe.syntax.*

/** Google の利用者の JSON を DirUser にする. */
private[federation] object GoogleUsers {
  private def pick(
    arr: List[Json],
    pred: HCursor => Boolean = _ => true
  ): Option[HCursor] = {
    val cs = arr.map(_.hcursor).filter(pred)
    cs.find(_.get[Boolean]("primary").toOption.contains(true)).orElse(cs.headOption)
  }

  def toUser(
    j: Json
  ): Option[DirUser] = {
    val c = j.hcursor
    for {
      id <- Dir.str(c, "id")
      email <- Dir.str(c, "primaryEmail")
    } yield {
      val n = c.downField("name")
      def ns(
        k: String
      ) = n.get[String](k).toOption.filter(_.nonEmpty)
      val org = pick(Dir.list(j, "organizations"))
      def os(
        k: String
      ) = org.flatMap(Dir.str(_, k)).map(_.asJson)
      val empId =
        pick(Dir.list(j, "externalIds"), x => Dir.str(x, "type").contains("organization")).flatMap(Dir.str(_, "value"))
      val phone = pick(Dir.list(j, "phones"), x => Dir.str(x, "type").exists(t => t == "work" || t == "mobile"))
        .orElse(pick(Dir.list(j, "phones"))).flatMap(Dir.str(_, "value"))
      val manager =
        pick(Dir.list(j, "relations"), x => Dir.str(x, "type").contains("manager")).flatMap(Dir.str(_, "value"))
      val gn = ns("givenName")
      val family = ns("familyName")
      DirUser(
        externalId = id,
        username = email,
        email = Some(email),
        name =
          ns("fullName").orElse((gn.toList ++ family.toList).mkString(" ").some.filter(_.nonEmpty)).getOrElse(email),
        givenName = gn,
        familyName = family,
        active = !c.get[Boolean]("suspended").getOrElse(false) && !c.get[Boolean]("archived").getOrElse(false),
        attributes = Dir.attrs(
          "department" -> os("department"),
          "jobTitle" -> os("title"),
          "costCenter" -> os("costCenter"),
          "employeeId" -> empId.map(_.asJson),
          "phone" -> phone.map(_.asJson),
          "manager" -> manager.map(_.asJson),
          "orgUnitPath" -> Dir.str(c, "orgUnitPath").map(_.asJson)
        ),
        photoUrl = Dir.str(c, "thumbnailPhotoUrl")
      )
    }
  }
}
