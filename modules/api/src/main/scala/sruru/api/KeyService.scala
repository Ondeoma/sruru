package sruru.api

import cats.effect.*
import cats.syntax.all.*
import io.circe.Json
import io.circe.syntax.*
import sruru.db.*
import sruru.security.*

import java.time.Instant

/** 署名鍵（RS256・ES256）. DB に暗号化して保存し、各ノードは1分ごとに読み直す（鍵の入れ替えをほかのノードにも反映する）. */
final class KeyService(store: TokenStore,
                       box: SecretBox,
                       cache: Ref[IO, Option[(Long, List[(StoredKey, SigningKey)])]],
                       cn: String) {

  private def generate(alg: String): StoredKey = {
    val kp = Jose.generate(alg)
    val kid = Jose.newKid()
    val cert = Option.when(alg == "RS256")(Jose.selfSignedCert(kp, cn))
    StoredKey(
      kid,
      alg,
      box.encrypt(Jose.encodePrivate(kp.getPrivate)),
      Jose.publicJwk(kid, alg, kp.getPublic),
      cert.map(Jose.certPem),
      true,
      Instant.now(),
      None
    )
  }

  /** 使用中の鍵がなければ作る（複数ノードが同時に起動しても1つだけ）. */
  def ensure: IO[Unit] =
    store.withKeyLock(store.keysC.flatMap { ks =>
      List("RS256", "ES256").filterNot(a => ks.exists(k => k.alg == a && k.active && k.retiredAt.isEmpty))
        .traverse_(a => store.addKeyC(generate(a)))
    }) *> cache.set(None)

  private def decode(k: StoredKey): Option[SigningKey] =
    for {
      enc <- box.decrypt(k.privateEnc)
      priv <- scala.util.Try(Jose.decodePrivate(k.alg, enc)).toOption
      pub <- Jose.publicKey(k.publicJwk).toOption
    } yield SigningKey(
      k.kid,
      k.alg,
      priv,
      pub,
      k.certPem.flatMap(p => Jose.parseCerts(p).toOption.flatMap(_.headOption))
    )

  def all: IO[List[(StoredKey, SigningKey)]] =
    (cache.get, IO.monotonic).flatMapN {
      (c, now) =>
        c match {
          case Some((at, ks)) if now.toMillis - at < 60000 => IO.pure(ks)
          case _ =>
            store.keys.map(_.filter(_.retiredAt.isEmpty).flatMap(k => decode(k).map(k -> _))).flatTap { ks =>
              IO.whenA(ks.isEmpty)(
                sbirds.observe.Log.println("[sruru] WARNING: 署名鍵を復号できません（APP_SECRET が違う可能性があります）")
              ) *>
                cache.set(Some(now.toMillis -> ks))
            }
        }
    }

  def active(alg: String): IO[SigningKey] =
    all.flatMap { ks =>
      ks.find((s, _) => s.active && s.alg == alg).orElse(
        ks.find((s, _) => s.active && s.alg == "RS256")
      ).map(_._2) match {
        case Some(k) => IO.pure(k)
        case None => ensure *>
            all.flatMap(_.find(_._1.active).map(_._2).liftTo[IO](new IllegalStateException("署名鍵を用意できません")))
      }
    }

  /** SAML の署名に使う鍵（証明書つきの RS256）. */
  def saml: IO[SigningKey] = active("RS256")

  def jwks: IO[Json] = all.map(ks => Json.obj("keys" -> ks.map(_._1.publicJwk).asJson))

  def publicJwks: IO[List[Json]] = all.map(_.map(_._1.publicJwk))

  def rotate(alg: String): IO[StoredKey] = {
    val k = generate(alg)
    store.addKey(k) *> cache.set(None).as(k)
  }

  def retire(kid: String): IO[Boolean] = store.retireKey(kid).flatTap(_ => cache.set(None))
}

object KeyService {
  def create(store: TokenStore, box: SecretBox, cn: String): IO[KeyService] =
    Ref.of[IO, Option[(Long, List[(StoredKey, SigningKey)])]](None).map(new KeyService(store, box, _, cn))
}
