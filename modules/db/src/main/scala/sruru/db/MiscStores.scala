package sruru.db

import java.time.Instant
import java.util.UUID

final case class FederationProvider(id: UUID,
                                    slug: String,
                                    kind: String,
                                    name: String,
                                    enabled: Boolean,
                                    issuer: String,
                                    clientId: String,
                                    clientSecretEnc: String,
                                    scopes: String,
                                    subjectClaim: String,
                                    jit: Boolean,
                                    linkByEmail: Boolean,
                                    allowedDomains: List[String],
                                    defaultGroups: List[UUID],
                                    trustMfa: Boolean,
                                    syncEnabled: Boolean,
                                    syncConfigEnc: Option[String],
                                    syncIntervalMin: Int,
                                    lastSyncAt: Option[Instant],
                                    lastSyncResult: Option[String],
                                    createdAt: Instant)

final case class FederatedIdentity(providerId: UUID,
                                   subject: String,
                                   userId: UUID,
                                   email: Option[String],
                                   createdAt: Instant,
                                   lastLoginAt: Option[Instant])

/** 送信待ちのメール. */
final case class OutMail(id: Long, to: String, subject: String, body: String, attempts: Int)
