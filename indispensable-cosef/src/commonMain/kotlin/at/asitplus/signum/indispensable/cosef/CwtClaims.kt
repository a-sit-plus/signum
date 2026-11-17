package at.asitplus.signum.indispensable.cosef

import kotlin.time.Instant

/** Application-owned CWT claims, independent of the type of a COSE payload. Annotate concrete fields explicitly. */
interface CwtClaims {
    val issuer: String? get() = null
    val subject: String? get() = null
    val audience: String? get() = null
    val expiration: Instant? get() = null
    val notBefore: Instant? get() = null
    val issuedAt: Instant? get() = null
    val cwtId: ByteArray? get() = null
    val nonce: ByteArray? get() = null
}
