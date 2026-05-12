package at.asitplus.signum.indispensable.josef.jwtpayload

import at.asitplus.signum.indispensable.io.InstantLongSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject
import kotlin.time.Instant

@Serializable
data class KeyStorageStatus(
    /**
     * Status list reference as specified by OID4VCI Appendix D.1. The value represents either the revocation state
     * of the WSCD/keystore type or, for per-KA indexing, the individual Wallet Unit's WSCD/keystore instance.
     */
    @SerialName("status")
    val status: JsonObject,

    /**
     * NumericDate specifying how long the Wallet Provider maintains revocation status at the referenced index.
     */
    @SerialName("exp")
    @Serializable(with = InstantLongSerializer::class)
    val expiration: Instant,
)