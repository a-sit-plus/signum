package at.asitplus.signum.indispensable.josef.jwtpayload

import at.asitplus.signum.indispensable.io.InstantLongSerializer
import at.asitplus.signum.indispensable.josef.JwtClaimNames.IanaRegistered
import at.asitplus.signum.indispensable.josef.JwtClaimNames.UnregisteredClaims
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject
import kotlin.time.Instant


@Deprecated("Will move into VCK next release")
@Serializable
data class ClientStatus(
    /**
     * Status list reference as specified by OID4VCI Appendix E. The value represents the revocation state of the
     * Wallet Instance.
     */
    @SerialName(UnregisteredClaims.DraftIetfOauthStatusList.STATUS)
    val status: JsonObject,

    /**
     * NumericDate specifying how long the Wallet Provider maintains revocation status at the referenced index.
     */
    @SerialName(IanaRegistered.ClaimNames.RFC7519.EXP)
    @Serializable(with = InstantLongSerializer::class)
    val expiration: Instant,
)
