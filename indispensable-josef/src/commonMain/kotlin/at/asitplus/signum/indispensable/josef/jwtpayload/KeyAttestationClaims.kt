package at.asitplus.signum.indispensable.josef.jwtpayload

import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.JwtClaims
import at.asitplus.signum.indispensable.josef.KeyStorageStatus
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable


@Serializable
data class KeyAttestationClaims(
    /**
     * Array of attested keys from the same key storage component using the syntax of JWK as defined in RFC7517.
     */
    @SerialName(JwtClaims.UnregisteredClaims.OID4VCI.ATTESTED_KEYS)
    val attestedKeys: Collection<JsonWebKey>,

    /**
     * Optional. Array of case-sensitive strings that assert the attack potential resistance of the key storage
     * component and its keys attested in the attested_keys parameter. This specification defines initial values in
     * Appendix D.2.
     */
    @SerialName(JwtClaims.UnregisteredClaims.OID4VCI.KEY_STORAGE)
    val keyStorage: Collection<String>? = null,

    /**
     * Optional. Array of case-sensitive strings that assert the attack potential resistance of the user authentication
     * methods allowed to access the private keys from the [attestedKeys] parameter.
     * This specification defines initial values in Appendix D.2.
     */
    @SerialName(JwtClaims.UnregisteredClaims.OID4VCI.USER_AUTHENTICATION)
    val userAuthentication: Collection<String>? = null,

    /**
     * Optional. A String that contains a URL that links to the certification of the key storage component.
     */
    @SerialName(JwtClaims.UnregisteredClaims.OID4VCI.CERTIFICATION)
    val certification: String? = null,

    /**
     * EUDI TS3 WUA 1.5: status list reference for the attested key storage and the time until which the Wallet
     * Provider commits to maintaining the referenced status.
     */
    @SerialName("key_storage_status")
    val keyStorageStatus: KeyStorageStatus? = null,
)