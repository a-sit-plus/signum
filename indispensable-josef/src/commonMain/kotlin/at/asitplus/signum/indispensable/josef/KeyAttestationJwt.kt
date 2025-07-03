package at.asitplus.signum.indispensable.josef

import at.asitplus.catching
import at.asitplus.signum.indispensable.josef.io.InstantLongSerializer
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import kotlinx.datetime.Instant
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.JsonObject

/**
 * Content of a Key Attestation in JWT format, according to
 * [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#keyattestation-jwt)
 */
@Serializable
data class KeyAttestationJwt(
    @SerialName("iss")
    val issuer: String? = null,

    @SerialName("sub")
    val subject: String? = null,

    @SerialName("aud")
    val audience: String? = null,

    /**
     * Optional. String that represents a nonce provided by the Issuer to prove that a key attestation was freshly
     * generated.
     */
    @SerialName("nonce")
    val nonce: String? = null,

    @SerialName("nbf")
    @Serializable(with = InstantLongSerializer::class)
    val notBefore: Instant? = null,

    /**
     * Integer for the time at which the key attestation was issued using the syntax defined in RFC7519.
     */
    @SerialName("iat")
    @Serializable(with = InstantLongSerializer::class)
    val issuedAt: Instant,

    /**
     * Integer for the time at which the key attestation and the key(s) it is attesting expire, using the syntax
     * defined in RFC7519. MUST be present if the attestation is used with the JWT proof type.
     */
    @SerialName("exp")
    @Serializable(with = InstantLongSerializer::class)
    val expiration: Instant? = null,

    /**
     * Array of attested keys from the same key storage component using the syntax of JWK as defined in RFC7517.
     */
    @SerialName("attested_keys")
    val attestedKeys: Collection<JsonWebKey>,

    /**
     * Optional. Array of case sensitive strings that assert the attack potential resistance of the key storage
     * component and its keys attested in the attested_keys parameter. This specification defines initial values in
     * Appendix D.2.
     */
    @SerialName("key_storage")
    val keyStorage: Collection<String>? = null,

    /**
     * Optional. Array of case sensitive strings that assert the attack potential resistance of the user authentication
     * methods allowed to access the private keys from the [attestedKeys] parameter.
     * This specification defines initial values in Appendix D.2.
     */
    @SerialName("user_authentication")
    val userAuthentication: Collection<String>? = null,

    /**
     * Optional. A String that contains a URL that links to the certification of the key storage component.
     */
    @SerialName("certification")
    val certification: String? = null,

    /**
     * Optional. JSON Object representing the supported revocation check mechanisms, such as the one defined in
     * ietf-oauth-status-list.
     */
    @SerialName("status")
    val status: JsonObject? = null,
) {

    @Deprecated("To be removed in next release")
    fun serialize() = joseCompliantSerializer.encodeToString(this)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as KeyAttestationJwt

        if (issuer != other.issuer) return false
        if (subject != other.subject) return false
        if (audience != other.audience) return false
        if (nonce != other.nonce) return false
        if (notBefore != other.notBefore) return false
        if (issuedAt != other.issuedAt) return false
        if (expiration != other.expiration) return false
        if (attestedKeys != other.attestedKeys) return false
        if (keyStorage != other.keyStorage) return false
        if (userAuthentication != other.userAuthentication) return false
        if (certification != other.certification) return false
        if (status != other.status) return false

        return true
    }

    override fun hashCode(): Int {
        var result = issuer?.hashCode() ?: 0
        result = 31 * result + (subject?.hashCode() ?: 0)
        result = 31 * result + (audience?.hashCode() ?: 0)
        result = 31 * result + (nonce?.hashCode() ?: 0)
        result = 31 * result + (notBefore?.hashCode() ?: 0)
        result = 31 * result + issuedAt.hashCode()
        result = 31 * result + (expiration?.hashCode() ?: 0)
        result = 31 * result + attestedKeys.hashCode()
        result = 31 * result + (keyStorage?.hashCode() ?: 0)
        result = 31 * result + (userAuthentication?.hashCode() ?: 0)
        result = 31 * result + (certification?.hashCode() ?: 0)
        result = 31 * result + (status?.hashCode() ?: 0)
        return result
    }

    companion object {
        @Deprecated("To be removed in next release")
        fun deserialize(it: String) = catching {
            joseCompliantSerializer.decodeFromString<KeyAttestationJwt>(it)
        }
    }
}
