@file:UseSerializers(ByteArrayBase64Serializer::class)

package at.asitplus.crypto.datatypes.jws

import at.asitplus.catching
import at.asitplus.crypto.datatypes.io.ByteArrayBase64Serializer
import at.asitplus.crypto.datatypes.jws.io.InstantLongSerializer
import at.asitplus.crypto.datatypes.jws.io.jsonSerializer
import kotlinx.datetime.Instant
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.UseSerializers
import kotlinx.serialization.encodeToString

/**
 * Content of a JWT (JsonWebToken), with many optional keys,
 * since no claim is strongly required.
 *
 * See [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)
 */
@Serializable
data class JsonWebToken(
    @SerialName("iss")
    val issuer: String? = null,
    @SerialName("sub")
    val subject: String? = null,
    @SerialName("aud")
    val audience: String? = null,
    @SerialName("nonce")
    val nonce: String? = null,
    @SerialName("nbf")
    @Serializable(with = InstantLongSerializer::class)
    val notBefore: Instant? = null,
    @SerialName("iat")
    @Serializable(with = InstantLongSerializer::class)
    val issuedAt: Instant? = null,
    @SerialName("exp")
    @Serializable(with = InstantLongSerializer::class)
    val expiration: Instant? = null,
    @SerialName("jti")
    val jwtId: String? = null,
    /**
     * OID4VP: This claim contains the confirmation method as defined in RFC7800. It MUST contain a JWK as defined in
     * Section 3.2 of RFC7800. This claim determines the public key for which the corresponding private key the
     * Verifier MUST proof possession of when presenting the Verifier Attestation JWT. This additional security measure
     * allows the Verifier to obtain a Verifier Attestation JWT from a trusted issuer and use it for a long time
     * independent of that issuer without the risk of an adversary impersonating the Verifier by replaying a captured
     * attestation.
     */
    @SerialName("cnf")
    val confirmationKey: JsonWebKey? = null,
) {

    fun serialize() = jsonSerializer.encodeToString(this)
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as JsonWebToken

        if (issuer != other.issuer) return false
        if (subject != other.subject) return false
        if (audience != other.audience) return false
        if (nonce != other.nonce) return false
        if (notBefore != other.notBefore) return false
        if (issuedAt != other.issuedAt) return false
        if (expiration != other.expiration) return false
        if (jwtId != other.jwtId) return false
        if (confirmationKey != other.confirmationKey) return false

        return true
    }

    override fun hashCode(): Int {
        var result = issuer?.hashCode() ?: 0
        result = 31 * result + (subject?.hashCode() ?: 0)
        result = 31 * result + (audience?.hashCode() ?: 0)
        result = 31 * result + (nonce?.hashCode() ?: 0)
        result = 31 * result + (notBefore?.hashCode() ?: 0)
        result = 31 * result + (issuedAt?.hashCode() ?: 0)
        result = 31 * result + (expiration?.hashCode() ?: 0)
        result = 31 * result + (jwtId?.hashCode() ?: 0)
        result = 31 * result + (confirmationKey?.hashCode() ?: 0)
        return result
    }

    companion object {
        fun deserialize(it: String) = catching {
            jsonSerializer.decodeFromString<JsonWebToken>(it)
        }
    }
}