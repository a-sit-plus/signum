@file:UseSerializers(ByteArrayBase64Serializer::class)

package at.asitplus.signum.indispensable.josef

import at.asitplus.catching
import at.asitplus.signum.indispensable.io.ByteArrayBase64Serializer
import at.asitplus.signum.indispensable.josef.io.InstantLongSerializer
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import kotlinx.datetime.Instant
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.UseSerializers
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.JsonObject

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
    val confirmationClaim: ConfirmationClaim? = null,

    /**
     * RFC 9449: The value of the HTTP method (Section 9.1 of [RFC9110](https://datatracker.ietf.org/doc/html/rfc9110))
     * of the request to which the JWT is attached.
     */
    @SerialName("htm")
    val httpMethod: String? = null,

    /**
     * RFC 9449: The HTTP target URI (Section 7.1 of [RFC9110](https://datatracker.ietf.org/doc/html/rfc9110)) of the
     * request to which the JWT is attached, without query and fragment parts.
     */
    @SerialName("htu")
    val httpTargetUrl: String? = null,

    /**
     * RFC 9449: Hash of the access token. The value MUST be the result of a base64url encoding (as defined in Section
     * 2 of [RFC7515](https://datatracker.ietf.org/doc/html/rfc7515) the SHA-256 hash of the ASCII encoding of the
     * associated access token's value.
     */
    @SerialName("ath")
    val accessTokenHash: String? = null,

    /**
     * OID4VC HAIP: String asserting the authentication level of the Wallet and the key as asserted in the `cnf` claim.
     */
    @SerialName("aal")
    @Deprecated("Removed in OID4VC HAIP")
    val authenticationLevel: String? = null,

    /**
     * OID4VCI: OPTIONAL. String containing a human-readable name of the Wallet.
     */
    @SerialName("wallet_name")
    val walletName: String? = null,

    /**
     * OID4VCI: OPTIONAL. String containing a URL to get further information about the Wallet and the Wallet Provider.
     */
    @SerialName("wallet_link")
    val walletLink: String? = null,

    /**
     * OID4VCI: OPTIONAL. Status mechanism for the Wallet Attestation as defined in ietf-oauth-status-list.
     */
    @SerialName("status")
    val status: JsonObject? = null,
) {

    fun serialize() = joseCompliantSerializer.encodeToString(this)

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
        if (confirmationClaim != other.confirmationClaim) return false
        if (httpMethod != other.httpMethod) return false
        if (httpTargetUrl != other.httpTargetUrl) return false
        if (accessTokenHash != other.accessTokenHash) return false
        @Suppress("DEPRECATION")
        if (authenticationLevel != other.authenticationLevel) return false
        if (walletName != other.walletName) return false
        if (walletLink != other.walletLink) return false
        if (status != other.status) return false

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
        result = 31 * result + (confirmationClaim?.hashCode() ?: 0)
        result = 31 * result + (httpMethod?.hashCode() ?: 0)
        result = 31 * result + (httpTargetUrl?.hashCode() ?: 0)
        result = 31 * result + (accessTokenHash?.hashCode() ?: 0)
        @Suppress("DEPRECATION")
        result = 31 * result + (authenticationLevel?.hashCode() ?: 0)
        result = 31 * result + (walletName?.hashCode() ?: 0)
        result = 31 * result + (walletLink?.hashCode() ?: 0)
        result = 31 * result + (status?.hashCode() ?: 0)
        return result
    }

    companion object {
        fun deserialize(it: String) = catching {
            joseCompliantSerializer.decodeFromString<JsonWebToken>(it)
        }
    }
}