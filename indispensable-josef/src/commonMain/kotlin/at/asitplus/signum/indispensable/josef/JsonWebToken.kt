@file:UseSerializers(ByteArrayBase64Serializer::class)

package at.asitplus.signum.indispensable.josef

import at.asitplus.catching
import at.asitplus.signum.indispensable.io.ByteArrayBase64Serializer
import at.asitplus.signum.indispensable.josef.io.InstantLongSerializer
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.UseSerializers
import kotlinx.serialization.json.JsonObject
import kotlin.time.Instant

/**
 * Content of a JWT (JsonWebToken), with many optional keys,
 * since no claim is strongly required.
 *
 * See [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)
 */
@Serializable
data class JsonWebToken(

    /**
     * RFC 7519: The "iss" (issuer) claim identifies the principal that issued the
     * JWT.  The processing of this claim is generally application specific.
     * The "iss" value is a case-sensitive string containing a StringOrURI
     * value.  Use of this claim is OPTIONAL.
     */
    @SerialName("iss")
    val issuer: String? = null,

    /**
     * RFC 7519: The "sub" (subject) claim identifies the principal that is the
     * subject of the JWT.  The claims in a JWT are normally statements
     * about the subject.  The subject value MUST either be scoped to be
     * locally unique in the context of the issuer or be globally unique.
     * The processing of this claim is generally application specific.  The
     * "sub" value is a case-sensitive string containing a StringOrURI
     * value.  Use of this claim is OPTIONAL.
     */
    @SerialName("sub")
    val subject: String? = null,

    /**
     * RFC 7519: The "aud" (audience) claim identifies the recipients that the JWT is
     * intended for.  Each principal intended to process the JWT MUST
     * identify itself with a value in the audience claim.  If the principal
     * processing the claim does not identify itself with a value in the
     * "aud" claim when this claim is present, then the JWT MUST be
     * rejected.  In the general case, the "aud" value is an array of case-
     * sensitive strings, each containing a StringOrURI value.  In the
     * special case when the JWT has one audience, the "aud" value MAY be a
     * single case-sensitive string containing a StringOrURI value.  The
     * interpretation of audience values is generally application specific.
     * Use of this claim is OPTIONAL.
     */
    @SerialName("aud")
    val audience: String? = null,

    @SerialName("nonce")
    val nonce: String? = null,

    /**
     * RFC 7519: The "nbf" (not before) claim identifies the time before which the JWT
     * MUST NOT be accepted for processing.  The processing of the "nbf"
     * claim requires that the current date/time MUST be after or equal to
     * the not-before date/time listed in the "nbf" claim.  Implementers MAY
     * provide for some small leeway, usually no more than a few minutes, to
     * account for clock skew.  Its value MUST be a number containing a
     * NumericDate value.  Use of this claim is OPTIONAL.
     */
    @SerialName("nbf")
    @Serializable(with = InstantLongSerializer::class)
    val notBefore: Instant? = null,

    /**
     * RFC 7519: The "iat" (issued at) claim identifies the time at which the JWT was
     * issued.  This claim can be used to determine the age of the JWT.  Its
     * value MUST be a number containing a NumericDate value.  Use of this
     * claim is OPTIONAL.
     */
    @SerialName("iat")
    @Serializable(with = InstantLongSerializer::class)
    val issuedAt: Instant? = null,

    /**
     * RFC 7519: The "exp" (expiration time) claim identifies the expiration time on
     * or after which the JWT MUST NOT be accepted for processing.  The
     * processing of the "exp" claim requires that the current date/time
     * MUST be before the expiration date/time listed in the "exp" claim.
     * Implementers MAY provide for some small leeway, usually no more than
     * a few minutes, to account for clock skew.  Its value MUST be a number
     * containing a NumericDate value.  Use of this claim is OPTIONAL.
     */
    @SerialName("exp")
    @Serializable(with = InstantLongSerializer::class)
    val expiration: Instant? = null,

    /**
     * RFC 7519: The "jti" (JWT ID) claim provides a unique identifier for the JWT.
     * The identifier value MUST be assigned in a manner that ensures that
     * there is a negligible probability that the same value will be
     * accidentally assigned to a different data object; if the application
     * uses multiple issuers, collisions MUST be prevented among values
     * produced by different issuers as well.  The "jti" claim can be used
     * to prevent the JWT from being replayed.  The "jti" value is a case-
     * sensitive string.  Use of this claim is OPTIONAL.
     */
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


    @Deprecated("To be removed in next release")
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
        result = 31 * result + (walletName?.hashCode() ?: 0)
        result = 31 * result + (walletLink?.hashCode() ?: 0)
        result = 31 * result + (status?.hashCode() ?: 0)
        return result
    }

    companion object {

        @Deprecated("To be removed in next release")
        fun deserialize(it: String) = catching {
            joseCompliantSerializer.decodeFromString<JsonWebToken>(it)
        }
    }
}
