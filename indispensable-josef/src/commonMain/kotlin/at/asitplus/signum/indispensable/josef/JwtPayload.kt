package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.io.InstantLongSerializer
import at.asitplus.signum.indispensable.josef.JwtClaimNames.IanaRegistered
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.time.Instant

/**
 * Base-Claims defined in RFC7519 which build the basis for
 * JWT Payloads none of which are required.
 *
 * `@SerialName` annotations are just for convenience and
 * ARE NOT BEING INHERITED to the implementing class!
 *
 * See [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)
 */
interface JwtPayload {
    /**
     * RFC 7519: The "iss" (issuer) claim identifies the principal that issued the
     * JWT.  The processing of this claim is generally application specific.
     * The "iss" value is a case-sensitive string containing a StringOrURI
     * value.  Use of this claim is OPTIONAL.
     */
    @SerialName(IanaRegistered.ClaimNames.RFC7519.ISS)
    val issuer: String?

    /**
     * RFC 7519: The "sub" (subject) claim identifies the principal that is the
     * subject of the JWT.  The claims in a JWT are normally statements
     * about the subject.  The subject value MUST either be scoped to be
     * locally unique in the context of the issuer or be globally unique.
     * The processing of this claim is generally application specific.  The
     * "sub" value is a case-sensitive string containing a StringOrURI
     * value.  Use of this claim is OPTIONAL.
     */
    @SerialName(IanaRegistered.ClaimNames.RFC7519.SUB)
    val subject: String?

    /**
     * RFC 7519: The "aud" (audience) claim identifies the recipients that the JWT is
     * intended for.  Each principal intended to process the JWT MUST
     * identify itself with a value in the audience claim.  If the principal
     * processing the claim does not identify itself with a value in the
     * "aud" claim when this claim is present, then the JWT MUST be
     * rejected.  In the general case, the "aud" value is an array of case-sensitive strings,
     * each containing a StringOrURI value.  In the
     * special case when the JWT has one audience, the "aud" value MAY be a
     * single case-sensitive string containing a StringOrURI value.  The
     * interpretation of audience values is generally application specific.
     * Use of this claim is OPTIONAL.
     */
    @SerialName(IanaRegistered.ClaimNames.RFC7519.AUD)
    val audience: String?

    /**
     * RFC 7519: The "nbf" (not before) claim identifies the time before which the JWT
     * MUST NOT be accepted for processing.  The processing of the "nbf"
     * claim requires that the current date/time MUST be after or equal to
     * the not-before date/time listed in the "nbf" claim.  Implementers MAY
     * provide for some small leeway, usually no more than a few minutes, to
     * account for clock skew.  Its value MUST be a number containing a
     * NumericDate value.  Use of this claim is OPTIONAL.
     */
    @SerialName(IanaRegistered.ClaimNames.RFC7519.NBF)
    @Serializable(with = InstantLongSerializer::class)
    val notBefore: Instant?

    /**
     * RFC 7519: The "iat" (issued at) claim identifies the time at which the JWT was
     * issued.  This claim can be used to determine the age of the JWT.  Its
     * value MUST be a number containing a NumericDate value.  Use of this
     * claim is OPTIONAL.
     */
    @SerialName(IanaRegistered.ClaimNames.RFC7519.IAT)
    @Serializable(with = InstantLongSerializer::class)
    val issuedAt: Instant?

    /**
     * RFC 7519: The "exp" (expiration time) claim identifies the expiration time on
     * or after which the JWT MUST NOT be accepted for processing.  The
     * processing of the "exp" claim requires that the current date/time
     * MUST be before the expiration date/time listed in the "exp" claim.
     * Implementers MAY provide for some small leeway, usually no more than
     * a few minutes, to account for clock skew.  Its value MUST be a number
     * containing a NumericDate value.  Use of this claim is OPTIONAL.
     */
    @SerialName(IanaRegistered.ClaimNames.RFC7519.EXP)
    @Serializable(with = InstantLongSerializer::class)
    val expiration: Instant?

    /**
     * RFC 7519: The "jti" (JWT ID) claim provides a unique identifier for the JWT.
     * The identifier value MUST be assigned in a manner that ensures that
     * there is a negligible probability that the same value will be
     * accidentally assigned to a different data object; if the application
     * uses multiple issuers, collisions MUST be prevented among values
     * produced by different issuers as well.  The "jti" claim can be used
     * to prevent the JWT from being replayed.  The "jti" value is a case-sensitive string.  Use of this claim is OPTIONAL.
     */
    @SerialName(IanaRegistered.ClaimNames.RFC7519.JTI)
    val jwtId: String?
}
