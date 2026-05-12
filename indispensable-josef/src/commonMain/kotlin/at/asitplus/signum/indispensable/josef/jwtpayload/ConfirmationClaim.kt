package at.asitplus.signum.indispensable.josef.jwtpayload

import at.asitplus.signum.indispensable.josef.JwtClaims
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Structure to declare posession of a particular proof-of-possesion key,
 * to be included in [at.asitplus.signum.indispensable.josef.JwtClaims.confirmationClaim]
 *
 * See [RFC 7800](https://datatracker.ietf.org/doc/html/rfc7800)
 */
@Serializable
data class ConfirmationClaim(
    /**
     * RFC 7800: When the key held by the presenter is an asymmetric private key, the
     * [jsonWebKey] member is a [at.asitplus.signum.indispensable.josef.JsonWebKey] representing the corresponding
     * asymmetric public key.
     */
    @SerialName(JwtClaims.IanaRegistered.ConfirmationMethods.RFC7800.JWK)
    val jsonWebKey: at.asitplus.signum.indispensable.josef.JsonWebKey? = null,

    /**
     * RFC 7800: When the key held by the presenter is a symmetric key, the [encryptedSymmetricKey]
     * member is an encrypted [at.asitplus.signum.indispensable.josef.JsonWebKey] encrypted to a key known to
     * the recipient using the JWE Compact Serialization containing the
     * symmetric key.
     */
    @SerialName(JwtClaims.IanaRegistered.ConfirmationMethods.RFC7800.JWE)
    @Serializable(at.asitplus.signum.indispensable.josef.JweEncryptedSerializer::class)
    val encryptedSymmetricKey: at.asitplus.signum.indispensable.josef.JweEncrypted? = null,

    /**
     * RFC 7800:  The proof-of-possession key can also be identified by the use of a
     * Key ID instead of communicating the actual key, provided the
     * recipient is able to obtain the identified key using the Key ID.
     */
    @SerialName(JwtClaims.IanaRegistered.ConfirmationMethods.RFC7800.KID)
    val keyId: String? = null,

    /**
     * RFC 7800: The proof-of-possession key can be passed by reference instead of
     * being passed by value.  This is done using the "jku" member.  Its
     * value is a URI (`RFC3986`) that refers to a resource for a set of JSON-
     * encoded public keys represented as a [at.asitplus.signum.indispensable.josef.JsonWebKeySet], one of which is
     * the proof-of-possession key.  If there are multiple keys in the
     * referenced JWK Set document, a [keyId] member MUST also be included
     * with the referenced key's JWK also containing the same [keyId] value.
     */
    @SerialName(JwtClaims.IanaRegistered.ConfirmationMethods.RFC7800.JKU)
    val jsonWebKeySetUrl: String? = null,

    /**
     * RFC 9449: JWK SHA-256 Thumbprint confirmation method. The value of the [jsonWebKeyThumbprint] member MUST be the
     * base64url encoding (as defined in `RFC7515`) of the JWK SHA-256 Thumbprint (according to `RFC7638`) of the DPoP
     * public key (in JWK format) to which the access token is bound.
     *
     * See also [at.asitplus.signum.indispensable.josef.JsonWebKey.jwkThumbprint]
     */
    @SerialName(JwtClaims.IanaRegistered.ConfirmationMethods.RFC9449.JKT)
    val jsonWebKeyThumbprint: String? = null,
)
