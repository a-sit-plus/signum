package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import at.asitplus.signum.indispensable.io.CertificateChainBase64Serializer
import at.asitplus.signum.indispensable.josef.JwsHeaderMonolith.SerialNames
import at.asitplus.signum.indispensable.pki.CertificateChain
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Standard header parameters defined in RFC 7515 for application-defined JWS header models.
 * [algorithm] is required; the other standard parameters are optional.
 *
 * Serialization annotations are documentation only and are not inherited. Implementations must declare
 * their own wire names and serializers, or mark unmodeled properties as transient.
 *
 * See [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515)
 */
interface JwsHeader {
    /** "kid": Case-sensitive key identifier; matches the JWK key ID when used with a JWK. */
    @SerialName(SerialNames.KEY_ID)
    val keyId: String?

    /** "typ": Media type of the complete JWS, interpreted by the application. */
    @SerialName(SerialNames.TYPE)
    val type: String?

    /** "alg": Required signing or MAC algorithm identifier; recipients must support it and have a suitable key. */
    @SerialName(SerialNames.ALGORITHM)
    val algorithm: JwsAlgorithm

    /** "cty": Media type of the payload, interpreted by the application. */
    @SerialName(SerialNames.CONTENT_TYPE)
    val contentType: String?

    /** "x5c": Base64-encoded DER certificate chain, signing certificate first; recipients must validate the chain. */
    @SerialName(SerialNames.CERTIFICATE_CHAIN)
    @Serializable(with = CertificateChainBase64Serializer::class)
    val certificateChain: CertificateChain?

    /** "jwk": Public key corresponding to the signing key, encoded as a JWK. */
    @SerialName(SerialNames.JSON_WEB_KEY)
    val jsonWebKey: JsonWebKey?

    /** "jku": JWK Set URL; retrieval requires TLS and server identity validation. */
    @SerialName(SerialNames.JSON_WEB_KEY_SET_URL)
    val jsonWebKeySetUrl: String?

    /** "x5u": URL of a PEM certificate chain, signing certificate first; retrieval requires TLS and server identity validation. */
    @SerialName(SerialNames.CERTIFICATE_URL)
    val certificateUrl: String?

    /** "x5t": Base64url-encoded SHA-1 thumbprint of the DER signing certificate. */
    @SerialName(SerialNames.CERTIFICATE_SHA1_THUMBPRINT)
    @Serializable(with = ByteArrayBase64UrlSerializer::class)
    val certificateSha1Thumbprint: ByteArray?

    /** "x5t#S256": Base64url-encoded SHA-256 thumbprint of the DER signing certificate. */
    @SerialName(SerialNames.CERTIFICATE_SHA256_THUMBPRINT)
    @Serializable(with = ByteArrayBase64UrlSerializer::class)
    val certificateSha256Thumbprint: ByteArray?

    /** "crit": Extension parameter names that recipients must understand and process; otherwise the JWS is invalid. */
    val crit: List<String>?
}
