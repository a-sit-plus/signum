@file:UseSerializers(ByteArrayBase64Serializer::class, JwsCertificateSerializer::class)

package at.asitplus.crypto.datatypes.jws

import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.io.ByteArrayBase64Serializer
import at.asitplus.crypto.datatypes.io.ByteArrayBase64UrlSerializer
import at.asitplus.crypto.datatypes.jws.io.InstantLongSerializer
import at.asitplus.crypto.datatypes.jws.io.JwsCertificateSerializer
import at.asitplus.crypto.datatypes.jws.io.jsonSerializer
import at.asitplus.crypto.datatypes.pki.CertificateChain
import at.asitplus.crypto.datatypes.pki.leaf
import kotlinx.datetime.Instant
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.UseSerializers
import kotlinx.serialization.encodeToString

/**
 * Header of a [JwsSigned].
 *
 * See [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515)
 */
@Serializable
data class JwsHeader(
    /**
     * The "kid" (key ID) Header Parameter is a hint indicating which key
     * was used to secure the JWS.  This parameter allows originators to
     * explicitly signal a change of key to recipients.  The structure of
     * the "kid" value is unspecified.  Its value MUST be a case-sensitive
     * string.  Use of this Header Parameter is OPTIONAL.
     *
     * When used with a JWK, the "kid" value is used to match a JWK "kid"
     * parameter value.
     */
    @SerialName("kid")
    val keyId: String? = null,

    /**
     * The "typ" (type) Header Parameter is used by JWS applications to
     * declare the media type (IANA.MediaTypes) of this complete JWS.  This
     * is intended for use by the application when more than one kind of
     * object could be present in an application data structure that can
     * contain a JWS; the application can use this value to disambiguate
     * among the different kinds of objects that might be present.  It will
     * typically not be used by applications when the kind of object is
     * already known.  This parameter is ignored by JWS implementations; any
     * processing of this parameter is performed by the JWS application.
     * Use of this Header Parameter is OPTIONAL.
     */
    @SerialName("typ")
    val type: String? = null,

    /**
     * The "alg" (algorithm) Header Parameter identifies the cryptographic
     * algorithm used to secure the JWS.  The JWS Signature value is not
     * valid if the "alg" value does not represent a supported algorithm or
     * if there is not a key for use with that algorithm associated with the
     * party that digitally signed or MACed the content.  "alg" values
     * should either be registered in the IANA "JSON Web Signature and
     * Encryption Algorithms" registry established by (JWA) or be a value
     * that contains a Collision-Resistant Name.  The "alg" value is a case-
     * sensitive ASCII string containing a StringOrURI value.  This Header
     * Parameter MUST be present and MUST be understood and processed by
     * implementations.
     */
    @SerialName("alg")
    val algorithm: JwsAlgorithm,

    /**
     * The "cty" (content type) Header Parameter is used by JWS applications
     * to declare the media type (IANA.MediaTypes) of the secured content
     * (the payload).  This is intended for use by the application when more
     * than one kind of object could be present in the JWS Payload; the
     * application can use this value to disambiguate among the different
     * kinds of objects that might be present.  It will typically not be
     * used by applications when the kind of object is already known.  This
     * parameter is ignored by JWS implementations; any processing of this
     * parameter is performed by the JWS application.  Use of this Header
     * Parameter is OPTIONAL.
     */
    @SerialName("cty")
    val contentType: String? = null,

    /**
     * The "x5c" (X.509 certificate chain) Header Parameter contains the
     * X.509 public key certificate or certificate chain (RFC5280)
     * corresponding to the key used to digitally sign the JWS.  The
     * certificate or certificate chain is represented as a JSON array of
     * certificate value strings.  Each string in the array is a
     * base64-encoded (Section 4 of (RFC4648) -- not base64url-encoded) DER
     * (ITU.X690.2008) PKIX certificate value.  The certificate containing
     * the public key corresponding to the key used to digitally sign the
     * JWS MUST be the first certificate.  This MAY be followed by
     * additional certificates, with each subsequent certificate being the
     * one used to certify the previous one.  The recipient MUST validate
     * the certificate chain according to RFC 5280 (RFC5280) and consider
     * the certificate or certificate chain to be invalid if any validation
     * failure occurs.  Use of this Header Parameter is OPTIONAL.
     */
    @SerialName("x5c")
    val certificateChain: CertificateChain? = null,

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
     * The "jwk" (JSON Web Key) Header Parameter is the public key that
     * corresponds to the key used to digitally sign the JWS.  This key is
     * represented as a JSON Web Key (JWK).  Use of this Header Parameter is
     * OPTIONAL.
     */
    @SerialName("jwk")
    val jsonWebKey: JsonWebKey? = null,

    /**
     * The "jku" (JWK Set URL) Header Parameter is a URI (RFC3986) that
     * refers to a resource for a set of JSON-encoded public keys, one of
     * which corresponds to the key used to digitally sign the JWS.  The
     * keys MUST be encoded as a JWK Set (JWK).  The protocol used to
     * acquire the resource MUST provide integrity protection; an HTTP GET
     * request to retrieve the JWK Set MUST use Transport Layer Security
     * (TLS) (RFC2818) (RFC5246); and the identity of the server MUST be
     * validated, as per Section 6 of RFC 6125 (RFC6125).  Also, see
     * Section 8 on TLS requirements.  Use of this Header Parameter is
     * OPTIONAL.
     */
    @SerialName("jku")
    val jsonWebKeySetUrl: String? = null,

    /**
     * The "x5u" (X.509 URL) Header Parameter is a URI (RFC3986) that refers
     * to a resource for the X.509 public key certificate or certificate
     * chain (RFC5280) corresponding to the key used to digitally sign the
     * JWS.  The identified resource MUST provide a representation of the
     * certificate or certificate chain that conforms to RFC 5280 (RFC5280)
     * in PEM-encoded form, with each certificate delimited as specified in
     * Section 6.1 of RFC 4945 (RFC4945).  The certificate containing the
     * public key corresponding to the key used to digitally sign the JWS
     * MUST be the first certificate.  This MAY be followed by additional
     * certificates, with each subsequent certificate being the one used to
     * certify the previous one.  The protocol used to acquire the resource
     * MUST provide integrity protection; an HTTP GET request to retrieve
     * the certificate MUST use TLS (RFC2818] [RFC5246); and the identity of
     * the server MUST be validated, as per Section 6 of RFC 6125 (RFC6125).
     * Also, see Section 8 on TLS requirements.  Use of this Header
     * Parameter is OPTIONAL.
     */
    @SerialName("x5u")
    val certificateUrl: String? = null,

    /**
     * The "x5t" (X.509 certificate SHA-1 thumbprint) Header Parameter is a
     * base64url-encoded SHA-1 thumbprint (a.k.a. digest) of the DER
     * encoding of the X.509 certificate (RFC5280) corresponding to the key
     * used to digitally sign the JWS.  Note that certificate thumbprints
     * are also sometimes known as certificate fingerprints.  Use of this
     * Header Parameter is OPTIONAL.
     */
    @SerialName("x5t")
    @Serializable(with = ByteArrayBase64UrlSerializer::class)
    val certificateSha1Thumbprint: ByteArray? = null,

    /**
     * The "x5t#S256" (X.509 certificate SHA-256 thumbprint) Header
     * Parameter is a base64url-encoded SHA-256 thumbprint (a.k.a. digest)
     * of the DER encoding of the X.509 certificate (RFC5280) corresponding
     * to the key used to digitally sign the JWS.  Note that certificate
     * thumbprints are also sometimes known as certificate fingerprints.
     * Use of this Header Parameter is OPTIONAL.
     */
    @SerialName("x5t#S256")
    @Serializable(with = ByteArrayBase64UrlSerializer::class)
    val certificateSha256Thumbprint: ByteArray? = null,

    /**
     * OID4VP: Verifier Attestation JWT, used to authenticate a Verifier, by providing a JWT signed by a trusted
     * third party. May be parsed as a [JwsSigned], with [JsonWebToken] as the payload.
     */
    @SerialName("jwt")
    val attestationJwt: String? = null,
) {

    fun serialize() = jsonSerializer.encodeToString(this)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as JwsHeader

        if (keyId != other.keyId) return false
        if (type != other.type) return false
        if (algorithm != other.algorithm) return false
        if (contentType != other.contentType) return false
        if (certificateChain != other.certificateChain) return false
        if (notBefore != other.notBefore) return false
        if (issuedAt != other.issuedAt) return false
        if (expiration != other.expiration) return false
        if (jsonWebKey != other.jsonWebKey) return false
        if (jsonWebKeySetUrl != other.jsonWebKeySetUrl) return false
        if (certificateUrl != other.certificateUrl) return false
        if (certificateSha1Thumbprint != null) {
            if (other.certificateSha1Thumbprint == null) return false
            if (!certificateSha1Thumbprint.contentEquals(other.certificateSha1Thumbprint)) return false
        } else if (other.certificateSha1Thumbprint != null) return false
        if (certificateSha256Thumbprint != null) {
            if (other.certificateSha256Thumbprint == null) return false
            if (!certificateSha256Thumbprint.contentEquals(other.certificateSha256Thumbprint)) return false
        } else if (other.certificateSha256Thumbprint != null) return false
        if (attestationJwt != other.attestationJwt) return false

        return true
    }

    override fun hashCode(): Int {
        var result = keyId?.hashCode() ?: 0
        result = 31 * result + (type?.hashCode() ?: 0)
        result = 31 * result + algorithm.hashCode()
        result = 31 * result + (contentType?.hashCode() ?: 0)
        result = 31 * result + (certificateChain?.hashCode() ?: 0)
        result = 31 * result + (notBefore?.hashCode() ?: 0)
        result = 31 * result + (issuedAt?.hashCode() ?: 0)
        result = 31 * result + (expiration?.hashCode() ?: 0)
        result = 31 * result + (jsonWebKey?.hashCode() ?: 0)
        result = 31 * result + (jsonWebKeySetUrl?.hashCode() ?: 0)
        result = 31 * result + (certificateUrl?.hashCode() ?: 0)
        result = 31 * result + (certificateSha1Thumbprint?.contentHashCode() ?: 0)
        result = 31 * result + (certificateSha256Thumbprint?.contentHashCode() ?: 0)
        result = 31 * result + (attestationJwt?.hashCode() ?: 0)
        return result
    }

    /**
     * Tries to compute a public key in descending order from [jsonWebKey], [keyId],
     * or [certificateChain], and takes the first success or null.
     */
    val publicKey: CryptoPublicKey? by lazy {
        jsonWebKey?.toCryptoPublicKey()?.getOrNull()
            ?: keyId?.let { runCatching { CryptoPublicKey.fromDid(it) } }?.getOrNull()
            ?: certificateChain?.leaf?.publicKey
    }


    companion object {
        fun deserialize(it: String) = kotlin.runCatching {
            jsonSerializer.decodeFromString<JwsHeader>(it)
        }.wrap()

    }
}