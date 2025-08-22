package at.asitplus.signum.indispensable.josef

import at.asitplus.catching
import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import at.asitplus.signum.indispensable.io.CertificateChainBase64Serializer
import at.asitplus.signum.indispensable.josef.io.InstantLongSerializer
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.pki.CertificateChain
import kotlinx.datetime.Instant
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString

/**
 * Header of a [JweEncrypted] or [JweDecrypted].
 *
 * See [RFC 7516](https://datatracker.ietf.org/doc/html/rfc7516)
 */
@Serializable
data class JweHeader(
    /**
     * This parameter has the same meaning, syntax, and processing rules as
     * the "alg" Header Parameter defined in Section 4.1.1 of (JWS), except
     * that the Header Parameter identifies the cryptographic algorithm used
     * to encrypt or determine the value of the CEK.  The encrypted content
     * is not usable if the "alg" value does not represent a supported
     * algorithm, or if the recipient does not have a key that can be used
     * with that algorithm.
     */
    @SerialName("alg")
    val algorithm: JweAlgorithm?,

    /**
     * The "enc" (encryption algorithm) Header Parameter identifies the
     * content encryption algorithm used to perform authenticated encryption
     * on the plaintext to produce the ciphertext and the Authentication
     * Tag.  This algorithm MUST be an AEAD algorithm with a specified key
     * length.  The encrypted content is not usable if the "enc" value does
     * not represent a supported algorithm.  "enc" values should either be
     * registered in the IANA "JSON Web Signature and Encryption Algorithms"
     * registry established by (JWA) or be a value that contains a
     * Collision-Resistant Name.  The "enc" value is a case-sensitive ASCII
     * string containing a StringOrURI value.  This Header Parameter MUST be
     * present and MUST be understood and processed by implementations.
     */
    @SerialName("enc")
    val encryption: JweEncryption?,

    /**
     * This parameter has the same meaning, syntax, and processing rules as
     * the "kid" Header Parameter defined in Section 4.1.4 of (JWS), except
     * that the key hint references the public key to which the JWE was
     * encrypted; this can be used to determine the private key needed to
     * decrypt the JWE.  This parameter allows originators to explicitly
     * signal a change of key to JWE recipients.
     *
     * See [JwsHeader.keyId]
     */
    @SerialName("kid")
    val keyId: String? = null,

    /**
     * This parameter has the same meaning, syntax, and processing rules as
     * the "typ" Header Parameter defined in Section 4.1.9 of (JWS), except
     * that the type is that of this complete JWE.
     *
     * See [JwsHeader.type]
     */
    @SerialName("typ")
    val type: String? = null,

    /**
     * This parameter has the same meaning, syntax, and processing rules as
     * the "cty" Header Parameter defined in Section 4.1.10 of [JWS], except
     * that the type is that of the secured content (the plaintext).
     *
     * See [JwsHeader.contentType]
     */
    @SerialName("cty")
    val contentType: String? = null,

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
     * This parameter has the same meaning, syntax, and processing rules as
     * the "jwk" Header Parameter defined in Section 4.1.3 of [JWS], except
     * that the key is the public key to which the JWE was encrypted; this
     * can be used to determine the private key needed to decrypt the JWE.
     *
     * See [JwsHeader.jsonWebKey]
     */
    @SerialName("jwk")
    val jsonWebKey: JsonWebKey? = null,

    /**
     * This parameter has the same meaning, syntax, and processing rules as
     * the "jku" Header Parameter defined in Section 4.1.2 of [JWS], except
     * that the JWK Set resource contains the public key to which the JWE
     * was encrypted; this can be used to determine the private key needed
     * to decrypt the JWE.
     *
     * See [JwsHeader.jsonWebKeySetUrl]
     */
    @SerialName("jku")
    val jsonWebKeyUrl: String? = null,

    /**
     * RFC 7518: The "epk" (ephemeral public key) value created by the originator for
     * the use in key agreement algorithms.  This key is represented as a
     * JSON Web Key (JWK) public key value.  It MUST contain only public key
     * parameters and SHOULD contain only the minimum JWK parameters
     * necessary to represent the key; other JWK parameters included can be
     * checked for consistency and honored, or they can be ignored.  This
     * Header Parameter MUST be present and MUST be understood and processed
     * by implementations when these algorithms are used.
     */
    @SerialName("epk")
    val ephemeralKeyPair: JsonWebKey? = null,

    /**
     * RFC 7518: The "apu" (agreement PartyUInfo) value for key agreement algorithms
     * using it (such as "ECDH-ES"), represented as a base64url-encoded
     * string.  When used, the PartyUInfo value contains information about
     * the producer.  Use of this Header Parameter is OPTIONAL.  This Header
     * Parameter MUST be understood and processed by implementations when
     * these algorithms are used.
     */
    @SerialName("apu")
    @Serializable(with = ByteArrayBase64UrlSerializer::class)
    val agreementPartyUInfo: ByteArray? = null,

    /**
     * RFC 7518: The "apv" (agreement PartyVInfo) value for key agreement algorithms
     * using it (such as "ECDH-ES"), represented as a base64url encoded
     * string.  When used, the PartyVInfo value contains information about
     * the recipient.  Use of this Header Parameter is OPTIONAL.  This
     * Header Parameter MUST be understood and processed by implementations
     * when these algorithms are used.
     */
    @SerialName("apv")
    @Serializable(with = ByteArrayBase64UrlSerializer::class)
    val agreementPartyVInfo: ByteArray? = null,

    /**
     * RFC 7518: The "iv" (initialization vector) Header Parameter value is the
     * base64url-encoded representation of the 96-bit IV value used for the
     * key encryption operation.  This Header Parameter MUST be present and
     * MUST be understood and processed by implementations when these
     * algorithms are used.
     */
    @SerialName("iv")
    @Serializable(with = ByteArrayBase64UrlSerializer::class)
    val initializationVector: ByteArray? = null,

    /**
     * RFC 7518: The "tag" (authentication tag) Header Parameter value is the
     * base64url-encoded representation of the 128-bit Authentication Tag
     * value resulting from the key encryption operation.  This Header
     * Parameter MUST be present and MUST be understood and processed by
     * implementations when these algorithms are used.
     */
    @SerialName("tag")
    @Serializable(with = ByteArrayBase64UrlSerializer::class)
    val authenticationTag: ByteArray? = null,

    /**
     * This parameter has the same meaning, syntax, and processing rules as
     * the "x5u" Header Parameter defined in Section 4.1.5 of (JWS), except
     * that the X.509 public key certificate or certificate chain (RFC5280)
     * contains the public key to which the JWE was encrypted; this can be
     * used to determine the private key needed to decrypt the JWE.
     *
     * See [JwsHeader.certificateUrl]
     */
    @SerialName("x5u")
    val certificateUrl: String? = null,

    /**
     * This parameter has the same meaning, syntax, and processing rules as
     * the "x5c" Header Parameter defined in Section 4.1.6 of (JWS), except
     * that the X.509 public key certificate or certificate chain (RFC5280)
     * contains the public key to which the JWE was encrypted; this can be
     * used to determine the private key needed to decrypt the JWE.
     *
     * See [JwsHeader.certificateChain]
     */
    @SerialName("x5c")
    @Serializable(with = CertificateChainBase64Serializer::class)
    val certificateChain: CertificateChain? = null,

    /**
     * This parameter has the same meaning, syntax, and processing rules as
     * the "x5t" Header Parameter defined in Section 4.1.7 of (JWS), except
     * that the certificate referenced by the thumbprint contains the public
     * key to which the JWE was encrypted; this can be used to determine the
     * private key needed to decrypt the JWE.  Note that certificate
     * thumbprints are also sometimes known as certificate fingerprints.
     *
     * See [JwsHeader.certificateSha1Thumbprint]
     */
    @SerialName("x5t")
    @Serializable(with = ByteArrayBase64UrlSerializer::class)
    val certificateSha1Thumbprint: ByteArray? = null,

    /**
     * This parameter has the same meaning, syntax, and processing rules as
     * the "x5t#S256" Header Parameter defined in Section 4.1.8 of (JWS),
     * except that the certificate referenced by the thumbprint contains the
     * public key to which the JWE was encrypted; this can be used to
     * determine the private key needed to decrypt the JWE.  Note that
     * certificate thumbprints are also sometimes known as certificate
     * fingerprints.
     *
     * See [JwsHeader.certificateSha256Thumbprint]
     */
    @SerialName("x5t#S256")
    @Serializable(with = ByteArrayBase64UrlSerializer::class)
    val certificateSha256Thumbprint: ByteArray? = null,
) {

    @Deprecated("To be removed in next release")
    fun serialize() = joseCompliantSerializer.encodeToString(this)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as JweHeader

        if (algorithm != other.algorithm) return false
        if (encryption != other.encryption) return false
        if (keyId != other.keyId) return false
        if (type != other.type) return false
        if (contentType != other.contentType) return false
        if (notBefore != other.notBefore) return false
        if (issuedAt != other.issuedAt) return false
        if (expiration != other.expiration) return false
        if (jwtId != other.jwtId) return false
        if (jsonWebKey != other.jsonWebKey) return false
        if (jsonWebKeyUrl != other.jsonWebKeyUrl) return false
        if (ephemeralKeyPair != other.ephemeralKeyPair) return false
        if (!agreementPartyUInfo.contentEquals(other.agreementPartyUInfo)) return false
        if (!agreementPartyVInfo.contentEquals(other.agreementPartyVInfo)) return false
        if (!initializationVector.contentEquals(other.initializationVector)) return false
        if (!authenticationTag.contentEquals(other.authenticationTag)) return false
        if (certificateUrl != other.certificateUrl) return false
        if (certificateChain != other.certificateChain) return false
        if (!certificateSha1Thumbprint.contentEquals(other.certificateSha1Thumbprint)) return false
        if (!certificateSha256Thumbprint.contentEquals(other.certificateSha256Thumbprint)) return false
        if (publicKey != other.publicKey) return false

        return true
    }

    override fun hashCode(): Int {
        var result = algorithm?.hashCode() ?: 0
        result = 31 * result + (encryption?.hashCode() ?: 0)
        result = 31 * result + (keyId?.hashCode() ?: 0)
        result = 31 * result + (type?.hashCode() ?: 0)
        result = 31 * result + (contentType?.hashCode() ?: 0)
        result = 31 * result + (notBefore?.hashCode() ?: 0)
        result = 31 * result + (issuedAt?.hashCode() ?: 0)
        result = 31 * result + (expiration?.hashCode() ?: 0)
        result = 31 * result + (jwtId?.hashCode() ?: 0)
        result = 31 * result + (jsonWebKey?.hashCode() ?: 0)
        result = 31 * result + (jsonWebKeyUrl?.hashCode() ?: 0)
        result = 31 * result + (ephemeralKeyPair?.hashCode() ?: 0)
        result = 31 * result + (agreementPartyUInfo?.contentHashCode() ?: 0)
        result = 31 * result + (agreementPartyVInfo?.contentHashCode() ?: 0)
        result = 31 * result + (initializationVector?.contentHashCode() ?: 0)
        result = 31 * result + (authenticationTag?.contentHashCode() ?: 0)
        result = 31 * result + (certificateUrl?.hashCode() ?: 0)
        result = 31 * result + (certificateChain?.hashCode() ?: 0)
        result = 31 * result + (certificateSha1Thumbprint?.contentHashCode() ?: 0)
        result = 31 * result + (certificateSha256Thumbprint?.contentHashCode() ?: 0)
        result = 31 * result + (publicKey?.hashCode() ?: 0)
        return result
    }


    val publicKey: JsonWebKey? by lazy {
        jsonWebKey ?: keyId?.let { JsonWebKey.fromDid(it).getOrNull() }
    }

    companion object {

        @Deprecated("To be removed in next release")
        fun deserialize(it: String) = catching {
            joseCompliantSerializer.decodeFromString<JweHeader>(it)
        }
    }
}
