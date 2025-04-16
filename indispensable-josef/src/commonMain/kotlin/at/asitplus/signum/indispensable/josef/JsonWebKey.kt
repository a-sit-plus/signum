@file:UseSerializers(JwsCertificateSerializer::class)

package at.asitplus.signum.indispensable.josef

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoPublicKey.EC.Companion.fromUncompressed
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.SecretExposure
import at.asitplus.signum.indispensable.SpecializedCryptoPublicKey
import at.asitplus.signum.indispensable.asn1.Asn1Integer
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import at.asitplus.signum.indispensable.io.CertificateChainBase64UrlSerializer
import at.asitplus.signum.indispensable.josef.io.JwsCertificateSerializer
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.symmetric.*
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.UseSerializers
import kotlinx.serialization.json.Json
import okio.ByteString.Companion.toByteString

/**
 * JSON Web Key as per [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517#section-4).
 *
 * Note that the members are ordered lexicographically, as required for JWK Thumbprint calculation,
 * see [RFC7638 s3](https://www.rfc-editor.org/rfc/rfc7638.html#section-3)
 */
@Serializable
data class JsonWebKey(
    /**
     * The "alg" (algorithm) parameter identifies the algorithm intended for
     * use with the key.  The values used should either be registered in the
     * IANA "JSON Web Signature and Encryption Algorithms" registry
     * established by [JWA] or be a value that contains a collision-resistant Name.
     * The "alg" value is a case-sensitive ASCII string.
     * Use of this member is OPTIONAL.
     */
    @SerialName("alg")
    val algorithm: JsonWebAlgorithm? = null,

    /**
     * Set for EC keys only
     */
    @SerialName("crv")
    val curve: ECCurve? = null,

    /**
     * Set for RSA keys only
     */
    @SerialName("e")
    @Serializable(with = ByteArrayBase64UrlSerializer::class)
    val e: ByteArray? = null,

    /**
     * Set for symmetric keys only
     */
    @SerialName("k")
    @Serializable(with = ByteArrayBase64UrlSerializer::class)
    val k: ByteArray? = null,

    /**
     * The "key_ops" (key operations) parameter identifies the operation(s)
     * for which the key is intended to be used.  The "key_ops" parameter is
     * intended for use cases in which public, private, or symmetric keys
     * may be present.
     */
    @SerialName("key_ops")
    val keyOperations: Set<String>? = null,

    /**
     * The "kid" (key ID) parameter is used to match a specific key.  This
     * is used, for instance, to choose among a set of keys within a JWK Set
     * during key rollover.  The structure of the "kid" value is
     * unspecified.  When "kid" values are used within a JWK Set, different
     * keys within the JWK Set SHOULD use distinct "kid" values.  (One
     * example in which different keys might use the same "kid" value is if
     * they have different "kty" (key type) values but are considered to be
     * equivalent alternatives by the application using them.)  The "kid"
     * value is a case-sensitive string.  Use of this member is OPTIONAL.
     * When used with JWS or JWE, the "kid" value is used to match a JWS or
     * JWE "kid" Header Parameter value.
     */
    @SerialName("kid")
    val keyId: String? = null,

    /**
     * The "kty" (key type) parameter identifies the cryptographic algorithm
     * family used with the key, such as "RSA" or "EC".  "kty" values should
     * either be registered in the IANA "JSON Web Key Types" registry
     * established by (JWA) or be a value that contains a Collision-Resistant
     * Name.  The "kty" value is a case-sensitive string.  This
     * member MUST be present in a JWK.
     */
    @SerialName("kty")
    val type: JwkType? = null,

    /**
     * Set for RSA keys only
     */
    @SerialName("n")
    @Serializable(with = ByteArrayBase64UrlSerializer::class)
    val n: ByteArray? = null,

    /**
     * The "use" (public key use) parameter identifies the intended use of
     * the public key.  The "use" parameter is employed to indicate whether
     * a public key is used for encrypting data or verifying the signature
     * on data.
     */
    @SerialName("use")
    val publicKeyUse: String? = null,

    /**
     * Set for EC keys only
     */
    @SerialName("x")
    @Serializable(with = ByteArrayBase64UrlSerializer::class)
    val x: ByteArray? = null,

    /**
     * The "x5c" (X.509 certificate chain) parameter contains a chain of one
     * or more PKIX certificates (RFC5280).  The certificate chain is
     * represented as a JSON array of certificate value strings.  Each
     * string in the array is a base64-encoded (Section 4 of (RFC4648) --
     * not base64url-encoded) DER (ITU.X690.1994) PKIX certificate value.
     * The PKIX certificate containing the key value MUST be the first
     * certificate.  This MAY be followed by additional certificates, with
     * each subsequent certificate being the one used to certify the
     * previous one.  The key in the first certificate MUST match the public
     * key represented by other members of the JWK.  Use of this member is
     * OPTIONAL.
     */
    @SerialName("x5c")
    @Serializable(with = CertificateChainBase64UrlSerializer::class)
    val certificateChain: CertificateChain? = null,

    /**
     * The "x5t" (X.509 certificate SHA-1 thumbprint) parameter is a
     * base64url-encoded SHA-1 thumbprint (a.k.a. digest) of the DER
     * encoding of an X.509 certificate (RFC5280).  Note that certificate
     * thumbprints are also sometimes known as certificate fingerprints.
     * The key in the certificate MUST match the public key represented by
     * other members of the JWK.  Use of this member is OPTIONAL.
     */
    @SerialName("x5t")
    @Serializable(with = ByteArrayBase64UrlSerializer::class)
    val certificateSha1Thumbprint: ByteArray? = null,

    /**
     * The "x5u" (X.509 URL) parameter is a URI (RFC3986) that refers to a
     * resource for an X.509 public key certificate or certificate chain
     * (RFC5280).  The identified resource MUST provide a representation of
     * the certificate or certificate chain that conforms to RFC 5280
     * (RFC5280) in PEM-encoded form, with each certificate delimited as
     * specified in Section 6.1 of RFC 4945 (RFC4945).  The key in the first
     * certificate MUST match the public key represented by other members of
     * the JWK.  The protocol used to acquire the resource MUST provide
     * integrity protection; an HTTP GET request to retrieve the certificate
     * MUST use TLS (RFC2818) (RFC5246); the identity of the server MUST be
     * validated, as per Section 6 of RFC 6125 (RFC6125).  Use of this
     * member is OPTIONAL.
     */
    @SerialName("x5u")
    val certificateUrl: String? = null,

    /**
     * The "x5t#S256" (X.509 certificate SHA-256 thumbprint) parameter is a
     * base64url-encoded SHA-256 thumbprint (a.k.a. digest) of the DER
     * encoding of an X.509 certificate (RFC5280).  Note that certificate
     * thumbprints are also sometimes known as certificate fingerprints.
     * The key in the certificate MUST match the public key represented by
     * other members of the JWK.  Use of this member is OPTIONAL.
     */
    @SerialName("x5t#S256")
    @Serializable(with = ByteArrayBase64UrlSerializer::class)
    val certificateSha256Thumbprint: ByteArray? = null,

    /**
     * Set for EC keys only
     */
    @SerialName("y")
    @Serializable(with = ByteArrayBase64UrlSerializer::class)
    val y: ByteArray? = null,
) : SpecializedCryptoPublicKey, SpecializedSymmetricKey {

    /**
     * Thumbprint in the form of `urn:ietf:params:oauth:jwk-thumbprint:sha256:DEADBEEF`
     *
     * See [RFC9278](https://www.rfc-editor.org/rfc/rfc9278.html)
     */
    val jwkThumbprint: String by lazy {
        val jsonEncoded = Json.encodeToString(this.toMinimalJsonWebKey().getOrNull() ?: this)
        val thumbprint = jsonEncoded
            .encodeToByteArray().toByteString().sha256().toByteArray().encodeToString(Base64UrlStrict)
        "urn:ietf:params:oauth:jwk-thumbprint:sha256:${thumbprint}"
    }

    fun serialize() = joseCompliantSerializer.encodeToString(this)

    val didEncoded: String? by lazy { toCryptoPublicKey().getOrNull()?.didEncoded }

    override fun toString(): String {
        return "JsonWebKey(curve=$curve," +
                " type=$type," +
                " keyId=$keyId," +
                " x=${x?.encodeToString(Base64UrlStrict)}," +
                " y=${y?.encodeToString(Base64UrlStrict)}," +
                " n=${n?.encodeToString(Base64UrlStrict)}," +
                " e=${e?.encodeToString(Base64UrlStrict)}," +
                " k=${k?.encodeToString(Base64UrlStrict)}," +
                " publicKeyUse=$publicKeyUse," +
                " keyOperations=$keyOperations," +
                " algorithm=$algorithm," +
                " certificateUrl=$certificateUrl," +
                " certificateChain=${certificateChain}," +
                " certificateSha1Thumbprint=${certificateSha1Thumbprint?.encodeToString(Base64UrlStrict)}," +
                " certificateSha256Thumbprint=${certificateSha256Thumbprint?.encodeToString(Base64UrlStrict)})"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as JsonWebKey

        if (curve != other.curve) return false
        if (type != other.type) return false
        if (keyId != other.keyId) return false
        if (x != null) {
            if (other.x == null) return false
            if (!x.contentEquals(other.x)) return false
        } else if (other.x != null) return false
        if (y != null) {
            if (other.y == null) return false
            if (!y.contentEquals(other.y)) return false
        } else if (other.y != null) return false
        if (n != null) {
            if (other.n == null) return false
            if (!n.contentEquals(other.n)) return false
        } else if (other.n != null) return false
        if (e != null) {
            if (other.e == null) return false
            if (!e.contentEquals(other.e)) return false
        } else if (other.e != null) return false
        if (k != null) {
            if (other.k == null) return false
            if (!k.contentEquals(other.k)) return false
        } else if (other.k != null) return false
        if (publicKeyUse != other.publicKeyUse) return false
        if (keyOperations != other.keyOperations) return false
        if (algorithm != other.algorithm) return false
        if (certificateUrl != other.certificateUrl) return false
        if (certificateChain != other.certificateChain) return false
        if (certificateSha1Thumbprint != null) {
            if (other.certificateSha1Thumbprint == null) return false
            if (!certificateSha1Thumbprint.contentEquals(other.certificateSha1Thumbprint)) return false
        } else if (other.certificateSha1Thumbprint != null) return false
        if (certificateSha256Thumbprint != null) {
            if (other.certificateSha256Thumbprint == null) return false
            if (!certificateSha256Thumbprint.contentEquals(other.certificateSha256Thumbprint)) return false
        } else if (other.certificateSha256Thumbprint != null) return false

        return true
    }

    override fun hashCode(): Int {
        var result = curve?.hashCode() ?: 0
        result = 31 * result + (type?.hashCode() ?: 0)
        result = 31 * result + (keyId?.hashCode() ?: 0)
        result = 31 * result + (x?.contentHashCode() ?: 0)
        result = 31 * result + (y?.contentHashCode() ?: 0)
        result = 31 * result + (n?.contentHashCode() ?: 0)
        result = 31 * result + (e?.contentHashCode() ?: 0)
        result = 31 * result + (k?.contentHashCode() ?: 0)
        result = 31 * result + (publicKeyUse?.hashCode() ?: 0)
        result = 31 * result + (keyOperations?.hashCode() ?: 0)
        result = 31 * result + (algorithm?.hashCode() ?: 0)
        result = 31 * result + (certificateUrl?.hashCode() ?: 0)
        result = 31 * result + (certificateChain?.hashCode() ?: 0)
        result = 31 * result + (certificateSha1Thumbprint?.contentHashCode() ?: 0)
        result = 31 * result + (certificateSha256Thumbprint?.contentHashCode() ?: 0)
        return result
    }

    /**
     * @return a KmmResult wrapped [CryptoPublicKey] equivalent if conversion is possible
     * (i.e. if all key params are set), or the first error.
     */
    override fun toCryptoPublicKey(): KmmResult<CryptoPublicKey> = catching {
        when (type) {
            JwkType.EC -> {
                fromUncompressed(
                    curve = curve ?: throw IllegalArgumentException("Missing or invalid curve"),
                    x = x ?: throw IllegalArgumentException("Missing x-coordinate"),
                    y = y ?: throw IllegalArgumentException("Missing y-coordinate")
                ).apply { jwkId = keyId }
            }

            JwkType.RSA -> {
                CryptoPublicKey.RSA(
                    n = Asn1Integer.fromUnsignedByteArray(
                        n ?: throw IllegalArgumentException("Missing modulus n")
                    ),
                    e = Asn1Integer.fromUnsignedByteArray(
                        e ?: throw IllegalArgumentException("Missing or invalid exponent e")
                    )
                ).apply { jwkId = keyId }
            }

            else -> throw IllegalArgumentException("Illegal key type")
        }
    }

    /**
     * @return a copy of this key with the minimal required members as listed in
     * [RFC7638 3.2](https://www.rfc-editor.org/rfc/rfc7638.html#section-3.2)
     */
    fun toMinimalJsonWebKey(): KmmResult<JsonWebKey> = catching {
        when (type) {
            JwkType.EC -> JsonWebKey(type = JwkType.EC, curve = curve, x = x, y = y)
            JwkType.RSA -> JsonWebKey(type = JwkType.RSA, n = n, e = e)
            JwkType.SYM -> JsonWebKey(type = JwkType.SYM, k = k)
            else -> throw IllegalArgumentException("Illegal key type")
        }
    }

    /**
     * Contains convenience functions
     */
    companion object {
        fun deserialize(it: String): KmmResult<JsonWebKey> =
            catching { joseCompliantSerializer.decodeFromString<JsonWebKey>(it) }

        fun fromDid(input: String): KmmResult<JsonWebKey> =
            catching { CryptoPublicKey.fromDid(input).also { it.jwkId = input }.toJsonWebKey() }

        fun fromIosEncoded(bytes: ByteArray): KmmResult<JsonWebKey> =
            catching { CryptoPublicKey.fromIosEncoded(bytes).toJsonWebKey() }

        fun fromCoordinates(curve: ECCurve, x: ByteArray, y: ByteArray): KmmResult<JsonWebKey> =
            catching { fromUncompressed(curve, x, y).toJsonWebKey() }
    }

    /**
     * Transforms this JsonWebKey into a [SymmetricKey] if an algorithm mapping exists.
     * Note: for [JweEncryption], see [JweEncryption.symmetricKeyFromJsonWebKeyBytes].
     * Supported algorithms are:
     * * [SymmetricEncryptionAlgorithm.AES.GCM]
     * * [SymmetricEncryptionAlgorithm.AES.WRAP]
     *
     */
    override fun toSymmetricKey(): KmmResult<SymmetricKey<*, *, *>> = catching {
        require(algorithm is JweAlgorithm.Symmetric) { "Not a symmetric JweAlgorithm" }
        require(k != null) { "key bytes not present" }
        when (val alg = algorithm.algorithm) {
            is SymmetricEncryptionAlgorithm.AES.GCM -> alg.keyFrom(k).getOrThrow()
            is SymmetricEncryptionAlgorithm.AES.WRAP.RFC3394 -> alg.keyFrom(k).getOrThrow()
            else -> throw IllegalArgumentException("Unsupported algorithm $algorithm")
        }
    }
}

/**
 * Converts this symmetric key to a [JsonWebKey]. [algorithm] may be null for algorithms, which do not directly
 * correspond to a valid JWA `alg` identifier but will still be encoded.
 * * Allowed key operations can be restricted by specifying [includedOps]
 * */
fun SymmetricKey<*, *, *>.toJsonWebKey(keyId: String? = this.jwkId, vararg includedOps: String): KmmResult<JsonWebKey> =
    catching {
        @OptIn(SecretExposure::class)
        JsonWebKey(
            k = jsonWebKeyBytes.getOrThrow(),
            type = JwkType.SYM,
            keyId = keyId,
            algorithm = algorithm.toJweKwAlgorithm().getOrThrow(),
            keyOperations = includedOps.toSet()
        )
    }

/**
 * converts a symmetric key to its JWE serializable form (i.e. a single bytearray)
 */
@OptIn(SecretExposure::class)
val SymmetricKey<*, *, *>.jsonWebKeyBytes
    get() = catching {
        when (hasDedicatedMacKey()) {
            true -> macKey.getOrThrow() + encryptionKey.getOrThrow()
            false -> secretKey.getOrThrow()
        }
    }

/**
 * Converts a [CryptoPublicKey] to a [JsonWebKey]
 */
fun CryptoPublicKey.toJsonWebKey(keyId: String? = this.jwkId): JsonWebKey =
    when (this) {
        is CryptoPublicKey.EC ->
            JsonWebKey(
                type = JwkType.EC,
                keyId = keyId,
                curve = curve,
                x = xBytes,
                y = yBytes
            )


        is CryptoPublicKey.RSA ->
            JsonWebKey(
                type = JwkType.RSA,
                keyId = keyId,
                n = n.magnitude,
                e = e.magnitude
            )
    }

/**
 * Converts a [at.asitplus.signum.indispensable.symmetric.SymmetricKey] to a [JsonWebKey]
 */
fun SymmetricKey<*, *, *>.toJsonWebKey(keyId: String? = this.jwkId): KmmResult<JsonWebKey> = catching {
    val jwAlg = this.algorithm.toJweKwAlgorithm().getOrThrow()
    JsonWebKey(algorithm = jwAlg, keyId = keyId, k = jsonWebKeyBytes.getOrNull())
}


private const val JWK_ID = "jwkIdentifier"

/**
 * Holds [JsonWebKey.keyId] when transforming a [JsonWebKey] to a [CryptoPublicKey]
 */
var CryptoPublicKey.jwkId: String?
    get() = additionalProperties[JWK_ID]
    set(value) {
        value?.also { additionalProperties[JWK_ID] = value } ?: additionalProperties.remove(JWK_ID)
    }

/**
 * Holds [JsonWebKey.keyId] when transforming a [JsonWebKey] to a [CryptoPublicKey]
 */
var SymmetricKey<*, *, *>.jwkId: String?
    get() = additionalProperties[JWK_ID]
    set(value) {
        value?.also { additionalProperties[JWK_ID] = value } ?: additionalProperties.remove(JWK_ID)
    }