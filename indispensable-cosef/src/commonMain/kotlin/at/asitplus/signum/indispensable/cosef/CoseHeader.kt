package at.asitplus.signum.indispensable.cosef

import at.asitplus.catching
import at.asitplus.signum.indispensable.cosef.io.Base16Strict
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.*
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.CborLabel

/**
 * Protected header of a [CoseSigned].
 *
 * See [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html).
 */
@OptIn(ExperimentalSerializationApi::class)
@Serializable(with = CoseHeaderSerializer::class)
data class CoseHeader(
    /**
     * This header parameter is used to indicate the algorithm used for the security processing. This header parameter
     * MUST be authenticated where the ability to do so exists. This support is provided by AEAD algorithms or
     * construction (e.g., COSE_Sign and COSE_Mac0). This authentication can be done either by placing the header
     * parameter in the protected-header-parameters bucket or as part of the externally supplied data (Section 4.3).
     * The value is taken from the "COSE Algorithms" registry.
     */
    @CborLabel(1)
    @SerialName("alg")
    val algorithm: CoseAlgorithm? = null,

    /**
     * This header parameter is used to indicate which protected header parameters an application that is processing a
     * message is required to understand. Header parameters defined in this document do not need to be included, as they
     * should be understood by all implementations. Additionally, the header parameter "counter signature" (label 7)
     * defined by RFC8152 must be understood by new implementations, to remain compatible with senders that adhere to
     * that document and assume all implementations will understand it. When present, the "crit" header parameter MUST
     * be placed in the protected-header-parameters bucket. The array MUST have at least one value in it.
     */
    @CborLabel(2)
    @SerialName("crit")
    val criticalHeaders: String? = null,

    /**
     * This header parameter is used to indicate the content type of the data in the "payload" or "ciphertext" field.
     * Integers are from the "CoAP Content-Formats" IANA registry table. Text values follow the syntax of
     * "<type-name>/<subtype-name>", where <type-name> and <subtype-name> are defined in Section 4.2 of RFC6838.
     * Leading and trailing whitespace is not permitted. Textual content type values, along with parameters and
     * subparameters, can be located using the IANA "Media Types" registry. Applications SHOULD provide this header
     * parameter if the content structure is potentially ambiguous.
     */
    @CborLabel(3)
    @SerialName("content type")
    val contentType: String? = null,

    /**
     * This header parameter identifies one piece of data that can be used as input to find the needed cryptographic
     * key. The value of this header parameter can be matched against the "kid" member in a COSE_Key structure. Other
     * methods of key distribution can define an equivalent field to be matched. Applications MUST NOT assume that "kid"
     * values are unique. There may be more than one key with the same "kid" value, so all of the keys associated with
     * this "kid" may need to be checked. The internal structure of "kid" values is not defined and cannot be relied on
     * by applications. Key identifier values are hints about which key to use. This is not a security-critical field.
     * For this reason, it can be placed in the unprotected-header-parameters bucket.
     */
    @CborLabel(4)
    @SerialName("kid")
    @ByteString
    val kid: ByteArray? = null,

    /**
     * This header parameter holds the Initialization Vector (IV) value. For some symmetric encryption algorithms, this
     * may be referred to as a nonce. The IV can be placed in the unprotected bucket, since for AE and AEAD algorithms,
     * modifying the IV will cause the decryption to fail.
     */
    @CborLabel(5)
    @SerialName("IV")
    @ByteString
    val iv: ByteArray? = null,

    /**
     * This header parameter holds a part of the IV value. When using the COSE_Encrypt0 structure, a portion of the IV
     * can be part of the context associated with the key (Context IV), while a portion can be changed with each message
     * (Partial IV). This field is used to carry a value that causes the IV to be changed for each message. The Partial
     * IV can be placed in the unprotected bucket, as modifying the value will cause the decryption to yield plaintext
     * that is readily detectable as garbled. The "Initialization Vector" and "Partial Initialization Vector" header
     * parameters MUST NOT both be present in the same security layer.
     */
    @CborLabel(6)
    @SerialName("Partial IV")
    @ByteString
    val partialIv: ByteArray? = null,

    /**
     * This header parameter contains an ordered array of X.509 certificates. The certificates are to be ordered
     * starting with the certificate containing the end-entity key followed by the certificate that signed it, and so
     * on. There is no requirement for the entire chain to be present in the element if there is reason to believe that
     * the relying party already has, or can locate, the missing certificates. This means that the relying party is
     * still required to do path building but that a candidate path is proposed in this header parameter.
     *
     * This header parameter allows for a single X.509 certificate or a chain of X.509 certificates to be carried in
     * the message.
     *
     * See [RFC9360](https://www.rfc-editor.org/rfc/rfc9360.html)
     */
    @CborLabel(33)
    @SerialName("x5chain")
    @ByteString
    val certificateChain: List<ByteArray>? = null,

    /**
     * https://www.rfc-editor.org/rfc/rfc9596
     * The "typ" (type) header parameter is used by COSE applications to declare the type of
     * this complete COSE object, as compared to the content type header parameter, which declares
     * the type of the COSE object payload. This is intended for use by the application when more
     * than one kind of COSE object could be present in an application data structure that can
     * contain a COSE object; the application can use this value to disambiguate among the different
     * kinds of COSE objects that might be present. It will typically not be used by applications
     * when the kind of COSE object is already known. Use of this header parameter is OPTIONAL.
     */
    @CborLabel(16)
    @SerialName("typ")
    val type: String? = null,
) {


    @Deprecated("To be removed in next release")
    fun serialize() = coseCompliantSerializer.encodeToByteArray(this)
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as CoseHeader

        if (algorithm != other.algorithm) return false
        if (criticalHeaders != other.criticalHeaders) return false
        if (contentType != other.contentType) return false
        if (!kid.contentEquals(other.kid)) return false
        if (!iv.contentEquals(other.iv)) return false
        if (!partialIv.contentEquals(other.partialIv)) return false
        if (certificateChain != null) {
            if (other.certificateChain == null) return false
            if (!certificateChain.all { t -> other.certificateChain.any { it.contentEquals(t) } }) return false
            if (!other.certificateChain.all { o -> certificateChain.any { it.contentEquals(o) } }) return false
        } else if (other.certificateChain != null) return false
        if (type != other.type) return false

        return true
    }

    override fun hashCode(): Int {
        var result = algorithm?.hashCode() ?: 0
        result = 31 * result + (criticalHeaders?.hashCode() ?: 0)
        result = 31 * result + (contentType?.hashCode() ?: 0)
        result = 31 * result + (kid?.contentHashCode() ?: 0)
        result = 31 * result + (iv?.contentHashCode() ?: 0)
        result = 31 * result + (partialIv?.contentHashCode() ?: 0)
        result = 31 * result + (certificateChain?.hashCode() ?: 0)
        result = 31 * result + (type?.hashCode() ?: 0)
        return result
    }

    override fun toString(): String {
        return "CoseHeader(" +
                "algorithm=$algorithm, " +
                "criticalHeaders=$criticalHeaders, " +
                "contentType=$contentType, " +
                "kid=${kid?.encodeToString(Base16Strict)}, " +
                "iv=${iv?.encodeToString(Base16Strict)}, " +
                "partialIv=${partialIv?.encodeToString(Base16Strict)}, " +
                "certificateChain=${certificateChain?.joinToString { it.encodeToString(Base16Strict) }}, " +
                "type=$type" +
                ")"
    }

    companion object {

        @Deprecated("To be removed in next release")
        fun deserialize(it: ByteArray) = catching {
            coseCompliantSerializer.decodeFromByteArray<CoseHeader>(it)
        }
    }
}
