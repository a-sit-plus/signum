package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.Transient
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.decodeFromJsonElement


/**
 * Signature element as defined in [RFC 7515 Sec 7.2.1](https://www.rfc-editor.org/rfc/rfc7515.html#section-7.2.1)
 */
@Serializable
data class SignatureElement(
    /**
     * The [plainSignature] member MUST be present
     *
     * Serialization: BASE64URL(JWS Signature).
     */
    @SerialName(JWS.SerialNames.SIGNATURE)
    @Serializable(ByteArrayBase64UrlSerializer::class)
    val plainSignature: ByteArray,

    /**
     * The [protectedHeader] member MUST be present ...when the JWS Protected
     * Header value is non-empty; otherwise, it MUST be absent.  These
     * Header Parameter values are integrity protected.
     *
     * Serialization: BASE64URL(UTF8(JWS Protected Header))
     */
    @SerialName(JWS.SerialNames.PROTECTED)
    @Serializable(with = ByteArrayBase64UrlSerializer::class)
    val plainProtectedHeader: ByteArray? = null,

    @SerialName(JWS.SerialNames.HEADER)
    val unprotectedHeader: JsonObject? = null
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as SignatureElement

        if (!plainSignature.contentEquals(other.plainSignature)) return false
        if (!plainProtectedHeader.contentEquals(other.plainProtectedHeader)) return false
        return true
    }

    override fun hashCode(): Int {
        var result = plainSignature.contentHashCode()
        result = 31 * result + plainProtectedHeader.contentHashCode()
        return result
    }

    @Transient
    val protectedHeader: JsonObject? =
        plainProtectedHeader?.let { joseCompliantSerializer.decodeFromString(it.decodeToString()) }

    /**
     * Only the combined header must be a valid [JwsHeader]
     */
    @Transient
    val combinedHeader: JwsHeader =
        joseCompliantSerializer.decodeFromJsonElement(unprotectedHeader.strictUnion(protectedHeader))

    /**
     * Lenient Signature Parsing
     */
    @Transient
    val signature: CryptoSignature.RawByteEncodable
        get() = when (val alg = combinedHeader.algorithm) {
            is JwsAlgorithm.Signature.EC -> CryptoSignature.EC.fromRawBytes(alg.ecCurve, plainSignature)
            is JwsAlgorithm.Signature.RSA -> CryptoSignature.RSA(plainSignature)
            else -> throw SerializationException("Unsupported algorithm for JWS signature element: $alg")
        }
}
