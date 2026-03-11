package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

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
     * The [plainProtectedHeader] member MUST be present ...when the JWS Protected
     * Header value is non-empty; otherwise, it MUST be absent.  These
     * Header Parameter values are integrity protected.
     *
     * Serialization: BASE64URL(UTF8(JWS Protected Header))
     */
    @SerialName(JWS.SerialNames.PROTECTED)
    @Serializable(with = ByteArrayBase64UrlSerializer::class)
    val plainProtectedHeader: ByteArray? = null,

    @SerialName(JWS.SerialNames.HEADER)
    val unprotectedHeader: JwsHeader.Part? = null
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as SignatureElement

        if (!plainSignature.contentEquals(other.plainSignature)) return false
        if (!plainProtectedHeader.contentEquals(other.plainProtectedHeader)) return false
        if (unprotectedHeader != other.unprotectedHeader) return false
        return true
    }

    override fun hashCode(): Int {
        var result = plainSignature.contentHashCode()
        result = 31 * result + plainProtectedHeader.contentHashCode()
        result = 31 * result + (unprotectedHeader?.hashCode() ?: 0)
        return result
    }
}
