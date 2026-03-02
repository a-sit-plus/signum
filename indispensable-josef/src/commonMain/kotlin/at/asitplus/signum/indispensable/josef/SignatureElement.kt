package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.CryptoSignature
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient


/**
 * Signature element as defined in [RFC 7515 Sec 7.2.1](https://www.rfc-editor.org/rfc/rfc7515.html#section-7.2.1)
 *
 * DOES NOT IMPLEMENT UNPROTECTED HEADERS!
 * Will only be implemented when use-case arises as this significantly
 * impacts JWS data class representation and verification
 * (The header in JWS is the union of protected and unprotected header elements)
 */
@Serializable(with = SignatureElementSerializer::class)
data class SignatureElement(
    /**
     * The [protectedHeader] member MUST be present ...when the JWS Protected
     * Header value is non-empty; otherwise, it MUST be absent.  These
     * Header Parameter values are integrity protected.
     *
     * Serialization: BASE64URL(UTF8(JWS Protected Header))
     */
    @SerialName("protected")
    @Serializable(with = JwsProtectedHeaderSerializer::class)
    val protectedHeader: JwsHeader,

    /**
     * The [signature] member MUST be present
     *
     * Serialization: BASE64URL(JWS Signature).
     */
    val signature: CryptoSignature.RawByteEncodable,

    /**
     * ASCII string `<BASE64URL(protected)>.<BASE64URL(payload)>` as used for signature verification.
     */
    @Transient
    val plainSignatureInput: ByteArray = byteArrayOf(),
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as SignatureElement

        if (protectedHeader != other.protectedHeader) return false
        if (signature != other.signature) return false

        return true
    }

    override fun hashCode(): Int {
        var result = protectedHeader.hashCode()
        result = 31 * result + signature.hashCode()
        return result
    }
}
