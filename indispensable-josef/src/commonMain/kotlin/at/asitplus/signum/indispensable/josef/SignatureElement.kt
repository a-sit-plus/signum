package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlNoPaddingSerializer
import at.asitplus.signum.indispensable.josef.JWS.Companion.getSignature
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient

/**
 * One signature entry of general JSON JWS serialization.
 *
 * A [SignatureElement] contains the signature bytes plus the header fragments for that signature. The protected
 * fragment is stored as encoded bytes in [plainProtectedHeader], while the optional unprotected fragment is
 * represented as [JwsHeader.Part]. The effective [jwsHeader] is reconstructed by merging both fragments.
 *
 * Either header fragment may be partial. Only the combination of protected and unprotected parameters must
 * constitute a valid [JwsHeader].
 *
 * See [RFC 7515 Sec 7.2.1](https://www.rfc-editor.org/rfc/rfc7515.html#section-7.2.1).
 */
@ConsistentCopyVisibility
@Serializable
data class SignatureElement internal constructor(
    /**
     * The [plainSignature] member MUST be present
     *
     * Serialization: BASE64URL(JWS Signature).
     */
    @SerialName(JWS.SerialNames.SIGNATURE)
    @Serializable(ByteArrayBase64UrlNoPaddingSerializer::class)
    val plainSignature: ByteArray,

    /**
     * The [plainProtectedHeader] member MUST be present ...when the JWS Protected
     * Header value is non-empty; otherwise, it MUST be absent.  These
     * Header Parameter values are integrity protected.
     *
     * Serialization: BASE64URL(UTF8(JWS Protected Header))
     */
    @SerialName(JWS.SerialNames.PROTECTED)
    @Serializable(with = ByteArrayBase64UrlNoPaddingSerializer::class)
    val plainProtectedHeader: ByteArray? = null,

    @SerialName(JWS.SerialNames.HEADER)
    val unprotectedHeader: JwsHeader.Part? = null
) {
    init {
        JwsProtectedHeaderSerializer.requireAbsentIfEmpty(plainProtectedHeader)
    }
    @Transient
    val jwsHeader: JwsHeader = JwsHeader.fromParts(protectedHeader, unprotectedHeader)
    @Transient
    val signature = getSignature(jwsHeader.algorithm, plainSignature)

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

val SignatureElement.protectedHeader: JwsHeader.Part?
    get() = plainProtectedHeader?.let(JwsProtectedHeaderSerializer::decodeFromByteArray)
