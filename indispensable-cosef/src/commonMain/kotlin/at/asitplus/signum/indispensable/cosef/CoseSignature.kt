package at.asitplus.signum.indispensable.cosef

import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.cosef.io.Base16Strict
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.CborArray

/**
 * One signer entry of a `COSE_Sign`. See (https://www.rfc-editor.org/rfc/rfc9052.html#section-4.1).
 */
@ConsistentCopyVisibility
@Serializable
@CborArray
data class CoseSignature internal constructor(
    @ByteString
    val plainProtectedHeader: ByteArray,

    val unprotectedHeader: CoseHeader?,

    @ByteString
    val plainSignature: ByteArray,
) {

    /** Typed view of [plainProtectedHeader]. */
    @Transient
    val protectedHeader: CoseHeader = COSE.decodeProtectedHeader(plainProtectedHeader)

    @Transient
    val signature: CryptoSignature =
        COSE.getSignature(plainSignature, protectedHeader, unprotectedHeader)

    /**
     * The five-element `Sig_structure` this signer's [signature] is computed over.
     */
    fun signatureInput(
        bodyProtectedHeader: ByteArray,
        externalAad: ByteArray = byteArrayOf(),
        payload: ByteArray,
    ): ByteArray = COSE.signerStructureInput(
        bodyProtectedHeader = bodyProtectedHeader,
        signProtectedHeader = plainProtectedHeader,
        externalAad = externalAad,
        payload = payload,
    )

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as CoseSignature

        if (!plainProtectedHeader.contentEquals(other.plainProtectedHeader)) return false
        if (unprotectedHeader != other.unprotectedHeader) return false
        if (!plainSignature.contentEquals(other.plainSignature)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = plainProtectedHeader.contentHashCode()
        result = 31 * result + (unprotectedHeader?.hashCode() ?: 0)
        result = 31 * result + plainSignature.contentHashCode()
        return result
    }

    override fun toString(): String = "CoseSignature(" +
            "protectedHeader=$protectedHeader, " +
            "unprotectedHeader=$unprotectedHeader, " +
            "signature=${plainSignature.encodeToString(Base16Strict)})"

}