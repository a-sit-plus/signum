package at.asitplus.signum.indispensable.cosef

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.cosef.io.Base16Strict
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.CborArray
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

/**
 * Representation of a signed `COSE_Sign1` object, i.e. consisting of protected header, unprotected header and payload.
 * It represents the bytes of the object as it has been transferred, i.e. useful for signature verification.
 *
 * For the class using typed payloads, see [CoseSigned].
 *
 * See [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html).
 */
@Serializable
@CborArray
data class CoseSignedBytes(
    @ByteString
    val protectedHeader: ByteArray,
    val unprotectedHeader: CoseHeader?,
    @ByteString
    val payload: ByteArray?,
    @ByteString
    val rawSignature: ByteArray,
) {
    fun toCoseSignatureInput(
        externalAad: ByteArray = byteArrayOf(),
        detachedPayload: ByteArray? = null,
    ): ByteArray = CoseSignatureInput(
        contextString = "Signature1",
        protectedHeader = protectedHeader.toZeroLengthByteString(),
        externalAad = externalAad,
        payload = payload ?: detachedPayload,
    ).serialize()

    fun serialize(): ByteArray = coseCompliantSerializer.encodeToByteArray(this)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as CoseSignedBytes

        if (!protectedHeader.contentEquals(other.protectedHeader)) return false
        if (unprotectedHeader != other.unprotectedHeader) return false
        if (!payload.contentEquals(other.payload)) return false
        if (!rawSignature.contentEquals(other.rawSignature)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = protectedHeader.contentHashCode()
        result = 31 * result + (unprotectedHeader?.hashCode() ?: 0)
        result = 31 * result + (payload?.contentHashCode() ?: 0)
        result = 31 * result + rawSignature.contentHashCode()
        return result
    }

    override fun toString(): String {
        return "CoseSigned(protectedHeader=${protectedHeader.encodeToString(Base16Strict)}," +
                " unprotectedHeader=$unprotectedHeader," +
                " payload=${payload?.encodeToString(Base16Strict)}," +
                " signature=${rawSignature.encodeToString(Base16Strict)})"
    }

    companion object {
        fun deserialize(it: ByteArray): KmmResult<CoseSignedBytes> = catching {
            coseCompliantSerializer.decodeFromByteArray(it)
        }
    }
}

/**
 * The protected attributes from the body structure, encoded in a
 * bstr type.  If there are no protected attributes, a zero-length
 * byte string is used.
 *
 *  [RFC 9052 4.4](https://datatracker.ietf.org/doc/html/rfc9052#section-4.4)
 */
private fun ByteArray.toZeroLengthByteString(): ByteArray = when {
    // "A0"
    this.size == 1 && this[0] == 160.toByte() -> byteArrayOf()
    else -> this
}
