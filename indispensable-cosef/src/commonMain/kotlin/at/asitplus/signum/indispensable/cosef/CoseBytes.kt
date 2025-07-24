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
@ConsistentCopyVisibility
data class CoseBytes internal constructor(
    @ByteString
    val protectedHeader: ByteArray,
    val unprotectedHeader: CoseHeader?,
    @ByteString
    val payload: ByteArray?,
    @ByteString
    val rawAuthBytes: ByteArray,
) {
    /**
     * @param detachedPayload only to be set when [payload] is null, i.e. it is transported externally,
     * as it ignores the [payload] member
     */
    internal fun toCoseSignatureInput(
        externalAad: ByteArray = byteArrayOf(),
        detachedPayload: ByteArray? = null,
    ): ByteArray = toCoseInput(externalAad, detachedPayload, "Signature1")

    internal fun toCoseMacInput(
        externalAad: ByteArray = byteArrayOf(),
        detachedPayload: ByteArray? = null,
    ): ByteArray = toCoseInput(externalAad, detachedPayload, "MAC0")

    private fun toCoseInput(
        externalAad: ByteArray = byteArrayOf(),
        detachedPayload: ByteArray? = null,
        contextString: String
    ): ByteArray = CoseInput(
        contextString = contextString,
        protectedHeader = protectedHeader.toZeroLengthByteString(),
        externalAad = externalAad,
        payload = if (detachedPayload != null) {
            require(payload == null)
            detachedPayload
        } else payload,
    ).run {
        coseCompliantSerializer.encodeToByteArray(this)
    }

    @Deprecated("To be removed in next release")
    fun serialize(): ByteArray = coseCompliantSerializer.encodeToByteArray(this)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as CoseBytes

        if (!protectedHeader.contentEquals(other.protectedHeader)) return false
        if (unprotectedHeader != other.unprotectedHeader) return false
        if (!payload.contentEquals(other.payload)) return false
        if (!rawAuthBytes.contentEquals(other.rawAuthBytes)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = protectedHeader.contentHashCode()
        result = 31 * result + (unprotectedHeader?.hashCode() ?: 0)
        result = 31 * result + (payload?.contentHashCode() ?: 0)
        result = 31 * result + rawAuthBytes.contentHashCode()
        return result
    }

    override fun toString(): String {
        return "CoseSigned(protectedHeader=${protectedHeader.encodeToString(Base16Strict)}," +
                " unprotectedHeader=$unprotectedHeader," +
                " payload=${payload?.encodeToString(Base16Strict)}," +
                " signature=${rawAuthBytes.encodeToString(Base16Strict)})"
    }

    companion object {

        @Deprecated("To be removed in next release")
        fun deserialize(it: ByteArray): KmmResult<CoseBytes> = catching {
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
