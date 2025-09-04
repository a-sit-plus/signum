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
 * Representation of a signed `COSE_Sign1/COSE_MAC0` object, i.e. consisting of protected header, unprotected header and payload.
 * It represents the bytes of the object as it has been transferred, i.e. useful for signature/hmac verification.
 *
 * For the class using typed payloads, see [CoseSigned] and [CoseMac].
 *
 * See [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html).
 */
@Serializable
@CborArray
@ConsistentCopyVisibility
data class CoseBytes internal constructor(
    @Serializable(with = ProtectedCoseHeaderSerializer::class)
    val protectedHeader: CoseHeader,
    val unprotectedHeader: CoseHeader?,
    @ByteString
    val payload: ByteArray?,
    @ByteString
    val rawAuthBytes: ByteArray,
) {

    internal fun toCoseSignatureInput(
        externalAad: ByteArray = byteArrayOf(),
        detachedPayload: ByteArray? = null,
    ): ByteArray = toCoseInput(externalAad, detachedPayload, "Signature1")

    internal fun toCoseMacInput(
        externalAad: ByteArray = byteArrayOf(),
        detachedPayload: ByteArray? = null,
    ): ByteArray = toCoseInput(externalAad, detachedPayload, "MAC0")

    /**
     * @param detachedPayload only to be set when [payload] is null, i.e. it is transported externally,
     * as it ignores the [payload] member
     */
    private fun toCoseInput(
        externalAad: ByteArray = byteArrayOf(),
        detachedPayload: ByteArray? = null,
        contextString: String
    ): ByteArray = CoseInput(
        contextString = contextString,
        protectedHeader = protectedHeader,
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

        if (protectedHeader != other.protectedHeader) return false
        if (unprotectedHeader != other.unprotectedHeader) return false
        if (!payload.contentEquals(other.payload)) return false
        if (!rawAuthBytes.contentEquals(other.rawAuthBytes)) return false

        return true
    }

    override fun hashCode(): Int {
        return this::class.hashCode()
    }

    override fun toString(): String {
        return "CoseSigned(protectedHeader=$protectedHeader," +
                " unprotectedHeader=$unprotectedHeader," +
                " payload=${payload?.encodeToString(Base16Strict)}," +
                " authBytes=${rawAuthBytes.encodeToString(Base16Strict)})"
    }

    companion object {

        @Deprecated("To be removed in next release")
        fun deserialize(it: ByteArray): KmmResult<CoseBytes> = catching {
            coseCompliantSerializer.decodeFromByteArray(it)
        }
    }
}
