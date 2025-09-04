package at.asitplus.signum.indispensable.cosef

import at.asitplus.catching
import at.asitplus.signum.indispensable.cosef.io.Base16Strict
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.CborArray
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

@Serializable
@CborArray
data class CoseInput(
    val contextString: String,
    @Serializable(with = ProtectedCoseHeaderSerializer::class)
    val protectedHeader: CoseHeader,
    @ByteString
    val externalAad: ByteArray,
    @ByteString
    val payload: ByteArray?,
) {
    
    @Deprecated("To be removed in next release")
    fun serialize() = coseCompliantSerializer.encodeToByteArray(this)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as CoseInput

        if (contextString != other.contextString) return false
        if (protectedHeader != other.protectedHeader) return false
        if (!externalAad.contentEquals(other.externalAad)) return false
        if (payload != null) {
            if (other.payload == null) return false
            if (!payload.contentEquals(other.payload)) return false
        } else if (other.payload != null) return false

        return true
    }

    override fun hashCode(): Int {
        var result = contextString.hashCode()
        result = 31 * result + protectedHeader.hashCode()
        result = 31 * result + externalAad.contentHashCode()
        result = 31 * result + (payload?.contentHashCode() ?: 0)
        return result
    }

    override fun toString(): String {
        return "CoseSignatureInput(contextString='$contextString'," +
                " protectedHeader=$protectedHeader," +
                " externalAad=${externalAad.encodeToString(Base16Strict)}," +
                " payload=${payload?.encodeToString(Base16Strict)})"
    }


    companion object {
        fun deserialize(it: ByteArray) = catching {
            coseCompliantSerializer.decodeFromByteArray<CoseInput>(it)
        }
    }
}
