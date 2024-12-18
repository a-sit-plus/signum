package at.asitplus.signum.indispensable.cosef

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.contentEqualsIfArray
import at.asitplus.signum.indispensable.contentHashCodeIfArray
import at.asitplus.signum.indispensable.cosef.CoseSigned.Companion.create
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapperSerializer
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToByteArray
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToByteArray

/**
 * Representation of a signed COSE_Sign1 object, i.e. consisting of protected header, unprotected header and payload.
 *
 * If the payload is a generic [ByteArray], then it will be serialized as-is. Should the payload be any other type,
 * we will tag it with 24 (see
 * [RFC8949 3.4.5.1](https://www.rfc-editor.org/rfc/rfc8949.html#name-encoded-cbor-data-item)) for serialization.
 * In order to prevent nested wrapping of the payload and the resulting type erasure
 * payloads of type [ByteStringWrapper] will be rejected.
 * In this case the payload could be handed over as the wrapped class itself or manually serialized to [ByteArray]
 *
 * See [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html).
 */
@OptIn(ExperimentalSerializationApi::class)
@Serializable(with = CoseSignedSerializer::class)
@ConsistentCopyVisibility
data class CoseSigned<P : Any?> internal constructor(
    val protectedHeader: CoseHeader,
    val unprotectedHeader: CoseHeader? = null,
    val payload: P?,
    val signature: CryptoSignature.RawByteEncodable,
    val wireFormat: CoseSignedBytes,
) {

    fun prepareCoseSignatureInput(externalAad: ByteArray = byteArrayOf()): ByteArray =
        wireFormat.toCoseSignatureInput(externalAad)

    fun serialize(parameterSerializer: KSerializer<P>): ByteArray = coseCompliantSerializer
        .encodeToByteArray(CoseSignedSerializer(parameterSerializer), this)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as CoseSigned<*>

        if (protectedHeader != other.protectedHeader) return false
        if (unprotectedHeader != other.unprotectedHeader) return false
        if (payload != null) {
            if (other.payload == null) return false
            if (!payload.contentEqualsIfArray(other.payload)) return false
        } else if (other.payload != null) return false
        if (signature != other.signature) return false
        if (wireFormat != other.wireFormat) return false

        return true
    }

    override fun hashCode(): Int {
        var result = protectedHeader.hashCode()
        result = 31 * result + (unprotectedHeader?.hashCode() ?: 0)
        result = 31 * result + (payload?.contentHashCodeIfArray() ?: 0)
        result = 31 * result + signature.hashCode()
        result = 31 * result + wireFormat.hashCode()
        return result
    }

    override fun toString(): String {
        return "CoseSigned(protectedHeader=$protectedHeader," +
                " unprotectedHeader=$unprotectedHeader," +
                " payload=${if (payload is ByteArray) payload.encodeToByteArray(Base16()) else payload}," +
                " signature=$signature," +
                " wireFormat=$wireFormat)"
    }

    companion object {
        fun <P : Any> deserialize(parameterSerializer: KSerializer<P>, it: ByteArray): KmmResult<CoseSigned<P>> =
            catching {
                coseCompliantSerializer.decodeFromByteArray(CoseSignedSerializer(parameterSerializer), it)
            }

        /**
         * Use this method to create a new [CoseSigned] object with correct [CoseSigned.wireFormat] set.
         */
        @Throws(IllegalArgumentException::class)
        fun <P : Any> create(
            protectedHeader: CoseHeader,
            unprotectedHeader: CoseHeader? = null,
            payload: P?,
            signature: CryptoSignature.RawByteEncodable,
            payloadSerializer: KSerializer<P>,
        ): CoseSigned<P> = CoseSigned<P>(
            protectedHeader = protectedHeader,
            unprotectedHeader = unprotectedHeader,
            payload = payload,
            signature = signature,
            wireFormat = CoseSignedBytes(
                protectedHeader = coseCompliantSerializer.encodeToByteArray(protectedHeader),
                unprotectedHeader = unprotectedHeader,
                payload = payload.toRawPayload(payloadSerializer),
                rawSignature = signature.rawByteArray
            ),
        )

        /**
         * Use this method to prepare a [CoseSignatureInput] object to calculate the signature,
         * and then call [create] to create a [CoseSigned] object.
         */
        @Throws(IllegalArgumentException::class)
        fun <P : Any> prepare(
            protectedHeader: CoseHeader,
            externalAad: ByteArray = byteArrayOf(),
            payload: P?,
            payloadSerializer: KSerializer<P>,
        ): CoseSignatureInput = CoseSignatureInput(
            contextString = "Signature1",
            protectedHeader = coseCompliantSerializer.encodeToByteArray<CoseHeader>(protectedHeader),
            externalAad = externalAad,
            payload = payload.toRawPayload(payloadSerializer),
        )

        /**
         * If [this] is a [ByteArray], use it as is, otherwise encode it as a [ByteStringWrapper], with CBOR tag 24
         */
        private fun <P : Any> P?.toRawPayload(payloadSerializer: KSerializer<P>): ByteArray = when (this) {
            is ByteArray -> this
            is Nothing -> byteArrayOf()
            is ByteStringWrapper<*> -> throw IllegalArgumentException("Payload must not be a ByteStringWrapper")
            is P -> coseCompliantSerializer.encodeToByteArray<ByteStringWrapper<P>>(
                ByteStringWrapperSerializer(payloadSerializer),
                ByteStringWrapper(this)
            ).wrapInCborTag(24)

            else -> byteArrayOf()
        }

        private fun ByteArray.wrapInCborTag(tag: Byte) = byteArrayOf(0xd8.toByte()) + byteArrayOf(tag) + this

    }
}


