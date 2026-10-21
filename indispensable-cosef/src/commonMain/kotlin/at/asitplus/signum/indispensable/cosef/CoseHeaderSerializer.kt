package at.asitplus.signum.indispensable.cosef

import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.cbor.CborArray
import kotlinx.serialization.cbor.CborByteString
import kotlinx.serialization.cbor.CborDecoder
import kotlinx.serialization.cbor.CborElement
import kotlinx.serialization.cbor.CborEncoder
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.serializer

/** `x5chain` (RFC 9360): one certificate as a byte string, several as an array of byte strings. */
@OptIn(ExperimentalSerializationApi::class)
internal object X5ChainSerializer : KSerializer<List<ByteArray>> {

    override val descriptor: SerialDescriptor =
        SerialDescriptor("at.asitplus.signum.indispensable.cosef.X5Chain", serializer<CborElement>().descriptor)

    override fun serialize(encoder: Encoder, value: List<ByteArray>) {
        val cborEncoder = encoder as? CborEncoder
            ?: throw SerializationException("x5chain can only be encoded to CBOR")
        cborEncoder.encodeCborElement(
            if (value.size == 1) CborByteString(value.single())
            else CborArray(value.map { CborByteString(it) })
        )
    }

    override fun deserialize(decoder: Decoder): List<ByteArray> {
        val cborDecoder = decoder as? CborDecoder
            ?: throw SerializationException("x5chain can only be decoded from CBOR")
        return when (val element = cborDecoder.decodeCborElement()) {
            is CborByteString -> listOf(element.toByteArray())
            is CborArray -> element.map {
                (it as? CborByteString)?.toByteArray()
                    ?: throw SerializationException("x5chain must contain byte strings only")
            }
            else -> throw SerializationException("x5chain must be a byte string or an array of byte strings")
        }
    }
}

@Deprecated("CoseHeader uses its generated serializer", ReplaceWith("CoseHeader.serializer()"))
object CoseHeaderSerializer : KSerializer<CoseHeader> by CoseHeader.serializer()

@OptIn(ExperimentalSerializationApi::class)
object ProtectedCoseHeaderSerializer : KSerializer<CoseHeader> {
    override val descriptor: SerialDescriptor = buildClassSerialDescriptor("ProtectedHeader")

    override fun serialize(encoder: Encoder, value: CoseHeader) {
        val headerBytes = coseCompliantSerializer.encodeToByteArray(CoseHeader.serializer(), value)
        // Empty map (0xA0) → h'' (zero-length bstr)
        val wrapped = if (headerBytes.size == 1 && headerBytes[0] == 0xA0.toByte()) {
            byteArrayOf()
        } else {
            headerBytes
        }

        encoder.encodeSerializableValue(ByteArraySerializer(), wrapped)
    }

    override fun deserialize(decoder: Decoder): CoseHeader {
        val raw = decoder.decodeSerializableValue(ByteArraySerializer())
        return if (raw.isEmpty()) {
            CoseHeader()
        } else {
            coseCompliantSerializer.decodeFromByteArray(CoseHeader.serializer(), raw)
        }
    }
}