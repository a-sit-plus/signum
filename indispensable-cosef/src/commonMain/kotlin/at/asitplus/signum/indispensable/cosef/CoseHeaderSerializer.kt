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

    override fun serialize(encoder: Encoder, value: List<ByteArray>) =
        encoder.encodeSerializableValue(
            CborElement.serializer(),
            if (value.size == 1) CborByteString(value.single())
            else CborArray(value.map { CborByteString(it) }),
        )

    // decodeSerializableValue instead of CborDecoder.decodeCborElement(): when decoding from a CborElement tree,
    // the latter returns the map key instead of the value
    override fun deserialize(decoder: Decoder): List<ByteArray> =
        when (val element = decoder.decodeSerializableValue(CborElement.serializer())) {
            is CborByteString -> listOf(element.toByteArray())
            is CborArray -> element.map {
                (it as? CborByteString)?.toByteArray()
                    ?: throw SerializationException("x5chain must contain byte strings only")
            }
            else -> throw SerializationException(
                "x5chain must be a byte string or an array of byte strings, was ${element::class.simpleName}"
            )
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