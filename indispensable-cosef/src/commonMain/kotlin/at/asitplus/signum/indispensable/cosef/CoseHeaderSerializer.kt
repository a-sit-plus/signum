package at.asitplus.signum.indispensable.cosef

import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/** RFC 9360: one certificate as a byte string, a chain as an array of byte strings. */
object X5ChainSerializer : KSerializer<List<ByteArray>> {
    private val chain = ListSerializer(ByteArraySerializer())
    override val descriptor: SerialDescriptor = chain.descriptor

    override fun serialize(encoder: Encoder, value: List<ByteArray>) {
        require(value.isNotEmpty()) { "x5chain must not be empty" }
        if (value.size == 1) encoder.encodeSerializableValue(ByteArraySerializer(), value.single())
        else encoder.encodeSerializableValue(chain, value)
    }

    // Depends on upstream CBOR checking the major type before consuming input; tested with following fields.
    override fun deserialize(decoder: Decoder): List<ByteArray> =
        try {
            decoder.decodeSerializableValue(chain)
        } catch (_: SerializationException) {
            listOf(decoder.decodeSerializableValue(ByteArraySerializer()))
        }.also { require(it.isNotEmpty()) { "x5chain must not be empty" } }
}

/** Reusable property serializer; crit is a nonempty array of integer/text labels. */
object CriticalHeadersSerializer : KSerializer<List<CoseHeaderLabel>> {
    private val labels = ListSerializer(CoseHeaderLabel.serializer())
    override val descriptor: SerialDescriptor = labels.descriptor
    override fun serialize(encoder: Encoder, value: List<CoseHeaderLabel>) {
        require(value.isNotEmpty()) { "crit must not be empty" }
        encoder.encodeSerializableValue(labels, value)
    }
    override fun deserialize(decoder: Decoder): List<CoseHeaderLabel> =
        decoder.decodeSerializableValue(labels).also { require(it.isNotEmpty()) { "crit must not be empty" } }
}
