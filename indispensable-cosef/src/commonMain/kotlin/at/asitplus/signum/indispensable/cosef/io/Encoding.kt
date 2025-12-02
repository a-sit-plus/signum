package at.asitplus.signum.indispensable.cosef.io

import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.base16.Base16ConfigBuilder
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.cbor.Cbor
import kotlinx.serialization.cbor.CborDecoder
import kotlinx.serialization.cbor.CborEncoder
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/**
 * CBOR Serializer, preconfigured with COSE-compliant settings.
 * Ignores unknown keys and always uses ByteString encoding.
 *
 *
 * **DOES NOT SORT KEYS!**
 */
@OptIn(ExperimentalSerializationApi::class)
val coseCompliantSerializer by lazy {
    Cbor(from = Cbor.CoseCompliant) {
        ignoreUnknownKeys = true
        alwaysUseByteString = true
    }
}


/**
 * Strict Base16 encoder
 */
val Base16Strict = Base16(config = Base16ConfigBuilder().apply {
    strict()
}.build())


/**
 * Use this class if you'll need to serialize a complex type as a byte string before encoding it,
 * i.e. as it is the case with the protected header in COSE structures.
 *
 * An example for a COSE header data class would be:
 *
 * ```
 * @Serializable
 * data class CoseHeader(
 *     @CborLabel(1)
 *     @SerialName("alg")
 *     val alg: Int? = null
 * )
 *
 * @Serializable
 * data class CoseSigned(
 *     @ByteString
 *     @CborLabel(1)
 *     @SerialName("protectedHeader")
 *     val protectedHeader: ByteStringWrapper<CoseHeader>,
 * )
 * ```
 *
 * Serializing this `CoseHeader` object would result in `a10143a10126`, in diagnostic notation:
 *
 * ```
 * A1           # map(1)
 *    01        # unsigned(1)
 *    43        # bytes(3)
 *       A10126 # "\xA1\u0001&"
 * ```
 *
 * so the `protectedHeader` got serialized first and then encoded as a `@ByteString`.
 *
 * Note that `equals()` and `hashCode()` only use `value`, not `serialized`.
 */
@Serializable(with = ByteStringWrapperSerializer::class)
class ByteStringWrapper<T>(
    val value: T,
    val serialized: ByteArray = byteArrayOf()
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as ByteStringWrapper<*>

        return value == other.value
    }

    override fun hashCode(): Int {
        return value?.hashCode() ?: 0
    }

    override fun toString(): String {
        return "ByteStringWrapper(value=$value, serialized=${serialized.contentToString()})"
    }
}

@OptIn(ExperimentalSerializationApi::class)
class ByteStringWrapperSerializer<T>(private val dataSerializer: KSerializer<T>) :
    KSerializer<ByteStringWrapper<T>> {

    override val descriptor: SerialDescriptor = dataSerializer.descriptor

    override fun serialize(encoder: Encoder, value: ByteStringWrapper<T>) {
        val bytes =
            (if (encoder is CborEncoder) encoder.cbor else coseCompliantSerializer)
                .encodeToByteArray(dataSerializer, value.value)
        encoder.encodeSerializableValue(ByteArraySerializer(), bytes)
    }

    override fun deserialize(decoder: Decoder): ByteStringWrapper<T> {
        val bytes = decoder.decodeSerializableValue(ByteArraySerializer())
        val value = (if (decoder is CborDecoder) decoder.cbor else coseCompliantSerializer)
            .decodeFromByteArray(dataSerializer, bytes)
        return ByteStringWrapper(value, bytes)
    }
}
