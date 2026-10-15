package at.asitplus.signum.indispensable.cosef

import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.io.Base64Strict
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.cbor.CborEncoder
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonDecoder

/**
 * Serializes a [COSE] structure in the same wire forms as the deprecated [CoseBytesWireFormatSerializer]:
 * the CBOR array when encoding to CBOR, and the Base64 encoding of that array otherwise
 *
 * Keeps the JSON form of [CoseSign1] and [CoseMac0] identical to that of [CoseSigned] and [CoseMac], so values
 * persisted with the old types can be read with the new ones and vice versa.
 */
@OptIn(ExperimentalSerializationApi::class)
open class CoseWireSerializer<T : COSE>(
    generatedSerializer: () -> KSerializer<T>,
) : KSerializer<T> {

    private val generated: KSerializer<T> by lazy(generatedSerializer)

    override val descriptor: SerialDescriptor
        get() = generated.descriptor

    override fun serialize(encoder: Encoder, value: T) {
        if (encoder is CborEncoder) {
            encoder.encodeSerializableValue(generated, value)
        } else {
            val bytes = coseCompliantSerializer.encodeToByteArray(generated, value)
            encoder.encodeString(bytes.encodeToString(Base64Strict))
        }
    }

    override fun deserialize(decoder: Decoder): T =
        if (decoder is JsonDecoder) {
            val bytes = decoder.decodeString().decodeToByteArray(Base64())
            coseCompliantSerializer.decodeFromByteArray(generated, bytes)
        } else {
            decoder.decodeSerializableValue(generated)
        }
}

object CoseSign1Serializer : CoseWireSerializer<CoseSign1>({ CoseSign1.generatedSerializer() })

object CoseMac0Serializer : CoseWireSerializer<CoseMac0>({ CoseMac0.generatedSerializer() })