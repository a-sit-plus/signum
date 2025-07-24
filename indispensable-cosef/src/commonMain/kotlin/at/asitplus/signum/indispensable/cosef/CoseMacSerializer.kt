package at.asitplus.signum.indispensable.cosef

import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapperSerializer
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.io.Base64Strict
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.cbor.CborEncoder
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonDecoder

class CoseMacSerializer<P : Any?>(
    private val parameterSerializer: KSerializer<P>,
) : KSerializer<CoseMac<P>> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("CoseMac", PrimitiveKind.BYTE)

    override fun serialize(encoder: Encoder, value: CoseMac<P>) {
        if (encoder is CborEncoder) {
            encoder.encodeSerializableValue(CoseBytes.serializer(), value.wireFormat)
        } else {
            val bytes = coseCompliantSerializer.encodeToByteArray(value.wireFormat)
            encoder.encodeString(bytes.encodeToString(Base64Strict))
        }
    }

    override fun deserialize(decoder: Decoder): CoseMac<P> {
        val wire = if (decoder is JsonDecoder) decoder.decodeString().decodeToByteArray(Base64())
            .let { bytes ->
                coseCompliantSerializer.decodeFromByteArray(CoseBytes.serializer(), bytes)
            } else decoder.decodeSerializableValue(
            CoseBytes.serializer()
        )
        val protectedHeader = wire.protectedHeader.toHeader()
        val tag = wire.rawAuthBytes
        return CoseMac<P>(
            protectedHeader = protectedHeader,
            unprotectedHeader = wire.unprotectedHeader,
            payload = wire.payload.toNullablePayload(),
            tag = tag,
            wireFormat = wire
        )
    }

    private fun ByteArray?.toNullablePayload(): P? = when (this) {
        null -> null
        else -> if (this.isEmpty()) null else toTypedPayload()
    }

    private fun ByteArray.toTypedPayload(): P =
        if (parameterSerializer == ByteArraySerializer()) {
            @Suppress("UNCHECKED_CAST")
            (this as P)
        } else {
            runCatching { fromBytes() }
                .getOrElse { fromByteStringWrapper() }
            // if it still fails, the input is not valid
        }

    private fun ByteArray.fromBytes(): P =
        coseCompliantSerializer.decodeFromByteArray(parameterSerializer, this)

    private fun ByteArray.fromByteStringWrapper(): P =
        coseCompliantSerializer.decodeFromByteArray(ByteStringWrapperSerializer(parameterSerializer), this).value

    private fun ByteArray.toHeader(): CoseHeader =
        coseCompliantSerializer.decodeFromByteArray(CoseHeader.serializer(), this)
}