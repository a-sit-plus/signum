package at.asitplus.signum.indispensable.cosef

import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapperSerializer
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.io.Base64Strict
import at.asitplus.signum.indispensable.pki.X509Certificate
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

/**
 * Serializes [CoseSigned] with a typed payload, by using its [CoseSigned.wireFormat].
 * Also handles deserialization of the bytes.
 */
class CoseSignedSerializer<P : Any?>(
    private val parameterSerializer: KSerializer<P>,
) : KSerializer<CoseSigned<P>> {

    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("CoseSigned", PrimitiveKind.BYTE)

    override fun serialize(encoder: Encoder, value: CoseSigned<P>) {
        if (encoder is CborEncoder) {
            encoder.encodeSerializableValue(CoseSignedBytes.serializer(), value.wireFormat)
        } else {
            val bytes = coseCompliantSerializer.encodeToByteArray(value.wireFormat)
            encoder.encodeString(bytes.encodeToString(Base64Strict))
        }
    }

    override fun deserialize(decoder: Decoder): CoseSigned<P> {
        val wire = if (decoder is JsonDecoder) decoder.decodeString().decodeToByteArray(Base64()).let { bytes ->
            coseCompliantSerializer.decodeFromByteArray(CoseSignedBytes.serializer(), bytes)
        } else decoder.decodeSerializableValue(
            CoseSignedBytes.serializer()
        )
        val protectedHeader = wire.protectedHeader.toHeader()
        val signature = wire.rawSignature.toSignature(protectedHeader, wire.unprotectedHeader)
        return CoseSigned<P>(
            protectedHeader = protectedHeader,
            unprotectedHeader = wire.unprotectedHeader,
            payload = wire.payload.toNullablePayload(),
            signature = signature,
            wireFormat = wire
        )
    }

    private fun ByteArray.toHeader(): CoseHeader =
        coseCompliantSerializer.decodeFromByteArray(CoseHeader.serializer(), this)

    private fun ByteArray.toSignature(
        protectedHeader: CoseHeader,
        unprotectedHeader: CoseHeader?,
    ): CryptoSignature.RawByteEncodable =
        if (protectedHeader.usesEC() ?: unprotectedHeader?.usesEC() ?: (size < 2048))
            CryptoSignature.EC.fromRawBytes(this)
        else CryptoSignature.RSAorHMAC(this)

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
            // if it still fails, the input not valid
        }

    private fun ByteArray.fromBytes(): P =
        coseCompliantSerializer.decodeFromByteArray(parameterSerializer, this)

    private fun ByteArray.fromByteStringWrapper(): P =
        coseCompliantSerializer.decodeFromByteArray(ByteStringWrapperSerializer(parameterSerializer), this).value

}

private fun CoseHeader.usesEC(): Boolean? = algorithm?.algorithm?.let { it is SignatureAlgorithm.ECDSA }
    ?: certificateChain?.let { X509Certificate.decodeFromDerOrNull(it)?.publicKey is CryptoPublicKey.EC }
