package at.asitplus.signum.indispensable.cosef

import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
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
            encoder.encodeSerializableValue(CoseBytes.serializer(), value.wireFormat)
        } else {
            val bytes = coseCompliantSerializer.encodeToByteArray(value.wireFormat)
            encoder.encodeString(bytes.encodeToString(Base64Strict))
        }
    }

    override fun deserialize(decoder: Decoder): CoseSigned<P> {
        val wire = if (decoder is JsonDecoder) decoder.decodeString().decodeToByteArray(Base64()).let { bytes ->
            coseCompliantSerializer.decodeFromByteArray(CoseBytes.serializer(), bytes)
        } else decoder.decodeSerializableValue(
            CoseBytes.serializer()
        )
        val protectedHeader = wire.protectedHeader.toHeader()
        val signature = wire.rawAuthBytes.toSignature(protectedHeader, wire.unprotectedHeader)
        return CoseSigned(
            protectedHeader = protectedHeader,
            unprotectedHeader = wire.unprotectedHeader,
            payload = wire.payload.toNullablePayload(parameterSerializer),
            signature = signature,
            wireFormat = wire
        )
    }
}

/**
 * Serializes [CoseMac] with a typed payload, by using its [CoseMac.wireFormat].
 * Also handles deserialization of the bytes.
 */
class CoseMacSerializer<P : Any?>(
    private val parameterSerializer: KSerializer<P>,
) : KSerializer<CoseMac<P>> {

    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("CoseMac", PrimitiveKind.BYTE)

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
        return CoseMac(
            protectedHeader = protectedHeader,
            unprotectedHeader = wire.unprotectedHeader,
            payload = wire.payload.toNullablePayload(parameterSerializer),
            tag = tag,
            wireFormat = wire
        )
    }
}

private fun <P : Any?> ByteArray?.toNullablePayload(serializer: KSerializer<P>): P? = when {
    this == null || this.isEmpty() -> null
    else -> toTypedPayload(serializer)
}

private fun ByteArray.toSignature(
    protectedHeader: CoseHeader,
    unprotectedHeader: CoseHeader?,
): CryptoSignature.RawByteEncodable =
    if (protectedHeader.usesEC() ?: unprotectedHeader?.usesEC() ?: (size < 2048))
        CryptoSignature.EC.fromRawBytes(this)
    else CryptoSignature.RSA(this)

private fun <P : Any?> ByteArray.toTypedPayload(serializer: KSerializer<P>): P =
    if (serializer == ByteArraySerializer()) {
        @Suppress("UNCHECKED_CAST")
        (this as P)
    } else {
        runCatching { fromBytes(serializer) }
            .getOrElse { fromByteStringWrapper(serializer) }
    }

private fun <P : Any?> ByteArray.fromBytes(serializer: KSerializer<P>): P =
    coseCompliantSerializer.decodeFromByteArray(serializer, this)

private fun <P : Any?> ByteArray.fromByteStringWrapper(serializer: KSerializer<P>): P =
    coseCompliantSerializer.decodeFromByteArray(
        ByteStringWrapperSerializer(serializer),
        this
    ).value

fun ByteArray.toHeader(): CoseHeader =
    coseCompliantSerializer.decodeFromByteArray(CoseHeader.serializer(), this)

private fun CoseHeader.usesEC(): Boolean? = when (algorithm) {
    null -> certificateChain?.firstOrNull()
        ?.let { X509Certificate.decodeFromDerOrNull(it) }
        ?.let { it.signatureAlgorithm is X509SignatureAlgorithm.ECDSA }
    is CoseAlgorithm.Signature -> (algorithm.algorithm is SignatureAlgorithm.ECDSA)
    else -> false
}


