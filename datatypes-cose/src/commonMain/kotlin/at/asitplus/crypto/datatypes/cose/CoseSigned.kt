package at.asitplus.crypto.datatypes.cose

import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.CryptoSignature
import at.asitplus.crypto.datatypes.cose.io.cborSerializer
import at.asitplus.crypto.datatypes.pki.X509Certificate
import io.github.aakira.napier.Napier
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.*
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.ByteStringWrapper
import kotlinx.serialization.cbor.CborArray
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/**
 * Representation of a signed COSE_Sign1 object, i.e. consisting of protected header, unprotected header and payload.
 */
@OptIn(ExperimentalSerializationApi::class)
@Serializable
@CborArray
data class CoseSigned(
    @Serializable(with = ByteStringWrapperCoseHeaderSerializer::class)
    @ByteString
    val protectedHeader: ByteStringWrapper<CoseHeader>,
    val unprotectedHeader: CoseHeader?,
    @ByteString
    val payload: ByteArray?,
    @ByteString
    @SerialName("signature")
    private val rawSignature: ByteArray
) {

    constructor(
        protectedHeader: ByteStringWrapper<CoseHeader>,
        unprotectedHeader: CoseHeader?,
        payload: ByteArray?,
        signature: CryptoSignature
    ) : this(protectedHeader, unprotectedHeader, payload, signature.rawByteArray)

    val signature: CryptoSignature by lazy {
        if (protectedHeader.value.usesEC() ?: unprotectedHeader?.usesEC() ?: (rawSignature.size < 2048))
            CryptoSignature.EC(rawSignature)
        else CryptoSignature.RSAorHMAC(rawSignature)
    }

    fun serialize() = cborSerializer.encodeToByteArray(this)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as CoseSigned

        if (protectedHeader != other.protectedHeader) return false
        if (unprotectedHeader != other.unprotectedHeader) return false
        if (payload != null) {
            if (other.payload == null) return false
            if (!payload.contentEquals(other.payload)) return false
        } else if (other.payload != null) return false
        return rawSignature != other.rawSignature
    }

    override fun hashCode(): Int {
        var result = protectedHeader.hashCode()
        result = 31 * result + (unprotectedHeader?.hashCode() ?: 0)
        result = 31 * result + (payload?.contentHashCode() ?: 0)
        result = 31 * result + rawSignature.contentHashCode()
        return result
    }

    override fun toString(): String {
        return "CoseSigned(protectedHeader=${protectedHeader.value}," +
                " unprotectedHeader=$unprotectedHeader," +
                " payload=${payload?.encodeToString(Base16(strict = true))}," +
                " signature=${rawSignature.encodeToString(Base16(strict = true))})"
    }

    companion object {
        fun deserialize(it: ByteArray) = kotlin.runCatching {
            cborSerializer.decodeFromByteArray<CoseSigned>(it)
        }.getOrElse {
            Napier.w("deserialize failed", it)
            null
        }
    }
}

fun CoseHeader.usesEC(): Boolean? {
    algorithm?.isEC?.let { return it }
    certificateChain?.let { return X509Certificate.decodeFromDerOrNull(it)?.publicKey is CryptoPublicKey.Ec }
    return null
}

@OptIn(ExperimentalSerializationApi::class)
@Serializable
@CborArray
data class CoseSignatureInput(
    val contextString: String = "Signature1",
    @Serializable(with = ByteStringWrapperCoseHeaderSerializer::class)
    @ByteString
    val protectedHeader: ByteStringWrapper<CoseHeader>,
    @ByteString
    val externalAad: ByteArray,
    @ByteString
    val payload: ByteArray?,
) {
    fun serialize() = cborSerializer.encodeToByteArray(this)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as CoseSignatureInput

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
                " protectedHeader=${protectedHeader.value}," +
                " externalAad=${externalAad.encodeToString(Base16(strict = true))}," +
                " payload=${payload?.encodeToString(Base16(strict = true))})"
    }


    companion object {
        fun deserialize(it: ByteArray) = kotlin.runCatching {
            cborSerializer.decodeFromByteArray<CoseSignatureInput>(it)
        }.getOrElse {
            Napier.w("deserialize failed", it)
            null
        }
    }
}

object ByteStringWrapperCoseHeaderSerializer : KSerializer<ByteStringWrapper<CoseHeader>> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("ByteStringWrapperCoseHeaderSerializer", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: ByteStringWrapper<CoseHeader>) {
        val bytes = cborSerializer.encodeToByteArray(value.value)
        encoder.encodeSerializableValue(ByteArraySerializer(), bytes)
    }

    override fun deserialize(decoder: Decoder): ByteStringWrapper<CoseHeader> {
        val bytes = decoder.decodeSerializableValue(ByteArraySerializer())
        return ByteStringWrapper(cborSerializer.decodeFromByteArray(bytes), bytes)
    }

}
