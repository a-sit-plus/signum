package at.asitplus.signum.indispensable.cosef

import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.cosef.io.Base16Strict
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.pki.X509Certificate
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.CborArray
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/**
 * Representation of a signed COSE_Sign1 object, i.e. consisting of protected header, unprotected header and payload.
 *
 * See [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html).
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
        signature: CryptoSignature.RawByteEncodable
    ) : this(protectedHeader, unprotectedHeader, payload, signature.rawByteArray)

    val signature: CryptoSignature by lazy {
        if (protectedHeader.value.usesEC() ?: unprotectedHeader?.usesEC() ?: (rawSignature.size < 2048))
            CryptoSignature.EC.fromRawBytes(rawSignature)
        else CryptoSignature.RSAorHMAC(rawSignature)
    }

    fun serialize() = coseCompliantSerializer.encodeToByteArray(this)

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
        return !rawSignature.contentEquals(other.rawSignature)
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
                " payload=${payload?.encodeToString(Base16Strict)}," +
                " signature=${rawSignature.encodeToString(Base16Strict)})"
    }

    companion object {
        fun deserialize(it: ByteArray) = catching {
            coseCompliantSerializer.decodeFromByteArray<CoseSigned>(it)
        }
    }
}

fun CoseHeader.usesEC(): Boolean? = algorithm?.algorithm?.let { it is SignatureAlgorithm.ECDSA }
    ?: certificateChain?.let { X509Certificate.decodeFromDerOrNull(it)?.publicKey is CryptoPublicKey.EC }


@OptIn(ExperimentalSerializationApi::class)
@Serializable
@CborArray
data class CoseSignatureInput(
    val contextString: String,
    @Serializable(with = ByteStringWrapperCoseHeaderSerializer::class)
    @ByteString
    val protectedHeader: ByteStringWrapper<CoseHeader>,
    @ByteString
    val externalAad: ByteArray,
    @ByteString
    val payload: ByteArray?,
) {
    fun serialize() = coseCompliantSerializer.encodeToByteArray(this)

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
                " externalAad=${externalAad.encodeToString(Base16Strict)}," +
                " payload=${payload?.encodeToString(Base16Strict)})"
    }


    companion object {
        fun deserialize(it: ByteArray) = catching {
            coseCompliantSerializer.decodeFromByteArray<CoseSignatureInput>(it)
        }
    }
}

object ByteStringWrapperCoseHeaderSerializer : KSerializer<ByteStringWrapper<CoseHeader>> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("ByteStringWrapperCoseHeaderSerializer", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: ByteStringWrapper<CoseHeader>) {
        val bytes = coseCompliantSerializer.encodeToByteArray(value.value)
        encoder.encodeSerializableValue(ByteArraySerializer(), bytes)
    }

    override fun deserialize(decoder: Decoder): ByteStringWrapper<CoseHeader> {
        val bytes = decoder.decodeSerializableValue(ByteArraySerializer())
        return ByteStringWrapper(coseCompliantSerializer.decodeFromByteArray(bytes), bytes)
    }

}
