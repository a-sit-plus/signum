package at.asitplus.signum.indispensable.cosef

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.cosef.io.Base16Strict
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapperSerializer
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.pki.X509Certificate
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.*
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.CborArray

/**
 * Representation of a signed COSE_Sign1 object, i.e. consisting of protected header, unprotected header and payload.
 *
 * If the payload is a generic [ByteArray], then it will be serialized as-is. Should the payload be any other type,
 * the [CoseSignedSerializer] will tag it with 24 (see [RFC8949 3.4.5.1](https://www.rfc-editor.org/rfc/rfc8949.html#name-encoded-cbor-data-item)) during serialization.
 * In order to prevent nested wrapping of the payload and the resulting type erasure
 * payloads of type [ByteStringWrapper] will be rejected.
 * In this case the payload could be handed over as the wrapped class itself or manually serialized to [ByteArray]
 *
 * See [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html).
 */
@OptIn(ExperimentalSerializationApi::class)
@Serializable(with = CoseSignedSerializer::class)
@CborArray
data class CoseSigned<P : Any?>(
    @ByteString
    val protectedHeader: ByteStringWrapper<CoseHeader>,
    val unprotectedHeader: CoseHeader?,
    @ByteString
    val payload: P?,
    @ByteString
    val rawSignature: ByteArray,
) {

    @Throws(IllegalArgumentException::class)
    constructor(
        protectedHeader: CoseHeader,
        unprotectedHeader: CoseHeader?,
        payload: P?,
        signature: CryptoSignature.RawByteEncodable
    ) : this(
        protectedHeader = ByteStringWrapper(value = protectedHeader),
        unprotectedHeader = unprotectedHeader,
        payload = kotlin.run {
            when(payload) {
                ByteStringWrapper -> throw IllegalArgumentException("CoseSigned does not support ByteStringWrapper payloads, unwrap or serialize manually")
                else -> payload
            }
        },
        rawSignature = signature.rawByteArray
    )

    val signature: CryptoSignature by lazy {
        if (protectedHeader.value.usesEC() ?: unprotectedHeader?.usesEC() ?: (rawSignature.size < 2048))
            CryptoSignature.EC.fromRawBytes(rawSignature)
        else CryptoSignature.RSAorHMAC(rawSignature)
    }

    fun serialize(parameterSerializer: KSerializer<P>): ByteArray = coseCompliantSerializer
        .encodeToByteArray(CoseSignedSerializer(parameterSerializer), this)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as CoseSigned<*>

        if (protectedHeader != other.protectedHeader) return false
        if (unprotectedHeader != other.unprotectedHeader) return false
        if (payload != null) {
            if (other.payload == null) return false
            if (!payload.contentEqualsIfArray(other.payload)) return false
        } else if (other.payload != null) return false
        return rawSignature.contentEquals(other.rawSignature)
    }

    override fun hashCode(): Int {
        var result = protectedHeader.hashCode()
        result = 31 * result + (unprotectedHeader?.hashCode() ?: 0)
        result = 31 * result + (payload?.contentHashCodeIfArray() ?: 0)
        result = 31 * result + rawSignature.contentHashCode()
        return result
    }

    override fun toString(): String {
        return "CoseSigned(protectedHeader=${protectedHeader.value}," +
                " unprotectedHeader=$unprotectedHeader," +
                " payload=${if (payload is ByteArray) payload.encodeToString(Base16Strict) else payload}," +
                " signature=${rawSignature.encodeToString(Base16Strict)})"
    }

    companion object {
        fun <P : Any> deserialize(parameterSerializer: KSerializer<P>, it: ByteArray): KmmResult<CoseSigned<P>> =
            catching {
                coseCompliantSerializer.decodeFromByteArray(CoseSignedSerializer(parameterSerializer), it)
            }

        /**
         * Called by COSE signing implementations to get the bytes that will be
         * used as the input for signature calculation of a `COSE_Sign1` object
         */
        fun <P : Any> prepareCoseSignatureInput(
            protectedHeader: CoseHeader,
            payload: P?,
            serializer: KSerializer<P>,
            externalAad: ByteArray = byteArrayOf(),
        ): ByteArray = CoseSignatureInput(
            contextString = "Signature1",
            protectedHeader = ByteStringWrapper(protectedHeader),
            externalAad = externalAad,
            payload = when (payload) {
                null -> null
                is ByteArray -> payload
                else -> coseCompliantSerializer.encodeToByteArray(
                    ByteStringWrapperSerializer(serializer),
                    ByteStringWrapper(payload)
                )
            },
        ).serialize()
    }
}

fun CoseHeader.usesEC(): Boolean? = algorithm?.algorithm?.let { it is SignatureAlgorithm.ECDSA }
    ?: certificateChain?.let { X509Certificate.decodeFromDerOrNull(it)?.publicKey is CryptoPublicKey.EC }


@OptIn(ExperimentalSerializationApi::class)
@Serializable
@CborArray
data class CoseSignatureInput(
    val contextString: String,
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

