package at.asitplus.signum.indispensable.cosef

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.contentEqualsIfArray
import at.asitplus.signum.indispensable.contentHashCodeIfArray
import at.asitplus.signum.indispensable.cosef.io.Base16Strict
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapperSerializer
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.pki.X509Certificate
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.CborArray
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

/**
 * Representation of a signed COSE_Sign1 object, i.e. consisting of protected header, unprotected header and payload.
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
    val payload: ByteArray?,
    @ByteString
    val rawSignature: ByteArray,
) {

    constructor(
        protectedHeader: CoseHeader,
        unprotectedHeader: CoseHeader?,
        payload: ByteArray?,
        signature: CryptoSignature.RawByteEncodable,
    ) : this(
        protectedHeader = ByteStringWrapper(value = protectedHeader),
        unprotectedHeader = unprotectedHeader,
        payload = payload,
        rawSignature = signature.rawByteArray
    )

    val signature: CryptoSignature by lazy {
        if (protectedHeader.value.usesEC() ?: unprotectedHeader?.usesEC() ?: (rawSignature.size < 2048))
            CryptoSignature.EC.fromRawBytes(rawSignature)
        else CryptoSignature.RSAorHMAC(rawSignature)
    }

    fun serialize(): ByteArray = coseCompliantSerializer.encodeToByteArray(CoseSignedSerializer(), this)

    /**
     * Decodes the payload of this object into a [ByteStringWrapper] containing an object of type [P].
     *
     * Note that this does not work if the payload is directly a [ByteArray].
     */
    fun getTypedPayload(deserializer: KSerializer<P>): KmmResult<ByteStringWrapper<P>?> = catching {
        payload?.let {
            coseCompliantSerializer.decodeFromByteArray(ByteStringWrapperSerializer(deserializer), it)
        }
    }

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
                " payload=${payload?.encodeToString(Base16Strict)}," +
                " signature=${rawSignature.encodeToString(Base16Strict)})"
    }

    companion object {
        fun deserialize(it: ByteArray): KmmResult<CoseSigned<ByteArray>> = catching {
            coseCompliantSerializer.decodeFromByteArray<CoseSigned<ByteArray>>(it)
        }

        /**
         * Creates a [CoseSigned] object from the given parameters,
         * encapsulating the [payload] into a [ByteStringWrapper].
         *
         * This has to be an inline function with a reified type parameter,
         * so it can't be a constructor (leads to a runtime error).
         */
        inline fun <reified P : Any?> fromObject(
            protectedHeader: CoseHeader,
            unprotectedHeader: CoseHeader?,
            payload: P,
            signature: CryptoSignature.RawByteEncodable,
        ): CoseSigned<P> =
            CoseSigned(
                protectedHeader = ByteStringWrapper(value = protectedHeader),
                unprotectedHeader = unprotectedHeader,
                payload =
                    when (payload) {
                        is ByteArray -> payload
                        else -> coseCompliantSerializer.encodeToByteArray(ByteStringWrapper(payload))
                    },
                rawSignature = signature.rawByteArray
            )

        inline fun <reified P : Any?> formObject(
            protectedHeader: CoseHeader,
            unprotectedHeader: CoseHeader?,
            payload: ByteStringWrapper<P>,
            signature: CryptoSignature.RawByteEncodable,
        ) = CoseSigned<P>(
            protectedHeader = protectedHeader,
            unprotectedHeader = unprotectedHeader,
            payload = coseCompliantSerializer.encodeToByteArray(payload),
            signature = signature
        )
    }

    /**
     * Called by COSE signing implementations to get the bytes that will be
     * used as the input for signature calculation of a `COSE_Sign1` object
     */
    inline fun <reified P : Any> prepareCoseSignatureInput(
        protectedHeader: CoseHeader,
        payload: P?,
        externalAad: ByteArray = byteArrayOf(),
    ): ByteArray = CoseSignatureInput(
        contextString = "Signature1",
        protectedHeader = ByteStringWrapper(protectedHeader),
        externalAad = externalAad,
        payload = when (payload) {
            is ByteArray -> payload
            is ByteStringWrapper<*> -> coseCompliantSerializer.encodeToByteArray(payload)
            else -> coseCompliantSerializer.encodeToByteArray(ByteStringWrapper(payload))
        },
    ).serialize()
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

