package at.asitplus.signum.indispensable.cosef

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapperSerializer
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.pki.Certificate
import at.asitplus.signum.indispensable.sign.EcdsaAlgorithm
import at.asitplus.signum.indispensable.sign.EcdsaSignature
import at.asitplus.signum.indispensable.sign.RsaSignature
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.Cbor
import kotlinx.serialization.cbor.CborMap
import kotlinx.serialization.cbor.CborObjectAsArray
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.serializer

/**
 * Common base for the COSE message structures of
 * [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html).
 */
@OptIn(ExperimentalSerializationApi::class)
sealed class COSE {

    abstract val plainProtectedHeader: ByteArray

    /** The protected bucket decoded from [plainProtectedHeader], not interpreted. */
    abstract val protectedHeader: CborMap

    /** The unprotected bucket, not interpreted. Unknown labels are kept. */
    abstract val unprotectedHeader: CborMap

    /**
     * The content of the message the plaintext or the ciphertext as transmitted, or `null` when it is
     * detached.
     */
    abstract val plainContent: ByteArray?

    /**
     * Combines and decodes both buckets with [serializer]. Unlike `typed()`, this does not touch the payload, so it
     * also works for detached messages.
     */
    fun <H : CoseHeaderBase> wrappedHeader(
        serializer: KSerializer<H>,
        serialFormat: Cbor = coseCompliantSerializer,
    ): CoseHeaderWrapped<H> = CoseHeaderWrapped.fromBuckets(serializer, protectedHeader, unprotectedHeader, serialFormat)

    /** Combines and decodes both buckets into [H]. */
    inline fun <reified H : CoseHeaderBase> wrappedHeader(
        serialFormat: Cbor = coseCompliantSerializer,
    ): CoseHeaderWrapped<H> = wrappedHeader(serialFormat.serializersModule.serializer(), serialFormat)


    companion object {

        /**
         * Builds the `Sig_structure` of a `COSE_Sign1` (RFC 9052 4.4):
         * `["Signature1", body_protected, external_aad, payload]`.
         */
        fun sign1StructureInput(
            plainProtectedHeader: ByteArray,
            externalAad: ByteArray = byteArrayOf(),
            payload: ByteArray,
        ): ByteArray = encodeStructure("Signature1", plainProtectedHeader, externalAad, payload)

        /**
         * Builds the `MAC_structure` of a `COSE_Mac0` (RFC 9052 §6.3):
         * `["MAC0", protected, external_aad, payload]`.
         */
        fun mac0StructureInput(
            plainProtectedHeader: ByteArray,
            externalAad: ByteArray = byteArrayOf(),
            payload: ByteArray,
        ): ByteArray = encodeStructure("MAC0", plainProtectedHeader, externalAad, payload)

        private fun encodeStructure(
            context: String,
            plainProtectedHeader: ByteArray,
            externalAad: ByteArray,
            payload: ByteArray,
        ): ByteArray = coseCompliantSerializer.encodeToByteArray(
            CoseStructure(context, plainProtectedHeader, externalAad, payload)
        )

        /**
         * Reconstructs a [CryptoSignature] from the raw `bstr`, using `alg` (or the `x5chain` leaf) of [header].
         */
        fun getSignature(plainSignature: ByteArray, header: CoseHeaderBase): CryptoSignature =
            getSignature(plainSignature, header, null)

        /** Also consults [fallbackHeader], for the deprecated `CoseSigned`, which keeps both buckets separate. */
        internal fun getSignature(
            plainSignature: ByteArray,
            header: CoseHeaderBase,
            fallbackHeader: CoseHeaderBase?,
        ): CryptoSignature =
            if (header.usesEC() ?: fallbackHeader?.usesEC() ?: (plainSignature.size < 2048))
                EcdsaSignature.fromP1363Bytes(plainSignature)
            else
                RsaSignature(plainSignature)

        private fun CoseHeaderBase.usesEC(): Boolean? = when (val alg = algorithm) {
            null -> certificateChain?.firstOrNull()
                ?.let { Certificate.decodeFromByteArray(it) }
                ?.let { it.signatureAlgorithm is EcdsaAlgorithm }

            is CoseAlgorithm.Signature -> (alg.algorithm is EcdsaAlgorithm)
            else -> false
        }
    }
}

/**
 * A COSE message whose content is the plaintext payload: signed and MACed messages.
 */
sealed class CosePlaintextMessage : COSE() {

    /** The payload as transmitted, or `null` when it is detached. */
    abstract val plainPayload: ByteArray?

    final override val plainContent: ByteArray? get() = plainPayload

    /**
     * Decodes [plainPayload] with [serializer]
     * Accepts both a directly encoded payload and one wrapped in CBOR tag 24
     */
    fun <P> getPayload(serializer: KSerializer<P>, serialFormat: Cbor = coseCompliantSerializer): KmmResult<P> =
        catching {
            val bytes = plainPayload ?: throw IllegalStateException("Payload is detached; supply it externally")
            bytes.toTypedPayload(serializer, serialFormat)
        }

    /** Find the correct serializer at compile time. */
    inline fun <reified P> getPayload(serialFormat: Cbor = coseCompliantSerializer): KmmResult<P> =
        getPayload(serialFormat.serializersModule.serializer(), serialFormat)
}

/**
 * A COSE message whose content is ciphertext: COSE_Encrypt0 and COSE_Encrypt
 * Not implemented by any message type yet
 */
sealed class CoseCiphertextMessage : COSE() {

    /** The ciphertext as transmitted, or `null` when it is detached. */
    abstract val ciphertext: ByteArray?

    final override val plainContent: ByteArray? get() = ciphertext
}

/** The four-element `Sig_structure` / `MAC_structure` */
@Serializable
@CborObjectAsArray
internal data class CoseStructure(
    val context: String,
    @ByteString val plainProtectedHeader: ByteArray,
    @ByteString val externalAad: ByteArray,
    @ByteString val payload: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as CoseStructure

        if (context != other.context) return false
        if (!plainProtectedHeader.contentEquals(other.plainProtectedHeader)) return false
        if (!externalAad.contentEquals(other.externalAad)) return false
        if (!payload.contentEquals(other.payload)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = context.hashCode()
        result = 31 * result + plainProtectedHeader.contentHashCode()
        result = 31 * result + externalAad.contentHashCode()
        result = 31 * result + payload.contentHashCode()
        return result
    }
}

@OptIn(ExperimentalSerializationApi::class)
internal fun <P> ByteArray.toTypedPayload(
    serializer: KSerializer<P>,
    serialFormat: Cbor = coseCompliantSerializer,
): P =
    if (serializer == ByteArraySerializer()) {
        @Suppress("UNCHECKED_CAST")
        (this as P)
    } else {
        runCatching { serialFormat.decodeFromByteArray(serializer, this) }
            .getOrElse { serialFormat.decodeFromByteArray(ByteStringWrapperSerializer(serializer), this).value }
    }