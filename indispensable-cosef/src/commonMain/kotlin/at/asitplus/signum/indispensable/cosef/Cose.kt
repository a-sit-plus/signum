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
import kotlinx.serialization.cbor.CborArray
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.serializer

/**
 * Common base for the COSE message structures of
 * [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html).
 */
sealed class COSE {

    abstract val plainProtectedHeader: ByteArray

    abstract val unprotectedHeader: CoseHeader?

    /**
     * The content of the message the plaintext or the ciphertext as transmitted, or `null` when it is
     * detached.
     */
    abstract val plainContent: ByteArray?

    companion object {

        /** The empty `protected` bucket: RFC 9052 zero-length byte string. */
        private val EMPTY_PROTECTED_HEADER: ByteArray = byteArrayOf()

        fun decodeProtectedHeader(plainProtectedHeader: ByteArray): CoseHeader =
            if (plainProtectedHeader.isEmpty()) CoseHeader()
            else coseCompliantSerializer.decodeFromByteArray(CoseHeader.serializer(), plainProtectedHeader)

        /** Encodes [header] for use as a protected bucket, collapsing an empty map to the zero-length form. */
        fun encodeProtectedHeader(header: CoseHeader): ByteArray =
            coseCompliantSerializer.encodeToByteArray(CoseHeader.serializer(), header)
                .let { if (it.size == 1 && it[0] == 0xA0.toByte()) EMPTY_PROTECTED_HEADER else it }

        /**
         * Builds the `Sig_structure` of a `COSE_Sign1` (RFC 9052 §4.4):
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
         * Reconstructs a [CryptoSignature] from the raw `bstr`.
         */
        internal fun getSignature(
            plainSignature: ByteArray,
            protectedHeader: CoseHeader,
            unprotectedHeader: CoseHeader?,
        ): CryptoSignature =
            if (protectedHeader.usesEC() ?: unprotectedHeader?.usesEC() ?: (plainSignature.size < 2048))
                EcdsaSignature.fromP1363Bytes(plainSignature)
            else
                RsaSignature(plainSignature)

        private fun CoseHeader.usesEC(): Boolean? = when (algorithm) {
            null -> certificateChain?.firstOrNull()
                ?.let { Certificate.decodeFromByteArray(it) }
                ?.let { it.signatureAlgorithm is EcdsaAlgorithm }

            is CoseAlgorithm.Signature -> (algorithm.algorithm is EcdsaAlgorithm)
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
    fun <P> getPayload(serializer: KSerializer<P>): KmmResult<P> = catching {
        val bytes = plainPayload ?: throw IllegalStateException("Payload is detached; supply it externally")
        bytes.toTypedPayload(serializer)
    }

    /** Find the correct serializer at compile time. */
    inline fun <reified P> getPayload(): KmmResult<P> =
        getPayload(coseCompliantSerializer.serializersModule.serializer())
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
@CborArray
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
internal fun <P> ByteArray.toTypedPayload(serializer: KSerializer<P>): P =
    if (serializer == ByteArraySerializer()) {
        @Suppress("UNCHECKED_CAST")
        (this as P)
    } else {
        runCatching { coseCompliantSerializer.decodeFromByteArray(serializer, this) }
            .getOrElse { coseCompliantSerializer.decodeFromByteArray(ByteStringWrapperSerializer(serializer), this).value }
    }

/**
 * Combines a protected and an unprotected bucket into one header, failing if a parameter occurs in
 * both. Only parameters modeled by [CoseHeader] can be checked; unknown labels are dropped on decoding.
 */
internal fun CoseHeader.strictUnion(unprotected: CoseHeader?): CoseHeader {
    if (unprotected == null) return this
    fun <T> pick(label: String, protected: T?, unprotected: T?): T? {
        require(protected == null || unprotected == null) {
            "Header parameter '$label' must not occur in both protected and unprotected header"
        }
        return protected ?: unprotected
    }
    return CoseHeader(
        algorithm = pick("alg", algorithm, unprotected.algorithm),
        criticalHeaders = pick("crit", criticalHeaders, unprotected.criticalHeaders),
        contentType = pick("content type", contentType, unprotected.contentType),
        kid = pick("kid", kid, unprotected.kid),
        iv = pick("IV", iv, unprotected.iv),
        partialIv = pick("Partial IV", partialIv, unprotected.partialIv),
        certificateChain = pick("x5chain", certificateChain, unprotected.certificateChain),
        type = pick("typ", type, unprotected.type),
    )
}