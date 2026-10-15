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

    abstract val plainPayload: ByteArray?

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

    /**
     * The `context` strings of RFC 9052
     */
    enum class Context(val value: String) {
        /** `Sig_structure` for a `COSE_Signature` inside a `COSE_Sign`. */
        Signature("Signature"),

        /** `Sig_structure` for a `COSE_Sign1`. */
        Signature1("Signature1"),

        /** `MAC_structure` for a `COSE_Mac`. */
        Mac("MAC"),

        /** `MAC_structure` for a `COSE_Mac0`. */
        Mac0("MAC0"),

        /** `Enc_structure` for a `COSE_Encrypt`. */
        Encrypt("Encrypt"),

        /** `Enc_structure` for a `COSE_Encrypt0`. */
        Encrypt0("Encrypt0"),

        /** `Enc_structure` for a recipient of a `COSE_Encrypt`. */
        EncRecipient("Enc_Recipient"),

        /** `Enc_structure` for a recipient of a `COSE_Mac`. */
        MacRecipient("Mac_Recipient"),

        /** `Enc_structure` for a recipient nested inside another recipient. */
        RecRecipient("Rec_Recipient"),
    }

    companion object {

        /** The empty `protected` bucket: RFC 9052 zero-length byte string. */
        val EMPTY_PROTECTED_HEADER: ByteArray = byteArrayOf()

        fun decodeProtectedHeader(plainProtectedHeader: ByteArray): CoseHeader =
            if (plainProtectedHeader.isEmpty()) CoseHeader()
            else coseCompliantSerializer.decodeFromByteArray(CoseHeader.serializer(), plainProtectedHeader)

        /** Encodes [header] for use as a protected bucket, collapsing an empty map to the zero-length form. */
        fun encodeProtectedHeader(header: CoseHeader): ByteArray =
            coseCompliantSerializer.encodeToByteArray(CoseHeader.serializer(), header)
                .let { if (it.size == 1 && it[0] == 0xA0.toByte()) EMPTY_PROTECTED_HEADER else it }

        /**
         * Builds the four-element Sig_structure/MAC_structure
         */
        fun structureInput(
            context: Context,
            plainProtectedHeader: ByteArray,
            externalAad: ByteArray = byteArrayOf(),
            payload: ByteArray,
        ): ByteArray = coseCompliantSerializer.encodeToByteArray(
            CoseStructure(context.value, plainProtectedHeader, externalAad, payload)
        )

        /**
         * Builds the five-element `Sig_structure` used for a `COSE_Signature` inside a `COSE_Sign`,
         */
        fun signerStructureInput(
            bodyProtectedHeader: ByteArray,
            signProtectedHeader: ByteArray,
            externalAad: ByteArray = byteArrayOf(),
            payload: ByteArray,
        ): ByteArray = coseCompliantSerializer.encodeToByteArray(
            CoseSignerStructure(
                Context.Signature.value, bodyProtectedHeader, signProtectedHeader, externalAad, payload
            )
        )

        /**
         * Reconstructs a [CryptoSignature] from the raw `bstr`.
         */
        fun getSignature(
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
 * Labels carried by this header, for the RFC 9052 check that a label does not occur in both buckets.
 * Only the labels [CoseHeader] models are visible here
 */
internal val CoseHeader.presentLabels: Set<Long>
    get() = buildSet {
        algorithm?.let { add(1L) }
        criticalHeaders?.let { add(2L) }
        contentType?.let { add(3L) }
        kid?.let { add(4L) }
        iv?.let { add(5L) }
        partialIv?.let { add(6L) }
        type?.let { add(16L) }
        certificateChain?.let { add(33L) }
    }

/**
 * Labels present in both buckets.
 * RFC 9052 applications SHOULD verify that a label does not occur in both the protected and the unprotected bucket
 */
fun COSE.duplicateLabels(): Set<Long> =
    unprotectedHeader?.let { COSE.decodeProtectedHeader(plainProtectedHeader).presentLabels intersect it.presentLabels }
        ?: emptySet()

/** The four-element `Sig_structure` / `MAC_structure` */
@Serializable
@CborArray
internal data class CoseStructure(
    val context: String,
    @ByteString val plainProtectedHeader: ByteArray,
    @ByteString val externalAad: ByteArray,
    @ByteString val payload: ByteArray,
)

/** The five-element `Sig_structure` used by `COSE_Signature` */
@Serializable
@CborArray
internal data class CoseSignerStructure(
    val context: String,
    @ByteString val bodyProtectedHeader: ByteArray,
    @ByteString val signProtectedHeader: ByteArray,
    @ByteString val externalAad: ByteArray,
    @ByteString val payload: ByteArray,
)

@OptIn(ExperimentalSerializationApi::class)
internal fun <P> ByteArray.toTypedPayload(serializer: KSerializer<P>): P =
    if (serializer == ByteArraySerializer()) {
        @Suppress("UNCHECKED_CAST")
        (this as P)
    } else {
        runCatching { coseCompliantSerializer.decodeFromByteArray(serializer, this) }
            .getOrElse { coseCompliantSerializer.decodeFromByteArray(ByteStringWrapperSerializer(serializer), this).value }
    }