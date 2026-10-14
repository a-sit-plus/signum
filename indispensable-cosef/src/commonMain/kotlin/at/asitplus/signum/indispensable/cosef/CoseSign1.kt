package at.asitplus.signum.indispensable.cosef

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.cosef.io.Base16Strict
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.CborArray
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

/**
 * COSE_Sign1
 * This type is the wire form. For a payload whose type is part of the contract, see [CoseSign1Typed].
 */
@ConsistentCopyVisibility
@Serializable
@CborArray
data class CoseSign1 internal constructor(
    @ByteString
    override val plainProtectedHeader: ByteArray,

    /**
     * Kept nullable to preserve the behavior of the previous `CoseBytes`. RFC 9052 models this bucket as always
     * present. Tightening it is deferred to the header rework
     */
    override val unprotectedHeader: CoseHeader?,

    @ByteString
    override val plainPayload: ByteArray?,

    @ByteString
    val plainSignature: ByteArray,
) : COSE() {

    @Transient
    val protectedHeader: CoseHeader = decodeProtectedHeader(plainProtectedHeader)

    @Transient
    val signature: CryptoSignature = getSignature(plainSignature, protectedHeader, unprotectedHeader)

    /**
     * The `Sig_structure` bytes that [signature] is computed over, built from [plainProtectedHeader] as received.
     */
    fun signatureInput(
        externalAad: ByteArray = byteArrayOf(),
        detachedPayload: ByteArray? = null,
    ): ByteArray {
        val payload = if (detachedPayload != null) {
            require(plainPayload == null) { "Payload is not detached; detachedPayload must not be set" }
            detachedPayload
        } else plainPayload
        return structureInput(Context.Signature1, plainProtectedHeader, externalAad, payload)
    }

    fun serialize(): ByteArray = coseCompliantSerializer.encodeToByteArray(this)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as CoseSign1

        if (!plainProtectedHeader.contentEquals(other.plainProtectedHeader)) return false
        if (unprotectedHeader != other.unprotectedHeader) return false
        if (!plainPayload.contentEquals(other.plainPayload)) return false
        if (!plainSignature.contentEquals(other.plainSignature)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = plainProtectedHeader.contentHashCode()
        result = 31 * result + (unprotectedHeader?.hashCode() ?: 0)
        result = 31 * result + (plainPayload?.contentHashCode() ?: 0)
        result = 31 * result + plainSignature.contentHashCode()
        return result
    }

    override fun toString(): String = "CoseSign1(" +
            "protectedHeader=$protectedHeader, " +
            "unprotectedHeader=$unprotectedHeader, " +
            "payload=${plainPayload?.encodeToString(Base16Strict)}, " +
            "signature=${plainSignature.encodeToString(Base16Strict)})"

    companion object {

        fun deserialize(input: ByteArray): KmmResult<CoseSign1> = catching {
            coseCompliantSerializer.decodeFromByteArray<CoseSign1>(input)
        }

        /**
         * Assembles a [CoseSign1] from an already computed signature.
         * [plainProtectedHeader] must be the same bytes that were passed to [prepare]; re-encoding
         * [protectedHeader] here would be the defect this type exists to prevent.
         */
        operator fun invoke(
            plainProtectedHeader: ByteArray,
            unprotectedHeader: CoseHeader? = null,
            plainPayload: ByteArray?,
            plainSignature: ByteArray,
        ): CoseSign1 = CoseSign1(plainProtectedHeader, unprotectedHeader, plainPayload, plainSignature)

        /**
         * Encodes [protectedHeader] once and returns both the bytes to keep and the `Sig_structure` to sign.
         */
        fun prepare(
            protectedHeader: CoseHeader,
            externalAad: ByteArray = byteArrayOf(),
            plainPayload: ByteArray?,
        ): Prepared {
            val plainProtectedHeader = encodeProtectedHeader(protectedHeader)
            return Prepared(
                plainProtectedHeader = plainProtectedHeader,
                signatureInput = structureInput(
                    Context.Signature1, plainProtectedHeader, externalAad, plainPayload
                ),
            )
        }

        /** Convenience overload that signs immediately. */
        suspend operator fun invoke(
            protectedHeader: CoseHeader,
            unprotectedHeader: CoseHeader? = null,
            plainPayload: ByteArray?,
            externalAad: ByteArray = byteArrayOf(),
            signer: suspend (ByteArray) -> ByteArray,
        ): CoseSign1 = prepare(protectedHeader, externalAad, plainPayload).let { prepared ->
            CoseSign1(
                plainProtectedHeader = prepared.plainProtectedHeader,
                unprotectedHeader = unprotectedHeader,
                plainPayload = plainPayload,
                plainSignature = signer(prepared.signatureInput),
            )
        }

        /** The encoded protected bucket together with the structure to be signed over it. */
        data class Prepared(
            val plainProtectedHeader: ByteArray,
            val signatureInput: ByteArray,
        ) {
            override fun equals(other: Any?): Boolean {
                if (this === other) return true
                if (other == null || this::class != other::class) return false
                other as Prepared
                if (!plainProtectedHeader.contentEquals(other.plainProtectedHeader)) return false
                return signatureInput.contentEquals(other.signatureInput)
            }

            override fun hashCode(): Int =
                31 * plainProtectedHeader.contentHashCode() + signatureInput.contentHashCode()
        }
    }
}

/** Decodes the payload of a [CoseSign1] into [P], yielding the typed wrapper. */
inline fun <reified P> CoseSign1.typed(): CoseSign1Typed<P> = CoseTyped(this, getPayload<P>().getOrThrow())

/** Decodes the payload of a [CoseSign1] into [P] using an explicit serializer. */
fun <P> CoseSign1.typed(serializer: KSerializer<P>): CoseSign1Typed<P> =
    CoseTyped(this, getPayload(serializer).getOrThrow())