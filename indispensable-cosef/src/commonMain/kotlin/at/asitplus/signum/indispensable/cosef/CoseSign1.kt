package at.asitplus.signum.indispensable.cosef

import at.asitplus.catchingUnwrappedAs
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.cosef.io.Base16Strict
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.Transient
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.CborArray
import kotlinx.serialization.cbor.CborMap
import kotlinx.serialization.cbor.CborObjectAsArray
import kotlinx.serialization.decodeFromByteArray

/**
 * COSE_Sign1
 * This type is the wire form. For a payload whose type is part of the contract, see [CoseSign1Typed].
 */
@OptIn(ExperimentalSerializationApi::class)
@ConsistentCopyVisibility
@Serializable
@CborObjectAsArray
data class CoseSign1 internal constructor(
    @ByteString
    override val plainProtectedHeader: ByteArray,

    /** Always encoded as a map; a CBOR `null` written by the deprecated `CoseSigned` is read as an empty bucket. */
    @Serializable(with = UnprotectedHeaderSerializer::class)
    override val unprotectedHeader: CborMap,

    @ByteString
    override val plainPayload: ByteArray?,

    @ByteString
    val plainSignature: ByteArray,
) : CosePlaintextMessage() {

    @Transient
    override val protectedHeader: CborMap = decodeProtectedBucket(plainProtectedHeader)

    init {
        requireValidBuckets(protectedHeader, unprotectedHeader)
    }

    /**
     * The `Sig_structure` bytes that [plainSignature] is computed over, built from [plainProtectedHeader] as received.
     */
    fun signatureInput(
        externalAad: ByteArray = byteArrayOf(),
        detachedPayload: ByteArray? = null,
    ): ByteArray {
        val payload = if (plainPayload != null) {
            require(detachedPayload == null) { "Payload is attached; detachedPayload must not be set" }
            plainPayload
        } else requireNotNull(detachedPayload) { "Payload is detached; supply it as detachedPayload" }
        return sign1StructureInput(plainProtectedHeader, externalAad, payload)
    }

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

        /** Parses a [CoseSign1] from its CBOR encoding. */
        @Throws(SerializationException::class)
        operator fun invoke(bytes: ByteArray): CoseSign1 = catchingUnwrappedAs(::SerializationException) {
            coseCompliantSerializer.decodeFromByteArray<CoseSign1>(bytes)
        }.getOrThrow()

        /** Builds a new [CoseSign1] with the buckets of [header], signing the `Sig_structure`. */
        suspend operator fun invoke(
            header: CoseHeaderWrapped<*>,
            plainPayload: ByteArray,
            detached: Boolean = false,
            externalAad: ByteArray = byteArrayOf(),
            signer: suspend (ByteArray) -> ByteArray,
        ): CoseSign1 {
            val plainProtectedHeader = header.plainProtectedHeader
            return CoseSign1(
                plainProtectedHeader = plainProtectedHeader,
                unprotectedHeader = header.unprotectedHeader,
                plainPayload = if (detached) null else plainPayload,
                plainSignature = signer(sign1StructureInput(plainProtectedHeader, externalAad, plainPayload)),
            )
        }

        /** Builds a new [CoseSign1] from two [CoseHeader]s, one per bucket. */
        suspend operator fun invoke(
            protectedHeader: CoseHeader,
            unprotectedHeader: CoseHeader? = null,
            plainPayload: ByteArray,
            detached: Boolean = false,
            externalAad: ByteArray = byteArrayOf(),
            signer: suspend (ByteArray) -> ByteArray,
        ): CoseSign1 {
            val plainProtectedHeader = encodeProtectedBucket(protectedHeader.toBucket())
            return CoseSign1(
                plainProtectedHeader = plainProtectedHeader,
                unprotectedHeader = unprotectedHeader?.toBucket() ?: EMPTY_BUCKET,
                plainPayload = if (detached) null else plainPayload,
                plainSignature = signer(sign1StructureInput(plainProtectedHeader, externalAad, plainPayload)),
            )
        }
    }
}

/** Decodes the payload of a [CoseSign1] into [P], yielding the typed wrapper. */
inline fun <reified P> CoseSign1.typed(): CoseSign1Typed<P> = CoseTyped(this, getPayload<P>().getOrThrow())

/** Decodes the payload of a [CoseSign1] into [P] using an explicit serializer. */
fun <P> CoseSign1.typed(serializer: KSerializer<P>): CoseSign1Typed<P> =
    CoseTyped(this, getPayload(serializer).getOrThrow())