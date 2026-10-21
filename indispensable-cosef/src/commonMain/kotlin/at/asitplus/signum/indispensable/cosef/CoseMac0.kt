package at.asitplus.signum.indispensable.cosef

import at.asitplus.catchingUnwrappedAs
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
 * Representation of a COSE_MAC0 object
 * [RFC 9052 §6.2](https://www.rfc-editor.org/rfc/rfc9052.html#section-6.2).
 * Serialized untagged, as [CoseSign1].
 */
@OptIn(ExperimentalSerializationApi::class)
@ConsistentCopyVisibility
@Serializable
@CborObjectAsArray
data class CoseMac0 internal constructor(
    @ByteString
    override val plainProtectedHeader: ByteArray,

    /** Always encoded as a map; a CBOR `null` written by the deprecated `CoseMac` is read as an empty bucket. */
    @Serializable(with = UnprotectedHeaderSerializer::class)
    override val unprotectedHeader: CborMap,

    @ByteString
    override val plainPayload: ByteArray?,

    /** The authentication tag `bstr`. */
    @ByteString
    val tag: ByteArray,
) : CosePlaintextMessage() {

    @Transient
    override val protectedHeader: CborMap = decodeProtectedBucket(plainProtectedHeader)

    init {
        requireValidBuckets(protectedHeader, unprotectedHeader)
    }

    /**
     * The `MAC_structure` bytes the [tag] is computed over, built from [plainProtectedHeader] as received.
     */
    fun macInput(
        externalAad: ByteArray = byteArrayOf(),
        detachedPayload: ByteArray? = null,
    ): ByteArray {
        val payload = if (plainPayload != null) {
            require(detachedPayload == null) { "Payload is attached; detachedPayload must not be set" }
            plainPayload
        } else requireNotNull(detachedPayload) { "Payload is detached; supply it as detachedPayload" }
        return mac0StructureInput(plainProtectedHeader, externalAad, payload)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as CoseMac0

        if (!plainProtectedHeader.contentEquals(other.plainProtectedHeader)) return false
        if (unprotectedHeader != other.unprotectedHeader) return false
        if (!plainPayload.contentEquals(other.plainPayload)) return false
        if (!tag.contentEquals(other.tag)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = plainProtectedHeader.contentHashCode()
        result = 31 * result + (unprotectedHeader?.hashCode() ?: 0)
        result = 31 * result + (plainPayload?.contentHashCode() ?: 0)
        result = 31 * result + tag.contentHashCode()
        return result
    }

    override fun toString(): String = "CoseMac0(" +
            "protectedHeader=$protectedHeader, " +
            "unprotectedHeader=$unprotectedHeader, " +
            "payload=${plainPayload?.encodeToString(Base16Strict)}, " +
            "tag=${tag.encodeToString(Base16Strict)})"

    companion object {

        /** Parses a [CoseMac0] from its CBOR encoding. */
        @Throws(SerializationException::class)
        operator fun invoke(bytes: ByteArray): CoseMac0 = catchingUnwrappedAs(::SerializationException) {
            coseCompliantSerializer.decodeFromByteArray<CoseMac0>(bytes)
        }.getOrThrow()

        /**
         * Builds a new [CoseMac0], authenticating the `MAC_structure` built from the encoded [protectedHeader].
         */
        suspend operator fun invoke(
            header: CoseHeaderWrapped<*>,
            plainPayload: ByteArray,
            detached: Boolean = false,
            externalAad: ByteArray = byteArrayOf(),
            mac: suspend (ByteArray) -> ByteArray,
        ): CoseMac0 {
            val plainProtectedHeader = header.plainProtectedHeader
            return CoseMac0(
                plainProtectedHeader = plainProtectedHeader,
                unprotectedHeader = header.unprotectedHeader,
                plainPayload = if (detached) null else plainPayload,
                tag = mac(mac0StructureInput(plainProtectedHeader, externalAad, plainPayload)),
            )
        }

        /** Builds a new [CoseMac0] from two [CoseHeader]s, one per bucket. */
        //TODO move to designated signer class/interface https://github.com/a-sit-plus/signum/pull/446
        suspend operator fun invoke(
            protectedHeader: CoseHeader,
            unprotectedHeader: CoseHeader? = null,
            plainPayload: ByteArray,
            detached: Boolean = false,
            externalAad: ByteArray = byteArrayOf(),
            mac: suspend (ByteArray) -> ByteArray,
        ): CoseMac0 {
            val plainProtectedHeader = encodeProtectedBucket(protectedHeader.toBucket())
            return CoseMac0(
                plainProtectedHeader = plainProtectedHeader,
                unprotectedHeader = unprotectedHeader?.toBucket() ?: EMPTY_BUCKET,
                plainPayload = if (detached) null else plainPayload,
                tag = mac(mac0StructureInput(plainProtectedHeader, externalAad, plainPayload)),
            )
        }
    }
}

/** Decodes the payload of a [CoseMac0] into [P], yielding the typed wrapper. */
inline fun <reified P> CoseMac0.typed(): CoseMac0Typed<P> = CoseTyped(this, getPayload<P>().getOrThrow())

/** Decodes the payload of a [CoseMac0] into [P] using an explicit serializer. */
fun <P> CoseMac0.typed(serializer: KSerializer<P>): CoseMac0Typed<P> =
    CoseTyped(this, getPayload(serializer).getOrThrow())