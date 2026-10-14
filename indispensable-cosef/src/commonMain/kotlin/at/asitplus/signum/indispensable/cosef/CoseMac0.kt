package at.asitplus.signum.indispensable.cosef

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.cosef.io.Base16Strict
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.CborArray
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

/**
 * `COSE_Mac0` — a MAC with no recipient structures. See
 * [RFC 9052 §6.2](https://www.rfc-editor.org/rfc/rfc9052.html#section-6.2).
 *
 * ```
 * COSE_Mac0 = [ Headers, payload: bstr / nil, tag: bstr ]
 * ```
 *
 * Structurally identical on the wire to [CoseSign1] — four CBOR array elements — which is exactly why the two were
 * previously served by one `CoseBytes` class and why nothing stopped a MAC from being read as a signature. They are
 * separate types here; without CBOR tags (17 vs 18) the wire form alone cannot tell them apart, so the caller must
 * choose, and that choice is now visible in the type.
 *
 * Serialized untagged, as [CoseSign1].
 */
@ConsistentCopyVisibility
@Serializable
@CborArray
data class CoseMac0 internal constructor(
    @ByteString
    override val plainProtectedHeader: ByteArray,

    override val unprotectedHeader: CoseHeader?,

    @ByteString
    override val plainPayload: ByteArray?,

    /** The authentication tag `bstr`. */
    @ByteString
    val tag: ByteArray,
) : COSE() {

    @Transient
    val protectedHeader: CoseHeader = decodeProtectedHeader(plainProtectedHeader)

    /**
     * The `MAC_structure` bytes the [tag] is computed over, built from [plainProtectedHeader] as received.
     *
     * @param detachedPayload only to be set when [plainPayload] is `null`
     */
    fun macInput(
        externalAad: ByteArray = byteArrayOf(),
        detachedPayload: ByteArray? = null,
    ): ByteArray {
        val payload = if (detachedPayload != null) {
            require(plainPayload == null) { "Payload is not detached; detachedPayload must not be set" }
            detachedPayload
        } else plainPayload
        return structureInput(Context.Mac0, plainProtectedHeader, externalAad, payload)
    }

    fun serialize(): ByteArray = coseCompliantSerializer.encodeToByteArray(this)

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

        fun deserialize(input: ByteArray): KmmResult<CoseMac0> = catching {
            coseCompliantSerializer.decodeFromByteArray<CoseMac0>(input)
        }

        operator fun invoke(
            plainProtectedHeader: ByteArray,
            unprotectedHeader: CoseHeader? = null,
            plainPayload: ByteArray?,
            tag: ByteArray,
        ): CoseMac0 = CoseMac0(plainProtectedHeader, unprotectedHeader, plainPayload, tag)

        /** Encodes [protectedHeader] once and returns both the bytes to keep and the structure to MAC. */
        fun prepare(
            protectedHeader: CoseHeader,
            externalAad: ByteArray = byteArrayOf(),
            plainPayload: ByteArray?,
        ): CoseSign1.Companion.Prepared {
            val plainProtectedHeader = encodeProtectedHeader(protectedHeader)
            return CoseSign1.Companion.Prepared(
                plainProtectedHeader = plainProtectedHeader,
                signatureInput = structureInput(Context.Mac0, plainProtectedHeader, externalAad, plainPayload),
            )
        }
    }
}

/** Decodes the payload of a [CoseMac0] into [P], yielding the typed wrapper. */
inline fun <reified P> CoseMac0.typed(): CoseMac0Typed<P> = CoseTyped(this, getPayload<P>().getOrThrow())