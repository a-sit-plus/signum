package at.asitplus.signum.indispensable.cosef

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.cosef.io.Base16Strict
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.CborArray
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

/**
 * Representation of a signed `COSE_Sign1/COSE_MAC0` object, i.e. consisting of protected header, unprotected header and payload.
 * It represents the bytes of the object as it has been transferred, i.e. useful for signature/hmac verification.
 *
 * For the class using typed payloads, see [CoseSigned] and [CoseMac].
 *
 * See [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html).
 */
@Serializable
@CborArray
@ConsistentCopyVisibility
data class CoseBytes internal constructor(
    /**
     * Content of the protected header byte string, i.e. the encoded [protectedHeader] exactly as it has been
     * transferred (zero-length for an empty protected header encoded as `h''`).
     * These bytes are used for the `Sig_structure`/`MAC_structure` and for serialization, as required by
     * [RFC 9052 Section 4.4](https://www.rfc-editor.org/rfc/rfc9052.html#section-4.4): re-encoding the parsed
     * [protectedHeader] does not necessarily reproduce the authenticated bytes (e.g. due to a different key order).
     *
     * When creating a new object (see [CoseSigned.create], [CoseMac.create]), this is the encoding of [protectedHeader].
     */
    @SerialName("protectedHeader")
    @ByteString
    val rawProtectedHeader: ByteArray,
    val unprotectedHeader: CoseHeader?,
    @ByteString
    val payload: ByteArray?,
    @ByteString
    val rawAuthBytes: ByteArray,
) {

    internal constructor(
        protectedHeader: CoseHeader,
        unprotectedHeader: CoseHeader?,
        payload: ByteArray?,
        rawAuthBytes: ByteArray,
    ) : this(protectedHeader.toProtectedHeaderBytes(), unprotectedHeader, payload, rawAuthBytes)

    /**
     * Parsed from [rawProtectedHeader], also on deserialization, so that malformed headers are rejected right away.
     */
    @Transient
    val protectedHeader: CoseHeader = rawProtectedHeader.toProtectedCoseHeader()

    internal fun toCoseSignatureInput(
        externalAad: ByteArray = byteArrayOf(),
        detachedPayload: ByteArray? = null,
    ): ByteArray = toCoseInput(externalAad, detachedPayload, "Signature1")

    internal fun toCoseMacInput(
        externalAad: ByteArray = byteArrayOf(),
        detachedPayload: ByteArray? = null,
    ): ByteArray = toCoseInput(externalAad, detachedPayload, "MAC0")

    /**
     * Uses [rawProtectedHeader] (and not a re-encoding of [protectedHeader]) as `body_protected`.
     *
     * @param detachedPayload only to be set when [payload] is null, i.e. it is transported externally,
     * as it ignores the [payload] member
     */
    private fun toCoseInput(
        externalAad: ByteArray = byteArrayOf(),
        detachedPayload: ByteArray? = null,
        contextString: String
    ): ByteArray = CoseInputBytes(
        contextString = contextString,
        protectedHeader = rawProtectedHeader,
        externalAad = externalAad,
        payload = if (detachedPayload != null) {
            require(payload == null)
            detachedPayload
        } else payload,
    ).run {
        coseCompliantSerializer.encodeToByteArray(this)
    }

    @Deprecated("To be removed in next release")
    fun serialize(): ByteArray = coseCompliantSerializer.encodeToByteArray(this)

    /**
     * Compares the protected header by its [rawProtectedHeader], i.e. the bytes that are authenticated.
     */
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as CoseBytes

        if (!rawProtectedHeader.contentEquals(other.rawProtectedHeader)) return false
        if (unprotectedHeader != other.unprotectedHeader) return false
        if (!payload.contentEquals(other.payload)) return false
        if (!rawAuthBytes.contentEquals(other.rawAuthBytes)) return false

        return true
    }

    // unprotectedHeader is left out, as CoseHeader.hashCode() is not content-based for its certificate chain
    override fun hashCode(): Int {
        var result = rawProtectedHeader.contentHashCode()
        result = 31 * result + (payload?.contentHashCode() ?: 0)
        result = 31 * result + rawAuthBytes.contentHashCode()
        return result
    }

    override fun toString(): String {
        return "CoseSigned(protectedHeader=$protectedHeader," +
                " unprotectedHeader=$unprotectedHeader," +
                " payload=${payload?.encodeToString(Base16Strict)}," +
                " authBytes=${rawAuthBytes.encodeToString(Base16Strict)})"
    }

    companion object {

        @Deprecated("To be removed in next release")
        fun deserialize(it: ByteArray): KmmResult<CoseBytes> = catching {
            coseCompliantSerializer.decodeFromByteArray(it)
        }
    }
}

/**
 * `Sig_structure`/`MAC_structure` with an already encoded protected header,
 * see [RFC 9052 Section 4.4](https://www.rfc-editor.org/rfc/rfc9052.html#section-4.4).
 */
@Serializable
@CborArray
private class CoseInputBytes(
    val contextString: String,
    @ByteString
    val protectedHeader: ByteArray,
    @ByteString
    val externalAad: ByteArray,
    @ByteString
    val payload: ByteArray?,
)
