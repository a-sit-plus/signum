package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.contentEqualsIfArray
import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlNoPaddingSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient

/**
 * Flattened JSON JWS serialization.
 *
 * A flattened JWS carries one payload and one signature. The protected header is stored as encoded bytes in
 * [plainProtectedHeader]; the optional unprotected header is represented as [JwsHeader.Part]. The effective
 * [jwsHeader] is reconstructed by merging both fragments with [JwsHeader.fromParts].
 *
 * Either header fragment may be partial. Only the combination of protected and unprotected parameters must
 * constitute a valid [JwsHeader].
 */
@Serializable
data class JwsFlattened(
    @Serializable(ByteArrayBase64UrlNoPaddingSerializer::class)
    @SerialName(SerialNames.PROTECTED)
    val plainProtectedHeader: ByteArray? = null,
    @SerialName(SerialNames.HEADER)
    val unprotectedHeader: JwsHeader.Part? = null,
    @Serializable(ByteArrayBase64UrlNoPaddingSerializer::class)
    @SerialName(SerialNames.PAYLOAD)
    override val plainPayload: ByteArray,
    @Serializable(ByteArrayBase64UrlNoPaddingSerializer::class)
    @SerialName(SerialNames.SIGNATURE)
    val plainSignature: ByteArray
) : JWS() {

    @Transient
    val jwsHeader = JwsHeader.fromParts(plainProtectedHeader, unprotectedHeader)

    @Transient
    val signature = getSignature(jwsHeader.algorithm, plainSignature)

    @Transient
    val signatureInput = getSignatureInput(plainProtectedHeader, plainPayload)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as JwsFlattened

        if (!plainProtectedHeader.contentEquals(other.plainProtectedHeader)) return false
        if (unprotectedHeader != other.unprotectedHeader) return false
        if (!plainPayload.contentEquals(other.plainPayload)) return false
        if (!plainSignature.contentEquals(other.plainSignature)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = plainProtectedHeader?.contentHashCode() ?: 0
        result = 31 * result + (unprotectedHeader?.hashCode() ?: 0)
        result = 31 * result + plainPayload.contentHashCode()
        result = 31 * result + plainSignature.contentHashCode()
        return result
    }

    companion object {
        /**
         * Creates a flattened JWS from protected and unprotected header fragments.
         *
         * The fragments may be partial, but their merged content must form a valid [JwsHeader].
         */
        suspend operator fun invoke(
            protectedHeader: JwsHeader.Part?,
            unprotectedHeader: JwsHeader.Part?,
            payload: ByteArray,
            signer: suspend (ByteArray) -> ByteArray
        ): JwsFlattened {
            val plainProtectedHeader = protectedHeader?.let { JwsProtectedHeaderSerializer.encodeToByteArray(it) }
            return JwsFlattened(
                plainProtectedHeader,
                unprotectedHeader,
                payload,
                signer(getSignatureInput(plainProtectedHeader, payload))
            )
        }
    }
}

/**
 * Converts flattened JSON serialization to compact serialization.
 *
 * This requires the absence of an unprotected header, because compact JWS can only carry protected parameters.
 * The protected fragment must therefore represent a valid [JwsHeader] by itself.
 */
fun JwsFlattened.toJwsCompact(): JwsCompact {
    require(unprotectedHeader == null) { "Compact Serialization does not support unprotected header" }
    requireNotNull(plainProtectedHeader)
    runCatching { JwsHeader.fromParts(plainProtectedHeader) }.getOrElse { throw IllegalArgumentException("Compact JWS requires protected header to be a valid JwsHeader") }
    return JwsCompact(
        plainProtectedHeader = plainProtectedHeader,
        plainPayload = plainPayload,
        plainSignature = plainSignature,
    )
}

/**
 * Converts multiple flattened JWS values with the same payload into general JSON JWS representation.
 */
fun List<JwsFlattened>.toJwsGeneral(): JwsGeneral {
    require(isNotEmpty()) { "General JWS requires at least one signature" }
    val payload = this[0].plainPayload
    val signatures = this.map {
        require(payload.contentEqualsIfArray(it.plainPayload)) {
            "Additional signed JWS payload must match existing payload"
        }
        SignatureElement(
            plainSignature = it.plainSignature,
            plainProtectedHeader = it.plainProtectedHeader,
            unprotectedHeader = it.unprotectedHeader,
        )
    }
    return JwsGeneral(
        plainPayload = payload,
        signatureElements = signatures
    )
}
