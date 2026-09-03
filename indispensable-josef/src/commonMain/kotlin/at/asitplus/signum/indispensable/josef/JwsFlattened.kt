package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.contentEqualsIfArray
import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlNoPaddingSerializer
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject

/**
 * Flattened JSON JWS serialization.
 *
 * A flattened JWS carries one payload and one signature. The protected header is stored as encoded bytes in
 * [plainProtectedHeader]; the optional unprotected header is represented as a [JsonObject]. The effective header
 * and its member-placement metadata are exposed together through [wrappedHeader].
 *
 * Either header fragment may be partial. Only the combination of protected and unprotected parameters must
 * constitute a valid [JwsHeader].
 *
 * [plainPayload] stores the plain payload bytes. JSON serialization base64url-encodes those bytes for the `payload`
 * member, so callers should not pre-encode them.
 *
 *
 * If [plainPayload] data structure is defined as part of the contact consider [JwsFlattenedTyped]
 */
@ConsistentCopyVisibility
@Serializable
data class JwsFlattened internal constructor(
    @Serializable(ByteArrayBase64UrlNoPaddingSerializer::class)
    @SerialName(SerialNames.PROTECTED)
    val plainProtectedHeader: ByteArray? = null,
    @SerialName(SerialNames.HEADER)
    val unprotectedHeader: JsonObject? = null,
    @Serializable(ByteArrayBase64UrlNoPaddingSerializer::class)
    @SerialName(SerialNames.PAYLOAD)
    override val plainPayload: ByteArray,
    @Serializable(ByteArrayBase64UrlNoPaddingSerializer::class)
    @SerialName(SerialNames.SIGNATURE)
    val plainSignature: ByteArray
) : JWS() {

    init {
        plainProtectedHeader.requireAbsentIfEmptyProtectedHeader()
    }

    @Transient
    val wrappedHeader = JwsHeaderWrapped(plainProtectedHeader, unprotectedHeader)

    @Transient
    val signature = getSignature(wrappedHeader.header.algorithm, plainSignature)

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
        result = 31 * result + unprotectedHeader.hashCode()
        result = 31 * result + plainPayload.contentHashCode()
        result = 31 * result + plainSignature.contentHashCode()
        return result
    }

    companion object {
        /**
         * Creates a flattened JWS, placing the serialized [header] members named by [unprotectedMembers] in its
         * unprotected fragment.
         *
         * [payload] must be the plain payload bytes. Do not base64url-encode it before calling this overload;
         * flattened JSON serialization and signing input construction apply base64url encoding internally.
         */
        suspend operator fun invoke(
            header: JwsHeader,
            payload: ByteArray,
            unprotectedMembers: Set<String> = emptySet(),
            signer: suspend (ByteArray) -> ByteArray
        ): JwsFlattened {
            val serializedHeader = joseCompliantSerializer.encodeToJsonElement(header).jsonObject
            val plainProtectedHeader = JsonObject(serializedHeader.filterKeys { it !in unprotectedMembers })
                .takeUnless { it.isEmpty() }
                ?.toProtectedHeaderBytes()
            val unprotectedHeader = JsonObject(serializedHeader.filterKeys { it in unprotectedMembers })
                .takeUnless { it.isEmpty() }
            return JwsFlattened(
                plainProtectedHeader,
                unprotectedHeader,
                payload,
                signer(getSignatureInput(plainProtectedHeader, payload))
            )
        }
    }
}

@Deprecated(
    "Use plainProtectedHeader for the encoded protected fragment or wrappedHeader for the effective typed header."
)
val JwsFlattened.protectedHeader: JsonObject?
    get() = plainProtectedHeader?.toProtectedHeaderJsonObject()

/**
 * Converts flattened JSON serialization to compact serialization.
 *
 * This requires the absence of an unprotected header, because compact JWS can only carry protected parameters.
 * The protected fragment must therefore represent a valid [JwsHeader] by itself.
 */
fun JwsFlattened.toJwsCompact(): JwsCompact {
    require(unprotectedHeader == null) { "Compact Serialization does not support unprotected header" }
    requireNotNull(plainProtectedHeader)
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
