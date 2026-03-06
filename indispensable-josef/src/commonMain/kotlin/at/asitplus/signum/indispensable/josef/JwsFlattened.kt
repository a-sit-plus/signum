package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.contentEqualsIfArray
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import kotlinx.serialization.Transient
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.decodeFromJsonElement


data class JwsFlattened(
    val plainProtectedHeader: ByteArray? = null,
    val unprotectedHeader: JsonObject? = null,
    val payload: ByteArray,
    val plainSignature: ByteArray
) {

    @Transient
    private val protectedHeader: JsonObject? =
        plainProtectedHeader?.let { joseCompliantSerializer.decodeFromString(it.decodeToString()) }

    /**
     * Only the combined header must be a valid [JwsHeader]
     */
    @Transient
    val combinedHeader: JwsHeader =
        joseCompliantSerializer.decodeFromJsonElement(unprotectedHeader.strictUnion(protectedHeader))

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as JwsFlattened

        if (!plainProtectedHeader.contentEquals(other.plainProtectedHeader)) return false
        if (unprotectedHeader != other.unprotectedHeader) return false
        if (!payload.contentEquals(other.payload)) return false
        if (!plainSignature.contentEquals(other.plainSignature)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = plainProtectedHeader?.contentHashCode() ?: 0
        result = 31 * result + (unprotectedHeader?.hashCode() ?: 0)
        result = 31 * result + payload.contentHashCode()
        result = 31 * result + plainSignature.contentHashCode()
        return result
    }
}

fun JwsFlattened.toJwsCompact(): JwsCompact =
    JwsCompact(
        protected = plainProtectedHeader!!,
        payload = payload,
        signature = plainSignature,
    )

fun List<JwsFlattened>.toJwsGeneral(): JwsGeneral {
    val payload = this[0].payload
    val signatures = this.map {
        require(payload.contentEqualsIfArray(it.payload)) {
            "Additional signed JWS payload must match existing payload"
        }
        SignatureElement(
            plainSignature = it.plainSignature,
            plainProtectedHeader = it.plainProtectedHeader,
            unprotectedHeader = it.unprotectedHeader,
        )
    }
    return JwsGeneral(
        payload = payload,
        signatures = signatures
    )
}