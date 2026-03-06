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