package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject

/**
 * An effective [JwsHeader] together with the names of the members carried in its unprotected fragment.
 *
 * Member placement belongs to a concrete JSON JWS representation rather than to [JwsHeader] itself.
 */
data class JwsHeaderWrapped(
    val header: JwsHeader,
    val unprotectedMembers: List<String> = emptyList(),
) {
    fun toProtectedHeader(): ByteArray =
        JsonObject(serializedHeader().filterKeys { it !in unprotectedMembers }).toProtectedHeaderBytes()

    fun toUnprotectedHeader(): JsonObject =
        JsonObject(serializedHeader().filterKeys { it in unprotectedMembers })

    private fun serializedHeader(): JsonObject =
        joseCompliantSerializer.encodeToJsonElement(header).jsonObject
}
