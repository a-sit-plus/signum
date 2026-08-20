package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject

/**
 * An effective [JwsHeader] together with the names of the members carried in its unprotected fragment.
 *
 * Member placement belongs to a concrete JSON JWS representation rather than to [JwsHeader] itself.
 */
data class JwsHeaderWrapped(
    val header: JwsHeader,
    val unprotectedMembers: Set<String> = emptySet(),
) {
    private val serializedHeader: JsonObject =
        joseCompliantSerializer.encodeToJsonElement(header).jsonObject

    /** Names requested as unprotected that are represented by the modeled [header]. */
    val effectiveUnprotectedMembers: Set<String> =
        unprotectedMembers intersect serializedHeader.keys

    fun toProtectedHeader(): ByteArray =
        JsonObject(serializedHeader.filterKeys { it !in effectiveUnprotectedMembers }).toProtectedHeaderBytes()

    fun toUnprotectedHeader(): JsonObject =
        JsonObject(serializedHeader.filterKeys { it in effectiveUnprotectedMembers })

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is JwsHeaderWrapped) return false

        if (header != other.header) return false
        if (effectiveUnprotectedMembers != other.effectiveUnprotectedMembers) return false

        return true
    }

    override fun hashCode(): Int {
        var result = header.hashCode()
        result = 31 * result + effectiveUnprotectedMembers.hashCode()
        return result
    }
}
