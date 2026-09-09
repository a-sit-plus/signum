package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.decodeFromJsonElement

/**
 * Type-safe (one-way) view of an effective [JwsHeader] together with the names of the members in its unprotected fragment.
 *
 * Header fragments are owned by the concrete [JWS] representation.
 */
@ConsistentCopyVisibility
data class JwsHeaderWrapped internal constructor(
    val header: JwsHeader,
    val unprotectedMembers: Set<String>,
) {

    internal constructor(
        protectedHeader: ByteArray?,
        unprotectedHeader: JsonObject?
    ) : this(
        joseCompliantSerializer
            .decodeFromJsonElement<JwsHeader>(
                protectedHeader?.toProtectedHeaderJsonObject().strictUnion(
                    unprotectedHeader
                )
            ),
        unprotectedHeader?.keys ?: emptySet()
    )
}

internal fun ByteArray.toProtectedHeaderJsonObject(): JsonObject =
    joseCompliantSerializer.decodeFromString(JsonObject.serializer(), decodeToString())