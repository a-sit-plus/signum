package at.asitplus.crypto.datatypes.jws

import at.asitplus.crypto.datatypes.jws.io.jsonSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString

/**
 * JSON Web Key Set as per [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517#section-5)
 */
@Serializable
data class JsonWebKeySet(
    @SerialName("keys")
    val keys: Collection<JsonWebKey>,
) {

    fun serialize() = kotlin.runCatching {
        jsonSerializer.encodeToString(this)
    }.getOrNull()

    companion object {
        fun deserialize(it: String) = kotlin.runCatching {
            jsonSerializer.decodeFromString<JsonWebKeySet>(it)
        }.getOrNull()
    }

}