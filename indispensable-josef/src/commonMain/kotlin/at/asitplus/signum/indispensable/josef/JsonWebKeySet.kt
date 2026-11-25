package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
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

    
    @Deprecated("To be removed in next release")
    @Throws(Throwable::class)
    fun serialize() =
        joseCompliantSerializer.encodeToString(this)

    companion object {

        @Deprecated("To be removed in next release")
        @Throws(Throwable::class)
        fun deserialize(it: String) =
            joseCompliantSerializer.decodeFromString<JsonWebKeySet>(it)
    }

}
