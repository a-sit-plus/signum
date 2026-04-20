package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.serializer

interface UnknownKeyWrapper<T> {
    val baseStructure: T
    val unknownKeys: Map<String, JsonElement>
    fun <G> getParameter(key: String, deserializer: KSerializer<G>): G? =
        unknownKeys[key]?.let {
            joseCompliantSerializer.decodeFromJsonElement(deserializer, it)
        }
}

@Serializable(with = JwsHeaderAllKeysSerializer::class)
data class JwsHeaderAllKeys(
    override val baseStructure: JwsHeader,
    override val unknownKeys: Map<String, JsonElement> = emptyMap(),
) : UnknownKeyWrapper<JwsHeader>


@Serializable(with = JsonWebTokenAllKeysSerializer::class)
data class JsonWebTokenAllKeys(
    override val baseStructure: JsonWebToken,
    override val unknownKeys: Map<String, JsonElement> = emptyMap(),
) : UnknownKeyWrapper<JsonWebToken>

object JwsHeaderAllKeysSerializer : KSerializer<JwsHeaderAllKeys> by UnknownKeyWrapperTransformingSerializer(
    structSerializer = JwsHeader.serializer(),
    wrap = ::JwsHeaderAllKeys,
)

object JsonWebTokenAllKeysSerializer : KSerializer<JsonWebTokenAllKeys> by UnknownKeyWrapperTransformingSerializer(
    structSerializer = JsonWebToken.serializer(),
    wrap = ::JsonWebTokenAllKeys,
)

inline fun <reified G> UnknownKeyWrapper<*>.getParameter(key: String): G? =
    getParameter(key, joseCompliantSerializer.serializersModule.serializer())
