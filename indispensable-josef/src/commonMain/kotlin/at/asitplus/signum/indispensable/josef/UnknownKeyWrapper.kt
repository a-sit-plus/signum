package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.serializer

interface UnknownKeyWrapper<T> {
    val baseStructure: T
    val unknownKeys: JsonObject
    fun <G> getParameter(key: String, deserializer: KSerializer<G>): G? =
        unknownKeys[key]?.let {
            joseCompliantSerializer.decodeFromJsonElement(deserializer, it)
        }

    fun <D> getDataClass(deserializer: KSerializer<D>): D =
        joseCompliantSerializer.decodeFromJsonElement(deserializer, unknownKeys)
}

@Serializable(with = JwsHeaderAllKeysSerializer::class)
data class JwsHeaderAllKeys(
    override val baseStructure: JwsHeader,
    override val unknownKeys: JsonObject = JsonObject(mapOf()),
) : UnknownKeyWrapper<JwsHeader>


@Serializable(with = JsonWebTokenAllKeysSerializer::class)
data class JsonWebTokenAllKeys(
    override val baseStructure: JsonWebToken,
    override val unknownKeys: JsonObject = JsonObject(mapOf()),
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

inline fun <reified D> UnknownKeyWrapper<*>.getDataClass(): D =
    getDataClass(joseCompliantSerializer.serializersModule.serializer())
