package at.asitplus.signum.indispensable.josef

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement

interface UnknownKeyWrapper<T> {
    val baseStructure: T
    val unknownKeys: Map<String, JsonElement>
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
