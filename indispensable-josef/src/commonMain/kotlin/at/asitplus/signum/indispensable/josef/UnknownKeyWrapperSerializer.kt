package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlin.collections.component1
import kotlin.collections.component2

class UnknownKeyWrapperTransformingSerializer<T, U : UnknownKeyWrapper<T>>(
    val structSerializer: KSerializer<T>,
    private val wrap: (knownStructure: T, unknownKeys: Map<String, JsonElement>) -> U,
    private val serialNames: Set<String> = structSerializer.topLevelSerialNames(),
) : TransformingSerializerTemplate<U, JsonObject>(
    parent = JsonObject.serializer(),
    encodeAs = { value ->
        val overlappingKeys = value.unknownKeys.keys.intersect(serialNames)
        require(overlappingKeys.isEmpty()) {
            "unknownKeys must not contain known keys: ${overlappingKeys.sorted().joinToString()}"
        }

        val knownKeys =
            joseCompliantSerializer.encodeToJsonElement(structSerializer, value.baseStructure) as JsonObject
        buildJsonObject {
            value.unknownKeys.forEach { (key, jsonElement) -> put(key, jsonElement) }
            knownKeys.forEach { (key, jsonElement) -> put(key, jsonElement) }
        }
    },
    decodeAs = { jsonObject ->
        val knownStructure = joseCompliantSerializer.decodeFromJsonElement(structSerializer, jsonObject)
        val unknownKeys = jsonObject.filterKeys { it !in serialNames }
        wrap(knownStructure, unknownKeys)
    },
    serialName = "${structSerializer.descriptor.serialName}AllKeys",
)

private fun KSerializer<*>.topLevelSerialNames(): Set<String> =
    (0 until descriptor.elementsCount)
        .map(descriptor::getElementName)
        .toSet()
