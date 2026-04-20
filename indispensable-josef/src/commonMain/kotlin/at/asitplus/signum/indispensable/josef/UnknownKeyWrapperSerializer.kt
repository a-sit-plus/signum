package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.JsonObject

class UnknownKeyWrapperTransformingSerializer<T, U : UnknownKeyWrapper<T>>(
    val structSerializer: KSerializer<T>,
    private val wrap: (knownStructure: T, unknownKeys: JsonObject) -> U,
    private val serialNames: Set<String> = structSerializer.topLevelSerialNames(),
) : TransformingSerializerTemplate<U, JsonObject>(
    parent = JsonObject.serializer(),
    encodeAs = { value ->
        val knownKeys = joseCompliantSerializer.encodeToJsonElement(structSerializer, value.baseStructure) as JsonObject
        knownKeys.strictUnion(value.unknownKeys)
    },
    decodeAs = { jsonObject ->
        val knownStructure = joseCompliantSerializer.decodeFromJsonElement(structSerializer, jsonObject)
        val unknownKeys = JsonObject(jsonObject.filterKeys { it !in serialNames })
        wrap(knownStructure, unknownKeys)
    },
    serialName = "${structSerializer.descriptor.serialName}AllKeys",
)

private fun KSerializer<*>.topLevelSerialNames(): Set<String> =
    (0 until descriptor.elementsCount)
        .map(descriptor::getElementName)
        .toSet()
