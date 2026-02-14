package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.Asn1Element
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException

internal typealias Asn1TagDiscriminatedSubtypeRegistration<T> =
        Asn1TagDiscriminatedOpenPolymorphicSerializer.SubtypeRegistration<T>

/**
 * Shared strict dispatch table for tag-discriminated ASN.1 polymorphism.
 *
 * - decode dispatches by exact leading tag
 * - encode dispatches by exactly one runtime match
 * - duplicate tag registrations are rejected
 */
internal class Asn1TagDiscriminatedDispatch<T : Any>(
    private val serialName: String,
    subtypes: List<Asn1TagDiscriminatedSubtypeRegistration<T>>,
) {
    private val registrations = mutableListOf<Asn1TagDiscriminatedSubtypeRegistration<T>>()
    private val serializersByTag = linkedMapOf<Asn1Element.Tag, KSerializer<out T>>()

    val leadingTags: Set<Asn1Element.Tag>
        get() = serializersByTag.keys

    init {
        require(subtypes.isNotEmpty()) { "At least one subtype registration is required" }
        subtypes.forEach(::registerSubtype)
    }

    fun registerSubtype(registration: Asn1TagDiscriminatedSubtypeRegistration<T>) {
        require(registration.leadingTags.isNotEmpty()) {
            "Subtype '${registration.debugName}' must declare at least one leading ASN.1 tag"
        }
        registration.leadingTags.forEach { tag ->
            val existing = serializersByTag[tag]
            if (existing != null) {
                throw IllegalArgumentException(
                    "Duplicate tag mapping for $tag in $serialName: " +
                            "${existing.descriptor.serialName} and ${registration.serializer.descriptor.serialName}"
                )
            }
        }
        registrations += registration
        registration.leadingTags.forEach { tag ->
            serializersByTag[tag] = registration.serializer
        }
    }

    fun serializerForDecodeOrNull(tag: Asn1Element.Tag): KSerializer<out T>? =
        serializersByTag[tag]

    fun serializerForDecode(tag: Asn1Element.Tag): KSerializer<out T> =
        serializerForDecodeOrNull(tag)
            ?: throw SerializationException(
                "No registered open-polymorphic subtype in $serialName for leading tag $tag"
            )

    fun serializerForEncode(value: T): KSerializer<out T> {
        val matches = registrations.filter { it.matches(value) }
        return when (matches.size) {
            1 -> matches.single().serializer
            0 -> throw SerializationException(
                "No registered open-polymorphic subtype matches runtime value ${value::class} for $serialName"
            )

            else -> throw SerializationException(
                "Multiple registered open-polymorphic subtypes match runtime value ${value::class} " +
                        "for $serialName: ${matches.joinToString { it.debugName }}"
            )
        }
    }

}
