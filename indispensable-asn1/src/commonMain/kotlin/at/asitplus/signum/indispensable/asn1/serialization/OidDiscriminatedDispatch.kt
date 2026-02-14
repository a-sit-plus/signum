package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.IdentifiedBy
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException

internal typealias Asn1OidDiscriminatedSubtypeRegistration<T> =
        Asn1OidDiscriminatedOpenPolymorphicSerializer.SubtypeRegistration<T>

/**
 * Shared strict dispatch table for OID-discriminated ASN.1 open polymorphism.
 *
 * - decode dispatches by exact ObjectIdentifier
 * - encode dispatches by value.oid
 * - duplicate OID registrations are rejected
 */
internal class Asn1OidDiscriminatedDispatch<T : IdentifiedBy<*>>(
    private val serialName: String,
    subtypes: List<Asn1OidDiscriminatedSubtypeRegistration<T>>,
) {
    private val serializersByOid = linkedMapOf<ObjectIdentifier, KSerializer<out T>>()
    private val tagsByOid = linkedMapOf<ObjectIdentifier, Set<Asn1Element.Tag>>()

    val leadingTags: Set<Asn1Element.Tag>
        get() = tagsByOid.values.flatten().toSet()

    init {
        require(subtypes.isNotEmpty()) { "At least one subtype registration is required" }
        subtypes.forEach(::registerSubtype)
    }

    fun registerSubtype(registration: Asn1OidDiscriminatedSubtypeRegistration<T>) {
        require(registration.leadingTags.isNotEmpty()) {
            "Subtype '${registration.debugName}' must declare at least one leading ASN.1 tag"
        }

        val existing = serializersByOid[registration.oid]
        if (existing != null) {
            throw IllegalArgumentException(
                "Duplicate OID mapping for ${registration.oid} in $serialName: " +
                        "${existing.descriptor.serialName} and ${registration.serializer.descriptor.serialName}"
            )
        }

        serializersByOid[registration.oid] = registration.serializer
        tagsByOid[registration.oid] = registration.leadingTags
    }

    fun serializerForDecodeOrNull(oid: ObjectIdentifier): KSerializer<out T>? =
        serializersByOid[oid]

    fun serializerForDecode(oid: ObjectIdentifier): KSerializer<out T> =
        serializerForDecodeOrNull(oid)
            ?: throw SerializationException(
                "No registered open-polymorphic subtype in $serialName for OID $oid"
            )

    fun serializerForEncode(value: T): KSerializer<out T> {
        return serializerForDecodeOrNull(value.oid)
            ?: throw SerializationException(
                "No registered open-polymorphic subtype in $serialName for runtime OID ${value.oid} " +
                        "(value type: ${value::class})"
            )
    }
}
