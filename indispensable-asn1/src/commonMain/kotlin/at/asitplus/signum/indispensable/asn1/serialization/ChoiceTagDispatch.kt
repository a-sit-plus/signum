package at.asitplus.signum.indispensable.asn1.serialization

import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.SerialDescriptor

internal fun <T : Any> buildSealedChoiceDispatch(
    ownerSerialName: String,
    alternativesDescriptor: SerialDescriptor,
    resolveSerializerByName: (String) -> KSerializer<out T>?,
    resolveRuntimeSerializer: ((T) -> KSerializer<out T>?)? = null,
): Asn1TagDiscriminatedDispatch<T> {
    val registrations = mutableListOf<Asn1TagDiscriminatedSubtypeRegistration<T>>()

    for (i in 0 until alternativesDescriptor.elementsCount) {
        val alternativeSerialName = alternativesDescriptor.getElementName(i)
        val alternativeSerializer = resolveSerializerByName(alternativeSerialName)
            ?: throw SerializationException(
                "Could not resolve serializer for CHOICE alternative '$alternativeSerialName' in $ownerSerialName"
            )

        val alternativeDescriptor = alternativesDescriptor.getElementDescriptor(i)
        val leadingTags = when (val resolution = alternativeDescriptor.possibleLeadingTagsForAsn1(
            propertyAsChoice = alternativeDescriptor.isSealed,
        )) {
            is Asn1LeadingTagsResolution.Exact -> resolution.tags
            Asn1LeadingTagsResolution.UnknownInfer -> throw SerializationException(
                "Undecidable CHOICE tag dispatch for alternative '$alternativeSerialName' in $ownerSerialName: " +
                        "${resolution.reason()}. Add disambiguating ASN.1 tags."
            )
        }

        val matches: (T) -> Boolean = if (resolveRuntimeSerializer == null) {
            { false }
        } else {
            { value ->
                resolveRuntimeSerializer(value)?.descriptor?.serialName ==
                        alternativeSerializer.descriptor.serialName
            }
        }

        registrations += Asn1TagDiscriminatedSubtypeRegistration(
            serializer = alternativeSerializer,
            leadingTags = leadingTags,
            matches = matches,
            debugName = alternativeSerializer.descriptor.serialName,
        )
    }

    return try {
        Asn1TagDiscriminatedDispatch(
            serialName = ownerSerialName,
            subtypes = registrations,
        )
    } catch (illegal: IllegalArgumentException) {
        throw SerializationException(
            "Ambiguous CHOICE tag dispatch for $ownerSerialName: ${illegal.message}"
        )
    }
}
