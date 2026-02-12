package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.TagClass
import kotlinx.serialization.SerializationException
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.descriptors.PolymorphicKind
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.SerialKind
import kotlinx.serialization.descriptors.StructureKind

private data class Asn1FieldShape(
    val index: Int,
    val name: String,
    val omittable: Boolean,
    val possibleLeadingTags: Set<Asn1Element.Tag>?,
)

private val Asn1StringTags: Set<Asn1Element.Tag> = setOf(
    Asn1Element.Tag.STRING_UTF8,
    Asn1Element.Tag.STRING_BMP,
    Asn1Element.Tag.STRING_NUMERIC,
    Asn1Element.Tag.STRING_T61,
    Asn1Element.Tag.STRING_VISIBLE,
    Asn1Element.Tag.STRING_UNIVERSAL,
    Asn1Element.Tag.STRING_PRINTABLE,
    Asn1Element.Tag.STRING_IA5,
    Asn1Element.Tag.STRING_GENERAL,
    Asn1Element.Tag.STRING_GRAPHIC,
    Asn1Element.Tag.STRING_UNRESTRICTED,
    Asn1Element.Tag.STRING_VIDEOTEX,
)

internal fun SerialDescriptor.ensureNoAsn1AmbiguousOptionalLayout() {
    if (kind !is StructureKind.CLASS && kind !is StructureKind.OBJECT) return

    val fields = (0 until elementsCount).map { index ->
        val fieldDescriptor = getElementDescriptor(index)
        val propertyAsn1nnotation = asn1nnotation(index)
        val omittableByNull = fieldDescriptor.isNullable &&
                propertyAsn1nnotation?.encodeNull != true &&
                fieldDescriptor.asn1nnotation?.encodeNull != true
        val omittable = omittableByNull || isElementOptional(index)
        Asn1FieldShape(
            index = index,
            name = getElementName(index),
            omittable = omittable,
            possibleLeadingTags = possibleLeadingTags(
                descriptor = fieldDescriptor,
                propertyAsn1nnotation = propertyAsn1nnotation
            )
        )
    }

    for (start in fields.indices) {
        val nullableOrOptionalField = fields[start]
        val firstTags = nullableOrOptionalField.possibleLeadingTags ?: continue
        if (!nullableOrOptionalField.omittable || firstTags.isEmpty()) continue

        var allSkippedFieldsAreOmittable = true
        for (candidate in (start + 1) until fields.size) {
            allSkippedFieldsAreOmittable =
                allSkippedFieldsAreOmittable && fields[candidate - 1].omittable
            if (!allSkippedFieldsAreOmittable) break

            val candidateField = fields[candidate]
            val candidateTags = candidateField.possibleLeadingTags ?: continue
            val overlap = firstTags intersect candidateTags
            if (overlap.isNotEmpty()) {
                throw SerializationException(
                    "Ambiguous ASN.1 layout for $serialName: " +
                            "property '${nullableOrOptionalField.name}' (index ${nullableOrOptionalField.index}) " +
                            "can be omitted and shares possible tag(s) ${formatTags(overlap)} with " +
                            "property '${candidateField.name}' (index ${candidateField.index}). " +
                            "Add disambiguating @Asn1nnotation layers or set encodeNull=true for nullable fields."
                )
            }
        }
    }
}

internal fun SerialDescriptor.possibleLeadingTagsForAsn1(
    propertyAsn1nnotation: Asn1nnotation? = null,
): Set<Asn1Element.Tag>? = possibleLeadingTags(
    descriptor = this,
    propertyAsn1nnotation = propertyAsn1nnotation,
)

private fun possibleLeadingTags(
    descriptor: SerialDescriptor,
    propertyAsn1nnotation: Asn1nnotation?,
    inheritedBitString: Boolean = false,
    forcedChoice: Boolean? = null,
): Set<Asn1Element.Tag>? {
    val allLayers = (propertyAsn1nnotation?.layers?.toList() ?: emptyList()) + descriptor.annotations.asn1Layers

    val isBitString = inheritedBitString || propertyAsn1nnotation?.asBitString == true || descriptor.isAsn1BitString
    val choiceMode = forcedChoice ?: (propertyAsn1nnotation?.asChoice == true || descriptor.asn1nnotation?.asChoice == true)

    val baseTags = possibleBaseLeadingTags(
        descriptor = descriptor,
        isBitString = isBitString,
        choiceMode = choiceMode,
    ) ?: return null

    return applyLayers(baseTags, allLayers)
}

private fun possibleBaseLeadingTags(
    descriptor: SerialDescriptor,
    isBitString: Boolean,
    choiceMode: Boolean,
): Set<Asn1Element.Tag>? {
    if (descriptor.isInline && descriptor.elementsCount == 1) {
        return possibleLeadingTags(
            descriptor = descriptor.getElementDescriptor(0),
            propertyAsn1nnotation = null,
            inheritedBitString = isBitString,
            forcedChoice = choiceMode,
        )
    }

    if (descriptor == ByteArraySerializer().descriptor) {
        return setOf(
            if (isBitString) Asn1Element.Tag.BIT_STRING
            else Asn1Element.Tag.OCTET_STRING
        )
    }

    return when (descriptor.kind) {
        PrimitiveKind.BOOLEAN -> setOf(Asn1Element.Tag.BOOL)
        PrimitiveKind.BYTE,
        PrimitiveKind.SHORT,
        PrimitiveKind.INT,
        PrimitiveKind.LONG -> setOf(Asn1Element.Tag.INT)

        PrimitiveKind.FLOAT,
        PrimitiveKind.DOUBLE -> setOf(Asn1Element.Tag.REAL)

        PrimitiveKind.CHAR,
        PrimitiveKind.STRING -> Asn1StringTags

        SerialKind.ENUM -> setOf(Asn1Element.Tag.INT)

        is StructureKind.CLASS,
        is StructureKind.OBJECT -> setOf(if (descriptor.isSetDescriptor) Asn1Element.Tag.SET else Asn1Element.Tag.SEQUENCE)

        is StructureKind.LIST,
        is StructureKind.MAP -> setOf(Asn1Element.Tag.SEQUENCE)

        is PolymorphicKind.OPEN -> setOf(Asn1Element.Tag.SEQUENCE)
        is PolymorphicKind.SEALED -> {
            if (choiceMode) possibleSealedChoiceAlternativeLeadingTags(descriptor)
            else setOf(Asn1Element.Tag.SEQUENCE)
        }

        else -> null
    }
}

internal fun SerialDescriptor.findLikelySealedAlternativesDescriptor(): SerialDescriptor? =
    (0 until elementsCount)
        .map { getElementDescriptor(it) }
        .filter { it.elementsCount > 0 }
        .maxByOrNull { it.elementsCount }

private fun possibleSealedChoiceAlternativeLeadingTags(descriptor: SerialDescriptor): Set<Asn1Element.Tag>? {
    val alternativesDescriptor = descriptor.findLikelySealedAlternativesDescriptor() ?: return null
    val alternativeTags = mutableSetOf<Asn1Element.Tag>()

    for (i in 0 until alternativesDescriptor.elementsCount) {
        val alternativeDescriptor = alternativesDescriptor.getElementDescriptor(i)
        val tags = possibleLeadingTags(
            descriptor = alternativeDescriptor,
            propertyAsn1nnotation = null,
            forcedChoice = alternativeDescriptor.asn1nnotation?.asChoice == true,
        ) ?: return null
        alternativeTags += tags
    }

    return alternativeTags.takeIf { it.isNotEmpty() }
}

private fun applyLayers(
    baseTags: Set<Asn1Element.Tag>,
    layers: List<Layer>,
): Set<Asn1Element.Tag> {
    if (layers.isEmpty()) return baseTags

    val innerTags = applyLayers(baseTags, layers.drop(1))
    val current = layers.first()

    return when (current.type) {
        Type.OCTET_STRING -> setOf(Asn1Element.Tag.OCTET_STRING)
        Type.EXPLICIT_TAG -> setOf(Asn1Element.Tag(current.tag, constructed = true, tagClass = TagClass.CONTEXT_SPECIFIC))
        Type.IMPLICIT_TAG -> innerTags.map {
            Asn1Element.Tag(current.tag, constructed = it.isConstructed, tagClass = TagClass.CONTEXT_SPECIFIC)
        }.toSet()
    }
}

private fun formatTags(tags: Set<Asn1Element.Tag>): String = tags
    .sortedWith(compareBy<Asn1Element.Tag>({ it.tagClass.ordinal }, { it.tagValue }, { it.isConstructed }))
    .joinToString(prefix = "[", postfix = "]") { formatTag(it) }

private fun formatTag(tag: Asn1Element.Tag): String =
    "${tag.tagClass}:${tag.tagValue}${if (tag.isConstructed) "/C" else "/P"}"
