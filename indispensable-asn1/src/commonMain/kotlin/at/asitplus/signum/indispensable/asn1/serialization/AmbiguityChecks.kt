package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.Asn1Element
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
    val possibleLeadingTagNumbers: Set<ULong>?,
)

private val Asn1StringTagNumbers: Set<ULong> = setOf(
    Asn1Element.Tag.STRING_UTF8.tagValue,
    Asn1Element.Tag.STRING_BMP.tagValue,
    Asn1Element.Tag.STRING_NUMERIC.tagValue,
    Asn1Element.Tag.STRING_T61.tagValue,
    Asn1Element.Tag.STRING_VISIBLE.tagValue,
    Asn1Element.Tag.STRING_UNIVERSAL.tagValue,
    Asn1Element.Tag.STRING_PRINTABLE.tagValue,
    Asn1Element.Tag.STRING_IA5.tagValue,
    Asn1Element.Tag.STRING_GENERAL.tagValue,
    Asn1Element.Tag.STRING_GRAPHIC.tagValue,
    Asn1Element.Tag.STRING_UNRESTRICTED.tagValue,
    Asn1Element.Tag.STRING_VIDEOTEX.tagValue,
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
            possibleLeadingTagNumbers = possibleLeadingTagNumbers(
                descriptor = fieldDescriptor,
                propertyAsn1nnotation = propertyAsn1nnotation
            )
        )
    }

    for (start in fields.indices) {
        val nullableOrOptionalField = fields[start]
        val firstTags = nullableOrOptionalField.possibleLeadingTagNumbers ?: continue
        if (!nullableOrOptionalField.omittable || firstTags.isEmpty()) continue

        var allSkippedFieldsAreOmittable = true
        for (candidate in (start + 1) until fields.size) {
            allSkippedFieldsAreOmittable =
                allSkippedFieldsAreOmittable && fields[candidate - 1].omittable
            if (!allSkippedFieldsAreOmittable) break

            val candidateField = fields[candidate]
            val candidateTags = candidateField.possibleLeadingTagNumbers ?: continue
            val overlap = firstTags intersect candidateTags
            if (overlap.isNotEmpty()) {
                throw SerializationException(
                    "Ambiguous ASN.1 layout for $serialName: " +
                            "property '${nullableOrOptionalField.name}' (index ${nullableOrOptionalField.index}) " +
                            "can be omitted and shares possible tag(s) ${overlap.sorted()} with " +
                            "property '${candidateField.name}' (index ${candidateField.index}). " +
                            "Add disambiguating @Asn1nnotation layers or set encodeNull=true for nullable fields."
                )
            }
        }
    }
}

private fun possibleLeadingTagNumbers(
    descriptor: SerialDescriptor,
    propertyAsn1nnotation: Asn1nnotation?,
    inheritedBitString: Boolean = false,
): Set<ULong>? {
    val allLayers = (propertyAsn1nnotation?.layers?.toList() ?: emptyList()) + descriptor.annotations.asn1Layers
    allLayers.firstOrNull()?.let {
        return setOf(it.tag)
    }

    val isBitString = inheritedBitString || propertyAsn1nnotation?.asBitString == true || descriptor.isAsn1BitString

    if (descriptor.isInline && descriptor.elementsCount == 1) {
        return possibleLeadingTagNumbers(
            descriptor = descriptor.getElementDescriptor(0),
            propertyAsn1nnotation = null,
            inheritedBitString = isBitString
        )
    }

    if (descriptor == ByteArraySerializer().descriptor) {
        return setOf(
            if (isBitString) Asn1Element.Tag.BIT_STRING.tagValue
            else Asn1Element.Tag.OCTET_STRING.tagValue
        )
    }

    return when (descriptor.kind) {
        PrimitiveKind.BOOLEAN -> setOf(Asn1Element.Tag.BOOL.tagValue)
        PrimitiveKind.BYTE,
        PrimitiveKind.SHORT,
        PrimitiveKind.INT,
        PrimitiveKind.LONG -> setOf(Asn1Element.Tag.INT.tagValue)

        PrimitiveKind.FLOAT,
        PrimitiveKind.DOUBLE -> setOf(Asn1Element.Tag.REAL.tagValue)

        PrimitiveKind.CHAR,
        PrimitiveKind.STRING -> Asn1StringTagNumbers

        SerialKind.ENUM -> setOf(Asn1Element.Tag.INT.tagValue)

        is StructureKind.CLASS,
        is StructureKind.OBJECT,
        is StructureKind.LIST,
        is StructureKind.MAP,
        is PolymorphicKind.OPEN,
        is PolymorphicKind.SEALED -> setOf(Asn1Element.Tag.SEQUENCE.tagValue)

        else -> null
    }
}
