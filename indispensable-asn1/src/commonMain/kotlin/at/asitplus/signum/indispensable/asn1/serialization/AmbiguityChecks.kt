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
    val possibleLeadingTags: Asn1LeadingTagsResolution,
)

internal sealed interface Asn1LeadingTagsResolution {
    data class Exact(val tags: Set<Asn1Element.Tag>) : Asn1LeadingTagsResolution
    data object UnknownInfer : Asn1LeadingTagsResolution
}

internal data class Asn1NullEncodingAnalysis(
    val encodeNullEnabled: Boolean,
    val usesImplicitNullSentinel: Boolean,
    val baseIsConstructed: Boolean,
    val baseCanEncodeEmptyContent: Boolean,
) {
    val isAmbiguous: Boolean
        get() = encodeNullEnabled &&
                usesImplicitNullSentinel &&
                !baseIsConstructed &&
                baseCanEncodeEmptyContent

    val canDecodeNullByZeroLength: Boolean
        get() = encodeNullEnabled &&
                usesImplicitNullSentinel &&
                !baseIsConstructed &&
                !baseCanEncodeEmptyContent

    val canDecodeNullByConstructedBit: Boolean
        get() = encodeNullEnabled &&
                usesImplicitNullSentinel &&
                baseIsConstructed
}

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
private val ByteArraySerialName: String = ByteArraySerializer().descriptor.serialName
private const val Asn1ElementSerializerSerialName = "Asn1ElementDerEncodedSerializer"
private const val Asn1OpaqueSerializerSerialName = "Asn1DerSerializer"

internal fun SerialDescriptor.ensureNoAsn1AmbiguousOptionalLayout() {
    if (kind !is StructureKind.CLASS && kind !is StructureKind.OBJECT) return

    val fields = (0 until elementsCount).map { index ->
        val fieldDescriptor = getElementDescriptor(index)
        val propertyAsn1Tag = asn1Tag(index)
        val propertyEncodeNull = isAsn1EncodeNull(index)
        val propertyAsBitString = isAsn1BitString(index)
        val propertyAsChoice = isAsn1Choice(index)
        val nullEncodingAnalysis = fieldDescriptor.analyzeAsn1NullableNullEncoding(
            propertyAsn1Tag = propertyAsn1Tag,
            propertyEncodeNull = propertyEncodeNull,
            propertyAsBitString = propertyAsBitString,
        )
        if (nullEncodingAnalysis.isAmbiguous) {
            throw SerializationException(
                ambiguousAsn1NullEncodingMessage(
                    ownerSerialName = serialName,
                    propertyName = getElementName(index),
                    propertyIndex = index,
                )
            )
        }

        val omittableByNull = fieldDescriptor.isNullable &&
                !propertyEncodeNull &&
                !fieldDescriptor.isAsn1EncodeNull
        val omittable = omittableByNull || isElementOptional(index)
        Asn1FieldShape(
            index = index,
            name = getElementName(index),
            omittable = omittable,
            possibleLeadingTags = possibleLeadingTags(
                descriptor = fieldDescriptor,
                propertyAsn1Tag = propertyAsn1Tag,
                propertyAsBitString = propertyAsBitString,
                propertyAsChoice = propertyAsChoice,
            )
        )
    }

    for (start in fields.indices) {
        val nullableOrOptionalField = fields[start]
        if (!nullableOrOptionalField.omittable) continue

        if (start < fields.lastIndex && nullableOrOptionalField.possibleLeadingTags !is Asn1LeadingTagsResolution.Exact) {
            throw SerializationException(
                undecidableAsn1OptionalLayoutMessage(
                    ownerSerialName = serialName,
                    propertyName = nullableOrOptionalField.name,
                    propertyIndex = nullableOrOptionalField.index,
                    reason = nullableOrOptionalField.possibleLeadingTags.reason(),
                )
            )
        }

        val firstTags = (nullableOrOptionalField.possibleLeadingTags as? Asn1LeadingTagsResolution.Exact)?.tags ?: continue
        if (firstTags.isEmpty()) continue

        var allSkippedFieldsAreOmittable = true
        for (candidate in (start + 1) until fields.size) {
            allSkippedFieldsAreOmittable =
                allSkippedFieldsAreOmittable && fields[candidate - 1].omittable
            if (!allSkippedFieldsAreOmittable) break

            val candidateField = fields[candidate]
            val candidateTags = when (val resolution = candidateField.possibleLeadingTags) {
                is Asn1LeadingTagsResolution.Exact -> resolution.tags
                else -> throw SerializationException(
                    undecidableAsn1OptionalLayoutMessage(
                        ownerSerialName = serialName,
                        propertyName = candidateField.name,
                        propertyIndex = candidateField.index,
                        reason = resolution.reason(),
                    )
                )
            }
            val overlap = firstTags intersect candidateTags
            if (overlap.isNotEmpty()) {
                throw SerializationException(
                    "Ambiguous ASN.1 layout for $serialName: " +
                            "property '${nullableOrOptionalField.name}' (index ${nullableOrOptionalField.index}) " +
                            "can be omitted and shares possible tag(s) ${formatTags(overlap)} with " +
                            "property '${candidateField.name}' (index ${candidateField.index}). " +
                            "Add disambiguating implicit @Asn1Tag tags or mark nullable fields with @Asn1EncodeNull."
                )
            }
        }
    }
}

internal fun SerialDescriptor.analyzeAsn1NullableNullEncoding(
    propertyAsn1Tag: Asn1Tag? = null,
    inlineAsn1Tag: Asn1Tag? = null,
    propertyEncodeNull: Boolean = false,
    inlineEncodeNull: Boolean = false,
    propertyAsBitString: Boolean = false,
    inlineAsBitString: Boolean = false,
): Asn1NullEncodingAnalysis {
    val encodeNullEnabled =
        isNullable && (
                inlineEncodeNull ||
                        propertyEncodeNull ||
                        isAsn1EncodeNull
                )
    if (!encodeNullEnabled) {
        return Asn1NullEncodingAnalysis(
            encodeNullEnabled = false,
            usesImplicitNullSentinel = false,
            baseIsConstructed = false,
            baseCanEncodeEmptyContent = false,
        )
    }

    val tagTemplate = resolveAsn1TagTemplate(
        inlineAsn1Tag = inlineAsn1Tag,
        propertyAsn1Tag = propertyAsn1Tag,
        classAsn1Tag = asn1Tag
    )
    val usesImplicitNullSentinel = tagTemplate != null
    if (!usesImplicitNullSentinel) {
        return Asn1NullEncodingAnalysis(
            encodeNullEnabled = true,
            usesImplicitNullSentinel = false,
            baseIsConstructed = false,
            baseCanEncodeEmptyContent = false,
        )
    }

    val unwrapped = unwrapInlineDescriptor()
    val isBitString =
        inlineAsBitString ||
                propertyAsBitString ||
                unwrapped.isAsn1BitString

    val baseIsConstructed = tagTemplate.constructed ?: unwrapped.asn1BaseIsConstructed()
    val baseCanEncodeEmptyContent = unwrapped.asn1BaseCanEncodeEmptyContent(isBitString)

    return Asn1NullEncodingAnalysis(
        encodeNullEnabled = true,
        usesImplicitNullSentinel = true,
        baseIsConstructed = baseIsConstructed,
        baseCanEncodeEmptyContent = baseCanEncodeEmptyContent,
    )
}

internal fun SerialDescriptor.possibleLeadingTagsForAsn1(
    propertyAsn1Tag: Asn1Tag? = null,
    inlineAsn1Tag: Asn1Tag? = null,
    propertyAsBitString: Boolean = false,
    inlineAsBitString: Boolean = false,
    propertyAsChoice: Boolean = false,
    inlineAsChoice: Boolean = false,
): Asn1LeadingTagsResolution = possibleLeadingTags(
    descriptor = this,
    propertyAsn1Tag = propertyAsn1Tag,
    inlineAsn1Tag = inlineAsn1Tag,
    propertyAsBitString = propertyAsBitString,
    inlineAsBitString = inlineAsBitString,
    propertyAsChoice = propertyAsChoice,
    inlineAsChoice = inlineAsChoice,
)

private fun possibleLeadingTags(
    descriptor: SerialDescriptor,
    propertyAsn1Tag: Asn1Tag?,
    inlineAsn1Tag: Asn1Tag? = null,
    propertyAsBitString: Boolean = false,
    inlineAsBitString: Boolean = false,
    propertyAsChoice: Boolean = false,
    inlineAsChoice: Boolean = false,
    inheritedBitString: Boolean = false,
    forcedChoice: Boolean? = null,
): Asn1LeadingTagsResolution {
    val isBitString = inheritedBitString || inlineAsBitString || propertyAsBitString || descriptor.isAsn1BitString
    val choiceMode = forcedChoice ?: (inlineAsChoice || propertyAsChoice || descriptor.isAsn1Choice)

    val tagTemplate = resolveAsn1TagTemplate(
        inlineAsn1Tag = inlineAsn1Tag,
        propertyAsn1Tag = propertyAsn1Tag,
        classAsn1Tag = descriptor.asn1Tag,
    )

    val baseTags = possibleBaseLeadingTags(
        descriptor = descriptor,
        isBitString = isBitString,
        choiceMode = choiceMode,
    )

    return applyImplicitTagOverride(baseTags, tagTemplate)
}

private fun possibleBaseLeadingTags(
    descriptor: SerialDescriptor,
    isBitString: Boolean,
    choiceMode: Boolean,
): Asn1LeadingTagsResolution {
    if (descriptor.isInline && descriptor.elementsCount == 1) {
        return possibleLeadingTags(
            descriptor = descriptor.getElementDescriptor(0),
            propertyAsn1Tag = null,
            propertyAsBitString = false,
            inlineAsBitString = false,
            propertyAsChoice = false,
            inlineAsChoice = false,
            inheritedBitString = isBitString,
            forcedChoice = choiceMode,
        )
    }

    if (descriptor.isAsn1OpaqueSerializerDescriptor()) {
        return Asn1LeadingTagsResolution.UnknownInfer
    }

    if (descriptor.isByteArrayLikeDescriptor()) {
        return Asn1LeadingTagsResolution.Exact(
            setOf(
                if (isBitString) Asn1Element.Tag.BIT_STRING
                else Asn1Element.Tag.OCTET_STRING
            )
        )
    }

    val tags = when (descriptor.kind) {
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
            return if (choiceMode) possibleSealedChoiceAlternativeLeadingTags(descriptor)
            else Asn1LeadingTagsResolution.Exact(setOf(Asn1Element.Tag.SEQUENCE))
        }

        else -> null
    }

    return tags?.let { Asn1LeadingTagsResolution.Exact(it) } ?: Asn1LeadingTagsResolution.UnknownInfer
}

internal fun SerialDescriptor.findLikelySealedAlternativesDescriptor(): SerialDescriptor? =
    (0 until elementsCount)
        .map { getElementDescriptor(it) }
        .filter { it.elementsCount > 0 }
        .maxByOrNull { it.elementsCount }

private fun possibleSealedChoiceAlternativeLeadingTags(descriptor: SerialDescriptor): Asn1LeadingTagsResolution {
    val alternativesDescriptor = descriptor.findLikelySealedAlternativesDescriptor() ?: return Asn1LeadingTagsResolution.UnknownInfer
    val alternativeTags = mutableSetOf<Asn1Element.Tag>()

    for (i in 0 until alternativesDescriptor.elementsCount) {
        val alternativeDescriptor = alternativesDescriptor.getElementDescriptor(i)
        when (val resolution = possibleLeadingTags(
            descriptor = alternativeDescriptor,
            propertyAsn1Tag = null,
            propertyAsBitString = false,
            inlineAsBitString = false,
            propertyAsChoice = false,
            inlineAsChoice = false,
            forcedChoice = alternativeDescriptor.isAsn1Choice,
        )) {
            is Asn1LeadingTagsResolution.Exact -> alternativeTags += resolution.tags
            Asn1LeadingTagsResolution.UnknownInfer -> return Asn1LeadingTagsResolution.UnknownInfer
        }
    }

    return if (alternativeTags.isNotEmpty()) Asn1LeadingTagsResolution.Exact(alternativeTags)
    else Asn1LeadingTagsResolution.UnknownInfer
}

private fun applyImplicitTagOverride(
    baseTags: Asn1LeadingTagsResolution,
    tagTemplate: Asn1Element.Tag.Template?,
): Asn1LeadingTagsResolution {
    if (tagTemplate == null) return baseTags
    return when (baseTags) {
        is Asn1LeadingTagsResolution.Exact -> Asn1LeadingTagsResolution.Exact(
            baseTags.tags.map {
                Asn1Element.Tag(
                    tagValue = tagTemplate.tagValue,
                    tagClass = tagTemplate.tagClass ?: it.tagClass,
                    constructed = tagTemplate.constructed ?: it.isConstructed,
                )
            }.toSet()
        )

        Asn1LeadingTagsResolution.UnknownInfer -> {
            val tagClass = tagTemplate.tagClass
            val constructed = tagTemplate.constructed
            if (tagClass != null && constructed != null) {
                Asn1LeadingTagsResolution.Exact(
                    setOf(
                        Asn1Element.Tag(
                            tagValue = tagTemplate.tagValue,
                            tagClass = tagClass,
                            constructed = constructed,
                        )
                    )
                )
            } else {
                Asn1LeadingTagsResolution.UnknownInfer
            }
        }
    }
}

private fun formatTags(tags: Set<Asn1Element.Tag>): String = tags
    .sortedWith(compareBy<Asn1Element.Tag>({ it.tagClass.ordinal }, { it.tagValue }, { it.isConstructed }))
    .joinToString(prefix = "[", postfix = "]") { formatTag(it) }

private fun formatTag(tag: Asn1Element.Tag): String =
    "${tag.tagClass}:${tag.tagValue}${if (tag.isConstructed) "/C" else "/P"}"

internal fun Asn1LeadingTagsResolution.reason(): String = when (this) {
    is Asn1LeadingTagsResolution.Exact -> "exact leading tags are known"
    Asn1LeadingTagsResolution.UnknownInfer ->
        "leading tags cannot be inferred from descriptor"
}

internal fun undecidableAsn1OptionalLayoutMessage(
    ownerSerialName: String,
    propertyName: String,
    propertyIndex: Int,
    reason: String,
): String =
    "Undecidable ASN.1 optional/nullable layout for property '$propertyName' (index $propertyIndex) in $ownerSerialName: " +
            "$reason. Add disambiguating ASN.1 tags (typically EXPLICIT/IMPLICIT context tags)."

internal fun undecidableAsn1NullableDecodingMessage(
    ownerSerialName: String,
    propertyName: String,
    propertyIndex: Int,
    reason: String,
): String =
    "Undecidable nullable ASN.1 decode for property '$propertyName' (index $propertyIndex) in $ownerSerialName: " +
            "$reason. Add disambiguating ASN.1 tags (typically EXPLICIT/IMPLICIT context tags)."

internal fun ambiguousAsn1NullEncodingMessage(
    ownerSerialName: String,
    propertyName: String? = null,
    propertyIndex: Int? = null,
): String {
    val propertyPart = if (propertyName != null && propertyIndex != null) {
        "property '$propertyName' (index $propertyIndex) in "
    } else {
        ""
    }
    return "Ambiguous ASN.1 null encoding for ${propertyPart}$ownerSerialName: " +
            "nullable value with @Asn1EncodeNull uses implicit tag override where null and empty non-null values become indistinguishable. " +
            "Use EXPLICIT tagging, remove @Asn1EncodeNull, or choose a non-ambiguous value type."
}

private tailrec fun SerialDescriptor.unwrapInlineDescriptor(): SerialDescriptor =
    if (isInline && elementsCount == 1) getElementDescriptor(0).unwrapInlineDescriptor() else this

private fun SerialDescriptor.asn1BaseIsConstructed(): Boolean =
    if (isAsn1OpaqueSerializerDescriptor() || isByteArrayLikeDescriptor()) false
    else isSetDescriptor || when (kind) {
        is StructureKind.CLASS,
        is StructureKind.OBJECT,
        is StructureKind.LIST,
        is StructureKind.MAP,
        is PolymorphicKind.OPEN,
        is PolymorphicKind.SEALED -> true

        else -> false
    }

private fun SerialDescriptor.asn1BaseCanEncodeEmptyContent(isBitString: Boolean): Boolean {
    if (isAsn1OpaqueSerializerDescriptor()) return true
    if (isByteArrayLikeDescriptor()) return !isBitString
    return when (kind) {
        PrimitiveKind.STRING -> true
        PrimitiveKind.FLOAT,
        PrimitiveKind.DOUBLE -> true

        else -> false
    }
}

private fun SerialDescriptor.isByteArrayLikeDescriptor(): Boolean =
    this == ByteArraySerializer().descriptor ||
            serialName.removeSuffix("?") == ByteArraySerialName ||
            (kind is StructureKind.LIST &&
                    elementsCount == 1 &&
                    getElementDescriptor(0).kind == PrimitiveKind.BYTE)

private fun SerialDescriptor.isAsn1OpaqueSerializerDescriptor(): Boolean {
    val normalizedSerialName = serialName.removeSuffix("?")
    return normalizedSerialName == Asn1ElementSerializerSerialName ||
            normalizedSerialName == Asn1OpaqueSerializerSerialName
}
