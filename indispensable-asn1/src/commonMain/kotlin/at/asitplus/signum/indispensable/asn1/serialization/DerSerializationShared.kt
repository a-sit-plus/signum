package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Primitive
import at.asitplus.signum.indispensable.asn1.Asn1TagMismatchException
import at.asitplus.signum.indispensable.asn1.TagClass
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/**
 * Inline annotation hints captured by [DerEncoder]/[DerDecoder] from [SerialDescriptor]s.
 */
internal data class DerInlineHints(
    val tag: Asn1Tag?,
    val asBitString: Boolean,
    val asChoice: Boolean = false,
)

internal data class DerPropertyContext(
    val ownerDescriptor: SerialDescriptor,
    val index: Int,
    val propertyDescriptor: SerialDescriptor,
    val propertyAsn1Tag: Asn1Tag?,
    val propertyAsBitString: Boolean,
    val propertyAsChoice: Boolean = false,
    val propertyName: String?,
) {
    val ownerSerialName: String
        get() = ownerDescriptor.serialName
}

/**
 * Mutable holder for pending inline hints with explicit consume/peek semantics.
 */
internal class DerInlineHintState {
    private var inlineAsn1Tag: Asn1Tag? = null
    private var inlineAsBitString: Boolean = false

    fun recordFrom(descriptor: SerialDescriptor) {
        inlineAsn1Tag = descriptor.annotations.asn1Tag
        inlineAsBitString = descriptor.isAsn1BitString
    }

    fun peek(): DerInlineHints = DerInlineHints(
        tag = inlineAsn1Tag,
        asBitString = inlineAsBitString,
    )

    fun consume(): DerInlineHints = peek().also {
        inlineAsn1Tag = null
        inlineAsBitString = false
    }
}

internal fun Pair<SerialDescriptor, Int>.toDerPropertyContext(
    safePropertyNameLookup: Boolean = false,
): DerPropertyContext {
    val (ownerDescriptor, index) = this
    val propertyName = if (safePropertyNameLookup) {
        runCatching { ownerDescriptor.getElementName(index) }.getOrNull()
    } else {
        ownerDescriptor.getElementName(index)
    }
    return DerPropertyContext(
        ownerDescriptor = ownerDescriptor,
        index = index,
        propertyDescriptor = ownerDescriptor.getElementDescriptor(index),
        propertyAsn1Tag = ownerDescriptor.asn1Tag(index),
        propertyAsBitString = ownerDescriptor.isAsn1BitString(index),
        propertyAsChoice = ownerDescriptor.getElementDescriptor(index).isSealed,
        propertyName = propertyName,
    )
}

internal fun isAsn1ChoiceRequested(
    descriptor: SerialDescriptor,
    inlineAsChoice: Boolean,
    propertyAsChoice: Boolean,
): Boolean = inlineAsChoice || propertyAsChoice || descriptor.isSealed

internal fun Encoder.requireDerEncoder(serializerName: String): DerEncoder {
    if (this !is DerEncoder) {
        throw SerializationException(
            "$serializerName supports ASN.1 DER format only. " +
                    "Use DER.encodeToDer(...) / DER.encodeToTlv(...) instead of non-ASN.1 formats."
        )
    }
    return this
}

internal fun Decoder.requireDerDecoder(serializerName: String): DerDecoder {
    if (this !is DerDecoder) {
        throw SerializationException(
            "$serializerName supports ASN.1 DER format only. " +
                    "Use DER.decodeFromDer(...) / DER.decodeFromTlv(...) instead of non-ASN.1 formats."
        )
    }
    return this
}

internal fun validateAndResolveImplicitTagOverride(
    actualTag: Asn1Element.Tag,
    inlineAsn1Tag: Asn1Tag? = null,
    propertyAsn1Tag: Asn1Tag? = null,
    classAsn1Tag: Asn1Tag? = null,
): Asn1Element.Tag? {
    val tagTemplate = resolveAsn1TagTemplate(
        inlineAsn1Tag = inlineAsn1Tag,
        propertyAsn1Tag = propertyAsn1Tag,
        classAsn1Tag = classAsn1Tag,
    ) ?: return null

    val expectedTag = Asn1Element.Tag(
        tagValue = tagTemplate.tagValue,
        tagClass = tagTemplate.tagClass ?: actualTag.tagClass,
        constructed = tagTemplate.constructed ?: actualTag.isConstructed,
    )
    if (actualTag != expectedTag) {
        throw SerializationException(Asn1TagMismatchException(expectedTag, actualTag))
    }
    return expectedTag
}

internal fun requireAsn1ExplicitWrapperTag(
    descriptor: SerialDescriptor,
    tagTemplate: Asn1Element.Tag.Template?,
    ownerSerialName: String,
    propertyName: String? = null,
    propertyIndex: Int? = null,
) {
    if (!descriptor.isAsn1ExplicitWrapperDescriptor()) return
    val location = if (propertyName != null && propertyIndex != null) {
        "property '$propertyName' (index $propertyIndex) in $ownerSerialName"
    } else {
        ownerSerialName
    }
    if (tagTemplate == null) {
        throw SerializationException(
            "Asn1Explicit requires an implicit tag override at $location. " +
                    "Provide @Asn1Tag(tagNumber=..., tagClass=CONTEXT_SPECIFIC, constructed=CONSTRUCTED)."
        )
    }
    val effectiveClass = tagTemplate.tagClass ?: TagClass.UNIVERSAL
    val effectiveConstructed = tagTemplate.constructed ?: true
    if (effectiveClass != TagClass.CONTEXT_SPECIFIC || !effectiveConstructed) {
        throw SerializationException(
            "Asn1Explicit requires CONTEXT_SPECIFIC + CONSTRUCTED tag at $location, " +
                    "but effective override is class=$effectiveClass, constructed=$effectiveConstructed."
        )
    }
}

internal fun Asn1Element.isAsn1NullElement(): Boolean =
    this is Asn1Primitive &&
            tag == Asn1Element.Tag.NULL &&
            contentLength == 0
