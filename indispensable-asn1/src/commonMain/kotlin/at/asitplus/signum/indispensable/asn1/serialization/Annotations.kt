package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.TagClass
import kotlinx.serialization.SerialInfo
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.StructureKind

/**
 * ASN.1 implicit tag override annotation.
 *
 * This annotation only controls tag override behavior.
 * Use [Asn1BitString] for additional ASN.1 semantics.
 *
 * @param tagNumber implicit ASN.1 tag number override
 * @param tagClass implicit ASN.1 tag-class override; defaults to [Asn1TagClass.CONTEXT_SPECIFIC]
 * while [Asn1TagClass.INFER] keeps underlying class
 * @param constructed implicit ASN.1 constructed-bit override; [Asn1ConstructedBit.INFER] keeps underlying form
 */
@SerialInfo
@Target(AnnotationTarget.CLASS, AnnotationTarget.PROPERTY)
annotation class Asn1Tag(
    val tagNumber: ULong,
    val tagClass: Asn1TagClass = Asn1TagClass.CONTEXT_SPECIFIC,
    val constructed: Asn1ConstructedBit = Asn1ConstructedBit.INFER,
)

/**
 * Marks [ByteArray] properties to encode/decode as ASN.1 BIT STRING.
 */
@SerialInfo
@Target(AnnotationTarget.PROPERTY)
annotation class Asn1BitString

enum class Asn1TagClass {
    INFER,
    UNIVERSAL,
    APPLICATION,
    CONTEXT_SPECIFIC,
    PRIVATE;

    internal fun toTagClassOrNull(): TagClass? = when (this) {
        INFER -> null
        UNIVERSAL -> TagClass.UNIVERSAL
        APPLICATION -> TagClass.APPLICATION
        CONTEXT_SPECIFIC -> TagClass.CONTEXT_SPECIFIC
        PRIVATE -> TagClass.PRIVATE
    }
}

enum class Asn1ConstructedBit {
    INFER,
    PRIMITIVE,
    CONSTRUCTED;

    internal fun toBooleanOrNull(): Boolean? = when (this) {
        INFER -> null
        PRIMITIVE -> false
        CONSTRUCTED -> true
    }
}

internal val SerialDescriptor.asn1Tag get() = annotations.find { it is Asn1Tag } as? Asn1Tag
internal fun SerialDescriptor.asn1Tag(index: Int) =
    getElementAnnotations(index).find { it is Asn1Tag } as? Asn1Tag
internal val List<Annotation>.asn1Tag get() = find { it is Asn1Tag } as? Asn1Tag

internal val SerialDescriptor.isAsn1BitString: Boolean
    get() = annotations.isAsn1BitString || (isInline && elementsCount == 1 && getElementAnnotations(0).isAsn1BitString)
internal val List<Annotation>.isAsn1BitString: Boolean get() = any { it is Asn1BitString }
internal fun SerialDescriptor.isAsn1BitString(index: Int): Boolean =
    getElementAnnotations(index).isAsn1BitString || getElementDescriptor(index).isAsn1BitString

internal val SerialDescriptor.isSealed: Boolean get() = kind is kotlinx.serialization.descriptors.PolymorphicKind.SEALED

private val byteArrayDescriptor = ByteArraySerializer().descriptor
private val byteArraySerialName = byteArrayDescriptor.serialName.removeSuffix("?")

internal fun SerialDescriptor.isAsn1BitStringCompatibleDescriptor(): Boolean {
    val descriptor = unwrapInlineDescriptorForAsn1()
    val normalizedName = descriptor.serialName.removeSuffix("?")
    return descriptor == byteArrayDescriptor ||
            normalizedName == byteArraySerialName ||
            (descriptor.kind is StructureKind.LIST &&
                    descriptor.elementsCount == 1 &&
                    descriptor.getElementDescriptor(0).kind == PrimitiveKind.BYTE)
}

private tailrec fun SerialDescriptor.unwrapInlineDescriptorForAsn1(): SerialDescriptor =
    if (isInline && elementsCount == 1) getElementDescriptor(0).unwrapInlineDescriptorForAsn1() else this

internal fun resolveAsn1TagTemplate(
    inlineAsn1Tag: Asn1Tag? = null,
    propertyAsn1Tag: Asn1Tag? = null,
    classAsn1Tag: Asn1Tag? = null,
): Asn1Element.Tag.Template? {
    val selectedAsn1Tag = inlineAsn1Tag ?: propertyAsn1Tag ?: classAsn1Tag ?: return null
    val tagNumber = selectedAsn1Tag.tagNumber

    val tagClass =
        inlineAsn1Tag?.tagClass?.toTagClassOrNull()
            ?: propertyAsn1Tag?.tagClass?.toTagClassOrNull()
            ?: classAsn1Tag?.tagClass?.toTagClassOrNull()

    val constructed =
        inlineAsn1Tag?.constructed?.toBooleanOrNull()
            ?: propertyAsn1Tag?.constructed?.toBooleanOrNull()
            ?: classAsn1Tag?.constructed?.toBooleanOrNull()

    return Asn1Element.Tag.Template(tagNumber, tagClass, constructed)
}
