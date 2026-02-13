package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.TagClass
import kotlinx.serialization.SerialInfo
import kotlinx.serialization.descriptors.SerialDescriptor

/**
 * Unified ASN.1 serialization annotation.
 *
 * This bundles ASN.1-specific serialization hints for implicit tag overrides and behavior flags.
 *
 * @param tagNumber implicit ASN.1 tag number override; negative means "infer from underlying type"
 * @param tagClass implicit ASN.1 tag-class override; [Asn1TagClass.INFER] keeps underlying class
 * @param constructed implicit ASN.1 constructed-bit override; [Asn1ConstructedBit.INFER] keeps underlying form
 * @param asBitString only affects [ByteArray] values (including inline wrappers): encodes as BIT STRING instead of OCTET STRING
 * @param encodeNull encodes nulls as explicit ASN.1 NULL instead of omitting the value
 * @param asChoice enables ASN.1 CHOICE behavior for sealed polymorphism (no discriminator wrapper)
 */
@SerialInfo
@Target(AnnotationTarget.CLASS, AnnotationTarget.PROPERTY)
annotation class Asn1nnotation(
    val tagNumber: Long = -1,
    val tagClass: Asn1TagClass = Asn1TagClass.INFER,
    val constructed: Asn1ConstructedBit = Asn1ConstructedBit.INFER,
    val asBitString: Boolean = false,
    val encodeNull: Boolean = false,
    val asChoice: Boolean = false,
)

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

internal val SerialDescriptor.asn1nnotation get() = annotations.find { it is Asn1nnotation } as? Asn1nnotation
internal fun SerialDescriptor.asn1nnotation(index: Int) =
    getElementAnnotations(index).find { it is Asn1nnotation } as? Asn1nnotation

internal val SerialDescriptor.isAsn1BitString: Boolean get() = annotations.isAsn1BitString
internal val List<Annotation>.isAsn1BitString: Boolean get() = filterIsInstance<Asn1nnotation>().any { it.asBitString }
internal fun SerialDescriptor.isAsn1BitString(index: Int): Boolean = getElementAnnotations(index).isAsn1BitString

internal val Asn1nnotation.tagNumberOrNull: ULong?
    get() = tagNumber.takeIf { it >= 0 }?.toULong()

internal fun resolveAsn1TagTemplate(
    inlineAsn1nnotation: Asn1nnotation? = null,
    propertyAsn1nnotation: Asn1nnotation? = null,
    classAsn1nnotation: Asn1nnotation? = null,
): Asn1Element.Tag.Template? {
    val tagNumber =
        inlineAsn1nnotation?.tagNumberOrNull
            ?: propertyAsn1nnotation?.tagNumberOrNull
            ?: classAsn1nnotation?.tagNumberOrNull
            ?: return null

    val tagClass =
        inlineAsn1nnotation?.tagClass?.toTagClassOrNull()
            ?: propertyAsn1nnotation?.tagClass?.toTagClassOrNull()
            ?: classAsn1nnotation?.tagClass?.toTagClassOrNull()

    val constructed =
        inlineAsn1nnotation?.constructed?.toBooleanOrNull()
            ?: propertyAsn1nnotation?.constructed?.toBooleanOrNull()
            ?: classAsn1nnotation?.constructed?.toBooleanOrNull()

    return Asn1Element.Tag.Template(tagNumber, tagClass, constructed)
}
