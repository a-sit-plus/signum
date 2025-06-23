package at.asitplus.signum.indispensable.asn1.serialization

import kotlinx.serialization.SerialInfo
import kotlinx.serialization.descriptors.SerialDescriptor


//marks collection/class as sorted. must never be used on a map
@SerialInfo
@Target(AnnotationTarget.PROPERTY, AnnotationTarget.CLASS)
annotation class Asn1Set

@SerialInfo
@Target(AnnotationTarget.PROPERTY)
annotation class Asn1BitString //encode bytearray to bitstring

/**
 * OCTET STRING always encapsulates, i.e. adds another level to the resulting ASN.1 hierarchy (even on byte arrays!)
 */
@SerialInfo
@Target(AnnotationTarget.PROPERTY, AnnotationTarget.CLASS)
annotation class Asn1OctetString

@SerialInfo
@Target(AnnotationTarget.PROPERTY, AnnotationTarget.CLASS)
annotation class Asn1ExplicitlyTagged(val tag: ULong)

@SerialInfo
@Target(AnnotationTarget.PROPERTY, AnnotationTarget.CLASS)
annotation class Asn1ImplicitlyTagged(val tag: ULong)


@SerialInfo
@Target(AnnotationTarget.PROPERTY, AnnotationTarget.CLASS)
annotation class Asn1EncodeNull

//TODO: throw errors for nonsenical annotations

//TODO: config to always keep nulls


internal val SerialDescriptor.isAsn1Set: Boolean get() = annotations.find { it is Asn1Set } != null
internal val List<Annotation>.isAsn1Set: Boolean get() = find { it is Asn1Set } != null
internal fun SerialDescriptor.isAsn1Set(index: Int) = getElementAnnotations(index).find { it is Asn1Set } != null

internal val SerialDescriptor.isAsn1BitSet: Boolean get() = annotations.find { it is Asn1BitString } != null
internal val List<Annotation>.isAsn1BitSet: Boolean get() = find { it is Asn1BitString } != null
internal fun SerialDescriptor.isAsn1BitSet(index: Int): Boolean =
    getElementAnnotations(index).find { it is Asn1BitString } != null

internal val SerialDescriptor.isAsn1OctetString: Boolean get() = annotations.find { it is Asn1OctetString } != null
internal val List<Annotation>.isAsn1OctetString: Boolean get() = find { it is Asn1OctetString } != null
internal fun SerialDescriptor.isAsn1OctetString(index: Int): Boolean =
    getElementAnnotations(index).find { it is Asn1OctetString } != null

internal val SerialDescriptor.doEncodeNull: Boolean get() = annotations.find { it is Asn1EncodeNull } != null
internal val List<Annotation>.doEncodeNull: Boolean get() = find { it is Asn1EncodeNull } != null
internal fun SerialDescriptor.doEncodeNull(index: Int): Boolean =
    getElementAnnotations(index).find { it is Asn1EncodeNull } != null

internal val SerialDescriptor.explicitTag: ULong? get() = (annotations.find { it is Asn1ExplicitlyTagged } as Asn1ExplicitlyTagged?)?.tag
internal val List<Annotation>.explicitTag: ULong? get() = (find { it is Asn1ExplicitlyTagged } as Asn1ExplicitlyTagged?)?.tag
internal fun SerialDescriptor.explicitTag(index: Int): ULong? =
    (getElementAnnotations(index).find { it is Asn1ExplicitlyTagged } as Asn1ExplicitlyTagged?)?.tag

internal val SerialDescriptor.implicitTag: ULong? get() = (annotations.find { it is Asn1ImplicitlyTagged } as Asn1ImplicitlyTagged?)?.tag
internal val List<Annotation>.implicitTag: ULong? get() = (find { it is Asn1ImplicitlyTagged } as Asn1ImplicitlyTagged?)?.tag
internal fun SerialDescriptor.implicitTag(index: Int): ULong? =
    (getElementAnnotations(index).find { it is Asn1ImplicitlyTagged } as Asn1ImplicitlyTagged?)?.tag


internal val SerialDescriptor.isStructurallyAnnotated: Boolean get() = isAsn1OctetString || explicitTag != null
internal val List<Annotation>.isStructurallyAnnotated: Boolean get() = isAsn1OctetString || explicitTag != null
internal val Pair<SerialDescriptor, Int>.isStructurallyAnnotated: Boolean
    get() = first.isAsn1OctetString(second) || first.explicitTag(
        second
    ) != null