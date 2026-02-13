package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.Asn1Element
import kotlinx.serialization.SerialInfo
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.SerialDescriptor

/**
 * Unified ASN.1 serialization annotation.
 *
 * This bundles all ASN.1-specific serialization hints because annotation order on declarations
 * is not stable, while [layers] order is semantically relevant.
 *
 * @param layers ordered encapsulation/tagging layers, outermost first
 * @param asBitString only affects [ByteArray] values (including inline wrappers): encodes as BIT STRING instead of OCTET STRING
 * @param encodeNull encodes nulls as explicit ASN.1 NULL instead of omitting the value
 * @param asChoice enables ASN.1 CHOICE behavior for sealed polymorphism (no discriminator wrapper)
 */
@SerialInfo
@Target(AnnotationTarget.CLASS, AnnotationTarget.PROPERTY)
annotation class Asn1nnotation(
    vararg val layers: Layer,
    val asBitString: Boolean = false,
    val encodeNull: Boolean = false,
    val asChoice: Boolean = false,
)

/**
 * Single ASN.1 layer used by [Asn1nnotation].
 *
 * Depending on [type], this models:
 * - EXPLICIT tagging (requires exactly one tag value in [singleTag])
 * - IMPLICIT tagging (requires exactly one tag value in [singleTag])
 * - OCTET STRING encapsulation (ignores [singleTag])
 */
@SerialInfo
@Target(allowedTargets = [])
annotation class Layer(
    val type: Type,
    vararg val singleTag: ULong
)

/**
 * Validated access to a layer's effective tag.
 *
 * For [Type.EXPLICIT_TAG] and [Type.IMPLICIT_TAG], exactly one tag value must be present.
 * For [Type.OCTET_STRING], this returns [Asn1Element.Tag.OCTET_STRING].
 */
val Layer.tag: ULong
    get() = when (this.type) {
        Type.OCTET_STRING -> Asn1Element.Tag.OCTET_STRING.tagValue
        Type.EXPLICIT_TAG, Type.IMPLICIT_TAG -> if (singleTag.size != 1) throw SerializationException("Exactly one single tag value must be specified, got: ${singleTag.size}") else singleTag.first()
    }

/**
 * Layer mode used by [Layer].
 */
enum class Type {
    OCTET_STRING,
    EXPLICIT_TAG,
    IMPLICIT_TAG;
}

internal val SerialDescriptor.asn1nnotation get() = annotations.find { it is Asn1nnotation } as? Asn1nnotation
internal fun SerialDescriptor.asn1nnotation(index: Int) =
    getElementAnnotations(index).find { it is Asn1nnotation } as? Asn1nnotation

internal val Iterable<Annotation>.asn1Layers: List<Layer>
    get() = filterIsInstance<Asn1nnotation>().firstOrNull()?.layers?.asList() ?: emptyList()

internal val SerialDescriptor.isAsn1BitString: Boolean get() = annotations.isAsn1BitString
internal val List<Annotation>.isAsn1BitString: Boolean get() = filterIsInstance<Asn1nnotation>().any { it.asBitString }
internal fun SerialDescriptor.isAsn1BitString(index: Int): Boolean = getElementAnnotations(index).isAsn1BitString
