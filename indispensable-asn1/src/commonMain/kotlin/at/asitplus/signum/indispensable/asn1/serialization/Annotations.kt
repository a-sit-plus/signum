package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.internals.ImplementationError
import kotlinx.serialization.SerialInfo
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.SerialDescriptor

/**
 * All-in-one ASN.1 kitchen sink annotation for serialization.
 * Required since the order of encapsulating [layers] is important and the order of toplevel annotations is not preserved.
 *
 * @param layers any encapsulating layers
 * @param asBitString only affects [ByteArray]s (and value classes over byte arrays): Whether to encode a byte array as bit string instead of an octet string
 * @param encodeNull whether to encode a null value as ANS.1 null (or omit it).
 */
@SerialInfo
@Target(AnnotationTarget.CLASS, AnnotationTarget.PROPERTY)
annotation class Asn1nnotation(
    vararg val layers: Layer,
    val asBitString: Boolean = false,
    val encodeNull: Boolean = false,
)

/**
 * Encapsulation layer allowing for:
 *   * EXPLICIT tagging requiring **a single tag value**
 *   * IMPLICIT tagging requiring **a single tag value**
 *   * OCTET STRING encapsulation **ignoring all provided tag values**
 *
 * through [Asn1nnotation].
 */
@SerialInfo
@Target(allowedTargets = [])
annotation class Layer(
    val type: Type,
    vararg val singleTag: ULong
)

/**
 * checked access to tag, only use this one
 */
val Layer.tag: ULong
    get() = when (this.type) {
        Type.OCTET_STRING -> throw ImplementationError("Cannot specify tag for OCTET STRING")
        Type.EXPLICIT_TAG, Type.IMPLICIT_TAG -> if (singleTag.size != 1) throw SerializationException("Exactly one single tag value must be specified, got: ${singleTag.size}") else singleTag.first()
    }

/**
 * Layer type crutch, since annotations are limited
 */
enum class Type {
    OCTET_STRING,
    EXPLICIT_TAG,
    IMPLICIT_TAG;
}

internal val Iterable<Annotation>.asn1Layers: List<Layer>
    get() = filterIsInstance<Asn1nnotation>().firstOrNull()?.layers?.asList() ?: emptyList()

internal val SerialDescriptor.isAsn1BitString: Boolean get() = annotations.isAsn1BitString
internal val List<Annotation>.isAsn1BitString: Boolean get() = filterIsInstance<Asn1nnotation>().any { it.asBitString }
internal fun SerialDescriptor.isAsn1BitString(index: Int): Boolean = getElementAnnotations(index).isAsn1BitString

internal val SerialDescriptor.doEncodeNull: Boolean get() = annotations.doEncodeNull
internal val List<Annotation>.doEncodeNull: Boolean get() = filterIsInstance<Asn1nnotation>().any { it.encodeNull }
internal fun SerialDescriptor.doEncodeNull(index: Int): Boolean = getElementAnnotations(index).doEncodeNull
