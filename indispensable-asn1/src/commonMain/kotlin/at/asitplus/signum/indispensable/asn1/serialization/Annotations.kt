package at.asitplus.signum.indispensable.asn1.serialization

import kotlinx.serialization.SerialInfo
import kotlinx.serialization.descriptors.SerialDescriptor

class F(vararg val layers: Layer, iss: Boolean = false)

@SerialInfo
@Target(AnnotationTarget.CLASS, AnnotationTarget.PROPERTY)
annotation class Asn1nnotation(
    vararg val layers: Layer,
    val asSet: Boolean = false,
    val asBitString: Boolean = false,
    val encodeNull: Boolean = false
)

@SerialInfo
@Target(allowedTargets = [])
annotation class Layer(
    val type: Type,
    val tag: ULong = 0uL
)

enum class Type {
    OCTET_STRING,
    EXPLICIT_TAG,
    IMPLICIT_TAG;
}

val Iterable<Annotation>.asn1Layers: List<Layer>
    get() = filterIsInstance<Asn1nnotation>().firstOrNull()?.layers?.asList() ?: emptyList()

//TODO: config to always keep nulls


internal val SerialDescriptor.isAsn1Set: Boolean get() = annotations.isAsn1Set
internal val List<Annotation>.isAsn1Set: Boolean get() = filterIsInstance<Asn1nnotation>().any { it.asSet }
internal fun SerialDescriptor.isAsn1Set(index: Int) = getElementAnnotations(index).isAsn1Set

internal val SerialDescriptor.isAsn1BitString: Boolean get() = annotations.isAsn1BitString
internal val List<Annotation>.isAsn1BitString: Boolean get() = filterIsInstance<Asn1nnotation>().any { it.asBitString }
internal fun SerialDescriptor.isAsn1BitString(index: Int): Boolean = getElementAnnotations(index).isAsn1BitString

internal val SerialDescriptor.doEncodeNull: Boolean get() = annotations.doEncodeNull
internal val List<Annotation>.doEncodeNull: Boolean get() = filterIsInstance<Asn1nnotation>().any { it.encodeNull }
internal fun SerialDescriptor.doEncodeNull(index: Int): Boolean = getElementAnnotations(index).doEncodeNull
