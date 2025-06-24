package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.Asn1Set
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.encoding.encodeToAsn1Primitive
import kotlinx.io.Buffer
import kotlinx.io.Sink
import kotlinx.io.readByteArray
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerializationStrategy
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.AbstractEncoder
import kotlinx.serialization.modules.EmptySerializersModule
import kotlinx.serialization.modules.SerializersModule
import kotlinx.serialization.serializer


//TODO value classes proper!

/**
 * Holder for ASN.1 elements during serialization process.
 * Can hold either a concrete element or a placeholder that needs to be resolved later.
 */
private sealed class Asn1ElementHolder {
    data class Element(val element: Asn1Element) : Asn1ElementHolder()
    class StructurePlaceholder(
        val childSerializer: Asn1Serializer,
        val descriptor: SerialDescriptor
    ) : Asn1ElementHolder()

    sealed class NestedStructurePlaceholder(
        val childSerializer: Asn1Serializer,
        val annotations: List<Layer>,
    ) : Asn1ElementHolder() {
        class OctetString(childSerializer: Asn1Serializer, annotations: List<Layer>) :
            NestedStructurePlaceholder(childSerializer, annotations)

        class ExplicitTag(val tag: ULong, childSerializer: Asn1Serializer, annotations: List<Layer>) :
            NestedStructurePlaceholder(childSerializer, annotations)
    }

    // New holder for elements that need implicit tagging during finalization
    class ImplicitlyTagged(val element: Asn1ElementHolder, val tag: ULong) : Asn1ElementHolder()
}

/**
 * A buffer that automatically wraps elements with implicit tagging holders
 */
private class ImplicitTaggingBuffer(
    private val delegate: MutableList<Asn1ElementHolder>,
    private val implicitTag: ULong
) : MutableList<Asn1ElementHolder> by delegate {

    override fun add(element: Asn1ElementHolder): Boolean {
        val taggedElement = Asn1ElementHolder.ImplicitlyTagged(element, implicitTag)
        return delegate.add(taggedElement)
    }

    override fun add(index: Int, element: Asn1ElementHolder) {
        val taggedElement = Asn1ElementHolder.ImplicitlyTagged(element, implicitTag)
        delegate.add(index, taggedElement)
    }
}


@ExperimentalSerializationApi
class Asn1Serializer(
    override val serializersModule: SerializersModule = EmptySerializersModule(),
) : AbstractEncoder() {

    private val buffer = mutableListOf<Asn1ElementHolder>()
    private var descriptorAndIndex: Pair<SerialDescriptor, Int>? = null

    override fun encodeValue(value: Any) {
        val annotations = descriptorAndIndex?.let { (descriptor, index) ->
            descriptor.getElementAnnotations(index).asn1Layers
        } ?: emptyList<Layer>()

        descriptorAndIndex = null // Clear immediately after reading
        val targetBuffer = processAnnotationsAndGetTarget(annotations)

        val element = when (value) {
            is Asn1Element -> value
            is Asn1Encodable<*> -> value.encodeToTlv()
            is ByteArray -> Asn1PrimitiveOctetString(value)

            is Boolean -> value.encodeToAsn1Primitive()

            is Byte -> value.toInt().encodeToAsn1Primitive()
            is UByte -> value.toUInt().encodeToAsn1Primitive()

            is Short -> value.toInt().encodeToAsn1Primitive()
            is UShort -> value.toUInt().encodeToAsn1Primitive()

            is Int -> value.encodeToAsn1Primitive()
            is UInt -> value.encodeToAsn1Primitive()

            is Float -> value.encodeToAsn1Primitive()

            is Long -> value.encodeToAsn1Primitive()
            is ULong -> value.encodeToAsn1Primitive()

            is Double -> value.encodeToAsn1Primitive()

            is String -> value.encodeToAsn1Primitive()
            is Char -> value.toString().encodeToAsn1Primitive()

            else -> {
                super.encodeValue(value)
                return
            }
        }

        targetBuffer += Asn1ElementHolder.Element(element)
    }

    override fun encodeNull() {
        val currentDescriptorAndIndex = descriptorAndIndex
        descriptorAndIndex = null // Clear immediately after reading

        currentDescriptorAndIndex?.let { (descriptor, index) ->
            if (!descriptor.doEncodeNull(index)) return

            val targetBuffer = processAnnotationsAndGetTarget(descriptor.getElementAnnotations(index).asn1Layers)
            targetBuffer += Asn1ElementHolder.Element(Asn1.Null())
        }
    }

    override fun encodeElement(descriptor: SerialDescriptor, index: Int): Boolean {
        this.descriptorAndIndex = descriptor to index
        return super.encodeElement(descriptor, index)
    }

    override fun encodeEnum(enumDescriptor: SerialDescriptor, index: Int) {
        val targetBuffer = processAnnotationsAndGetTarget(
            (descriptorAndIndex?.let { (descriptor, index) -> descriptor.getElementAnnotations(index).asn1Layers }
                ?: emptyList()) +
                    enumDescriptor.annotations.asn1Layers
        )
        targetBuffer += Asn1ElementHolder.Element(Asn1.Enumerated(index))
    }

    override fun <T> encodeSerializableValue(serializer: SerializationStrategy<T>, value: T) {
        if (serializer.descriptor == ByteArraySerializer().descriptor) {
            if (serializer.descriptor.isAsn1BitString) encodeValue(BitSet.from(value as ByteArray))
            else encodeValue(value as ByteArray)
        } else if (value is Asn1Encodable<*> || value is Asn1Element) encodeValue(value)
        else super.encodeSerializableValue(serializer, value)
    }

    override fun beginStructure(descriptor: SerialDescriptor): Asn1Serializer {
        // Get property-level annotations BEFORE clearing descriptorAndIndex
        val propertyAnnotations = descriptorAndIndex?.let { (descriptor, index) ->
            descriptor.getElementAnnotations(index).asn1Layers
        } ?: emptyList<Layer>()
        
        // Clear any pending element annotations since we're starting a new structure
        descriptorAndIndex = null

        // Combine property-level annotations with class-level annotations
        // Property annotations should be applied first (outermost), then class annotations
        val allAnnotations = propertyAnnotations + descriptor.annotations.asn1Layers
        val targetBuffer = processAnnotationsAndGetTarget(allAnnotations)

        val childSerializer = Asn1Serializer(serializersModule)
        val placeholder = Asn1ElementHolder.StructurePlaceholder(childSerializer, descriptor)
        targetBuffer += placeholder
        return childSerializer
    }

    /**
     * Processes current element's annotations recursively and returns the target buffer.
     * Traverses annotations in reverse order, processing one annotation per recursion step.
     * This allows combining implicit tagging, explicit tagging, and octet string wrapping
     * in any desired order, with support for repeating annotations.
     */
    private fun processAnnotationsAndGetTarget(
        annotations: List<Layer>
    ): MutableList<Asn1ElementHolder> {
        return processAnnotationsRecursively(annotations, buffer)
    }

    /**
     * Walks the annotation list from first → last and builds the encoder
     * structure on the fly.
     *
     * * An IMPLICIT_TAG always (re-)wraps the current buffer with an
     *   ImplicitTaggingBuffer. If the buffer is already implicit, the tag is
     *   replaced, so the **latest** implicit tag wins.
     * * OCTET_STRING and EXPLICIT_TAG create nested serializers whose buffers
     *   are then filled recursively.
     * * Any other layer type is skipped.
     */
    private fun processAnnotationsRecursively(
        annotations: List<Layer>,
        targetBuffer: MutableList<Asn1ElementHolder>
    ): MutableList<Asn1ElementHolder> {

        if (annotations.isEmpty()) return targetBuffer

        val current = annotations.first()
        val remaining = annotations.drop(1)

        return when (current.type) {

            Type.IMPLICIT_TAG -> {
                // (Re-)wrap current buffer; newest tag overrides previous ones
                val wrappedBuffer =
                    if (targetBuffer is ImplicitTaggingBuffer)
                        ImplicitTaggingBuffer(targetBuffer, current.tag) // overwrite
                    else
                        ImplicitTaggingBuffer(targetBuffer, current.tag)

                processAnnotationsRecursively(remaining, wrappedBuffer)
            }

            Type.OCTET_STRING -> {
                val childSerializer = Asn1Serializer(serializersModule)
                val placeholder =
                    Asn1ElementHolder.NestedStructurePlaceholder.OctetString(
                        childSerializer,
                        listOf(current)
                    )
                targetBuffer += placeholder
                processAnnotationsRecursively(remaining, childSerializer.buffer)
            }

            Type.EXPLICIT_TAG -> {
                val childSerializer = Asn1Serializer(serializersModule)
                val placeholder =
                    Asn1ElementHolder.NestedStructurePlaceholder.ExplicitTag(
                        current.tag,
                        childSerializer,
                        listOf(current)
                    )
                targetBuffer += placeholder
                processAnnotationsRecursively(remaining, childSerializer.buffer)
            }

            // All other annotations are ignored at this level
            else -> processAnnotationsRecursively(remaining, targetBuffer)
        }
    }


    internal fun writeTo(destination: Sink) {
        val finalizedElements = finalizeElements(buffer)
        finalizedElements.forEach { it.encodeTo(destination) }
    }

private fun finalizeElements(holders: List<Asn1ElementHolder>): List<Asn1Element> {
    return holders.map { holder ->
        finalizeElement(holder)
    }
}

private fun finalizeElement(holder: Asn1ElementHolder): Asn1Element {
    return when (holder) {
        is Asn1ElementHolder.Element -> holder.element

        is Asn1ElementHolder.StructurePlaceholder -> {
            val childElements = finalizeElements(holder.childSerializer.buffer)
            if (holder.descriptor.isAsn1Set) {
                Asn1Set(childElements)
            } else {
                Asn1Sequence(childElements)
            }
        }

        is Asn1ElementHolder.NestedStructurePlaceholder -> {
            val childElements = finalizeElements(holder.childSerializer.buffer)
            when (holder) {
                is Asn1ElementHolder.NestedStructurePlaceholder.OctetString -> Asn1OctetString(childElements)
                is Asn1ElementHolder.NestedStructurePlaceholder.ExplicitTag -> {
                    Asn1ExplicitlyTagged(holder.tag, childElements)
                }
            }
        }

        is Asn1ElementHolder.ImplicitlyTagged -> {
            // Apply implicit tag to the finalized element
            val finalizedElement = finalizeElement(holder.element)
            finalizedElement.withImplicitTag(holder.tag)
        }
    }
}
}

@ExperimentalSerializationApi
fun <T> encodeToAsn1Bytes(serializer: SerializationStrategy<T>, value: T): ByteArray {
    val encoder = Asn1Serializer()
    encoder.encodeSerializableValue(serializer, value)
    return Buffer().also { encoder.writeTo(it) }.readByteArray()
}

@ExperimentalSerializationApi
inline fun <reified T> encodeToDer(value: T) = encodeToAsn1Bytes(serializer(), value)