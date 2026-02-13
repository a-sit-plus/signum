package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.encoding.encodeToAsn1Primitive
import kotlinx.io.Sink
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.InternalSerializationApi
import kotlinx.serialization.SealedClassSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.SerializationStrategy
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.builtins.SetSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.descriptors.PolymorphicKind
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.AbstractEncoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.modules.EmptySerializersModule
import kotlinx.serialization.modules.SerializersModule


/**
 * Holder for ASN.1 elements during serialization process.
 * Can hold either a concrete element or a placeholder that needs to be resolved later.
 */
private sealed class Asn1ElementHolder {
    data class Element(val element: Asn1Element) : Asn1ElementHolder()
    class StructurePlaceholder(
        val childSerializer: DerEncoder,
        val descriptor: SerialDescriptor
    ) : Asn1ElementHolder()

    //really nesting
    sealed class NestedStructurePlaceholder(
        val childSerializer: DerEncoder,
    ) : Asn1ElementHolder() {
        class OctetString(childSerializer: DerEncoder) :
            NestedStructurePlaceholder(childSerializer)

        class ExplicitTag(val tag: ULong, childSerializer: DerEncoder) :
            NestedStructurePlaceholder(childSerializer)
    }

    //overriding tags, not nesting
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
internal class DerEncoder(
    override val serializersModule: SerializersModule = EmptySerializersModule(),
) : AbstractEncoder() {

    private val buffer = mutableListOf<Asn1ElementHolder>()
    private var descriptorAndIndex: Pair<SerialDescriptor, Int>? = null

    private var pendingInlineAnnotation: Asn1nnotation? = null

    @OptIn(ExperimentalSerializationApi::class)
    override fun encodeInline(descriptor: SerialDescriptor): Encoder {
        descriptor.asn1nnotation?.let { pendingInlineAnnotation = it }
        return this
    }

    override fun encodeValue(value: Any) {
        val inlineAnnotation = pendingInlineAnnotation
        pendingInlineAnnotation = null


        // Property-level layers (coming from encodeElement)
        val propertyLayers = descriptorAndIndex
            ?.let { (d, i) ->
                descriptorAndIndex = null
                d.getElementAnnotations(i).asn1Layers
            } ?: emptyList()

        // Combine property layers with inline layers
        val annotations = propertyLayers + (inlineAnnotation?.layers?.toList() ?: emptyList())

        val targetBuffer = processAnnotationsAndGetTarget(annotations)

        val element = when (value) {
            is Asn1Element -> value
            is Asn1Encodable<*> -> value.encodeToTlv()
            is ByteArray -> if (inlineAnnotation?.asBitString == true) Asn1BitString(value).encodeToTlv()
            else Asn1PrimitiveOctetString(value)

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
        val inlineAnnotation = pendingInlineAnnotation
        pendingInlineAnnotation = null

        descriptorAndIndex?.let { (descriptor, index) ->
            descriptorAndIndex = null
            val propertyDescriptor = descriptor.getElementDescriptor(index)
            if (descriptor.asn1nnotation(index)?.encodeNull != true &&
                propertyDescriptor.asn1nnotation?.encodeNull != true
            ) return

            val propertyLayers = descriptor.getElementAnnotations(index).asn1Layers
            val allLayers = propertyLayers + (inlineAnnotation?.layers?.toList() ?: emptyList())

            val targetBuffer = processAnnotationsAndGetTarget(allLayers)
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
                ?: emptyList()) + enumDescriptor.annotations.asn1Layers
        )
        targetBuffer += Asn1ElementHolder.Element(Asn1.Enumerated(index))
    }


    override fun <T> encodeSerializableValue(serializer: SerializationStrategy<T>, value: T) {
        if (value == null) {
            val propertyEncodesNull = descriptorAndIndex?.let { (descriptor, index) ->
                descriptor.asn1nnotation(index)?.encodeNull == true ||
                        descriptor.getElementDescriptor(index).asn1nnotation?.encodeNull == true
            } ?: false

            if (serializer.descriptor.asn1nnotation?.encodeNull == true || propertyEncodesNull) {
                // Handle null values with layers similar to encodeNull()
                val inlineAnnotation = pendingInlineAnnotation
                pendingInlineAnnotation = null

                // Get property-level annotations
                val propertyLayers = descriptorAndIndex?.let { (descriptor, index) ->
                    descriptor.getElementAnnotations(index).asn1Layers
                } ?: emptyList()

                // Get class-level annotations
                val classLayers = serializer.descriptor.annotations.asn1Layers

                // Combine property-level annotations with inline and class-level annotations
                val allLayers = propertyLayers + (inlineAnnotation?.layers?.toList() ?: emptyList()) + classLayers

                // Process annotations and get target buffer
                val targetBuffer = processAnnotationsAndGetTarget(allLayers)

                // Add Asn1.Null() to the target buffer
                targetBuffer += Asn1ElementHolder.Element(Asn1.Null())
            }
            return
        }

        val inlineAnnotation = pendingInlineAnnotation
        if (shouldEncodeAsChoice(serializer.descriptor, inlineAnnotation)) {
            encodeChoiceSerializableValue(serializer, value, inlineAnnotation)
            return
        }

        if (serializer.descriptor == ByteArraySerializer().descriptor) {
            val bitset = descriptorAndIndex?.let { (descriptor, index) ->
                descriptor.isAsn1BitString(index)
            } ?: serializer.descriptor.isAsn1BitString
            if (bitset) encodeValue(Asn1BitString(value as ByteArray))
            else encodeValue(value as ByteArray)
        } else if (value is Asn1Encodable<*> || value is Asn1Element) encodeValue(value)
        else super.encodeSerializableValue(serializer, value as T)
    }

    private fun shouldEncodeAsChoice(
        descriptor: SerialDescriptor,
        inlineAnnotation: Asn1nnotation?
    ): Boolean {
        val propertyAnnotation = descriptorAndIndex?.let { (parentDescriptor, index) ->
            parentDescriptor.asn1nnotation(index)
        }
        return inlineAnnotation?.asChoice == true ||
                propertyAnnotation?.asChoice == true ||
                descriptor.asn1nnotation?.asChoice == true
    }

    @OptIn(InternalSerializationApi::class)
    @Suppress("UNCHECKED_CAST")
    private fun <T> encodeChoiceSerializableValue(
        serializer: SerializationStrategy<T>,
        value: T,
        inlineAnnotation: Asn1nnotation?
    ) {
        pendingInlineAnnotation = null

        if (serializer.descriptor.kind !is PolymorphicKind.SEALED) {
            throw SerializationException(
                "@Asn1nnotation(asChoice=true) requires a sealed polymorphic serializer, but got ${serializer.descriptor.kind}"
            )
        }
        val sealedSerializer = serializer as? SealedClassSerializer<T>
            ?: throw SerializationException(
                "@Asn1nnotation(asChoice=true) only supports kotlinx SealedClassSerializer"
            )

        val propertyLayers = descriptorAndIndex?.let { (parentDescriptor, index) ->
            parentDescriptor.getElementAnnotations(index).asn1Layers
        } ?: emptyList()
        descriptorAndIndex = null

        val classLayers = serializer.descriptor.annotations.asn1Layers
        val allLayers = propertyLayers + (inlineAnnotation?.layers?.toList() ?: emptyList()) + classLayers
        val targetBuffer = processAnnotationsAndGetTarget(allLayers)

        val selectedSerializer = sealedSerializer.findPolymorphicSerializerOrNull(this, value)
            ?: throw SerializationException(
                "Could not resolve concrete serializer for CHOICE value of ${serializer.descriptor.serialName}: ${(value as Any)::class}"
            )

        val childSerializer = DerEncoder(serializersModule)
        childSerializer.encodeSerializableValue(selectedSerializer as SerializationStrategy<Any?>, value as Any?)
        val elements = childSerializer.encodeToTLV()
        if (elements.size != 1) {
            throw SerializationException(
                "ASN.1 CHOICE arm must encode to exactly one element, got ${elements.size} for ${selectedSerializer.descriptor.serialName}"
            )
        }

        targetBuffer += Asn1ElementHolder.Element(elements.first())
    }

    override fun beginStructure(descriptor: SerialDescriptor): DerEncoder {
        if (descriptor.kind is kotlinx.serialization.descriptors.StructureKind.CLASS ||
            descriptor.kind is kotlinx.serialization.descriptors.StructureKind.OBJECT
        ) {
            descriptor.ensureNoAsn1AmbiguousOptionalLayout()
        }
        // Get property-level annotations BEFORE clearing descriptorAndIndex
        val propertyAnnotations = descriptorAndIndex?.let { (descriptor, index) ->
            descriptorAndIndex = null
            descriptor.getElementAnnotations(index).asn1Layers
        } ?: emptyList()

        // Combine property-level annotations with class-level annotations
        // Property annotations should be applied first (outermost), then class annotations
        val allAnnotations = propertyAnnotations + descriptor.annotations.asn1Layers
        val targetBuffer = processAnnotationsAndGetTarget(allAnnotations)

        val childSerializer = DerEncoder(serializersModule)
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

            Type.IMPLICIT_TAG ->
                // (Re-)wrap current buffer; newest tag overrides previous ones
                processAnnotationsRecursively(remaining, ImplicitTaggingBuffer(targetBuffer, current.tag))

            Type.OCTET_STRING -> {
                val childSerializer = DerEncoder(serializersModule)
                targetBuffer += Asn1ElementHolder.NestedStructurePlaceholder.OctetString(
                    childSerializer
                )
                processAnnotationsRecursively(remaining, childSerializer.buffer)
            }

            Type.EXPLICIT_TAG -> {
                val childSerializer = DerEncoder(serializersModule)
                targetBuffer += Asn1ElementHolder.NestedStructurePlaceholder.ExplicitTag(
                    current.tag,
                    childSerializer
                )
                processAnnotationsRecursively(remaining, childSerializer.buffer)
            }
        }
    }

    internal fun writeTo(destination: Sink) {
        encodeToTLV().forEach { it.encodeTo(destination) }
    }

    //exists to keep the below function
    internal fun encodeToTLV() = buffer.finalizeElements()

    private fun List<Asn1ElementHolder>.finalizeElements(): List<Asn1Element> = map(::finalizeElement)


    private fun finalizeElement(holder: Asn1ElementHolder): Asn1Element {

        return when (holder) {
            is Asn1ElementHolder.Element -> holder.element

            is Asn1ElementHolder.StructurePlaceholder -> {
                val childElements = holder.childSerializer.buffer.finalizeElements()
                if (holder.descriptor.isSetDescriptor) Asn1Set(childElements)
                else Asn1Sequence(childElements)

            }

            is Asn1ElementHolder.NestedStructurePlaceholder -> {
                val childElements = holder.childSerializer.buffer.finalizeElements()
                when (holder) {
                    is Asn1ElementHolder.NestedStructurePlaceholder.OctetString ->
                        Asn1OctetString(childElements)

                    is Asn1ElementHolder.NestedStructurePlaceholder.ExplicitTag ->
                        Asn1ExplicitlyTagged(holder.tag, childElements)

                }
            }

            // Apply implicit tag to the finalized element
            is Asn1ElementHolder.ImplicitlyTagged ->
                finalizeElement(holder.element).withImplicitTag(holder.tag)

        }
    }
}

private val setDescriptor: SerialDescriptor = SetSerializer(String.serializer()).descriptor
internal val SerialDescriptor.isSetDescriptor: Boolean get() = setDescriptor::class.isInstance(this)
