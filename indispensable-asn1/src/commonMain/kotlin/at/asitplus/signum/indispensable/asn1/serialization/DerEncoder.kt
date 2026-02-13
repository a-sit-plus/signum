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
        val descriptor: SerialDescriptor,
        val tagTemplate: Asn1Element.Tag.Template?,
    ) : Asn1ElementHolder()
}


@ExperimentalSerializationApi
internal class DerEncoder(
    override val serializersModule: SerializersModule = EmptySerializersModule(),
    private val formatConfiguration: DerConfiguration = DerConfiguration(),
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

        val propertyAnnotation = descriptorAndIndex
            ?.let { (descriptor, index) -> descriptor.asn1nnotation(index) }
            .also { descriptorAndIndex = null }
        val tagTemplate = resolveAsn1TagTemplate(
            inlineAsn1nnotation = inlineAnnotation,
            propertyAsn1nnotation = propertyAnnotation,
            classAsn1nnotation = null
        )

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

        val taggedElement = tagTemplate?.let { element.withImplicitTag(it) } ?: element
        buffer += Asn1ElementHolder.Element(taggedElement)
    }

    override fun encodeNull() {
        val inlineAnnotation = pendingInlineAnnotation
        pendingInlineAnnotation = null

        descriptorAndIndex?.let { (descriptor, index) ->
            descriptorAndIndex = null
            val propertyDescriptor = descriptor.getElementDescriptor(index)
            val propertyAnnotation = descriptor.asn1nnotation(index)
            val nullEncodingAnalysis = propertyDescriptor.analyzeAsn1NullableNullEncoding(
                propertyAsn1nnotation = propertyAnnotation,
                inlineAsn1nnotation = inlineAnnotation,
            )
            if (nullEncodingAnalysis.isAmbiguous) {
                throw SerializationException(
                    ambiguousAsn1NullEncodingMessage(
                        ownerSerialName = descriptor.serialName,
                        propertyName = descriptor.getElementName(index),
                        propertyIndex = index,
                    )
                )
            }
            if (!nullEncodingAnalysis.encodeNullEnabled) return

            val tagTemplate = resolveAsn1TagTemplate(
                inlineAsn1nnotation = inlineAnnotation,
                propertyAsn1nnotation = propertyAnnotation,
                classAsn1nnotation = propertyDescriptor.asn1nnotation,
            )
            val nullElement = tagTemplate?.let { Asn1.Null().withImplicitTag(it) } ?: Asn1.Null()
            buffer += Asn1ElementHolder.Element(nullElement)
        }
    }

    override fun encodeElement(descriptor: SerialDescriptor, index: Int): Boolean {
        this.descriptorAndIndex = descriptor to index
        return super.encodeElement(descriptor, index)
    }

    override fun shouldEncodeElementDefault(descriptor: SerialDescriptor, index: Int): Boolean =
        formatConfiguration.encodeDefaults

    override fun encodeEnum(enumDescriptor: SerialDescriptor, index: Int) {
        val propertyAnnotation = descriptorAndIndex
            ?.let { (descriptor, elementIndex) -> descriptor.asn1nnotation(elementIndex) }
            .also { descriptorAndIndex = null }
        val tagTemplate = resolveAsn1TagTemplate(
            propertyAsn1nnotation = propertyAnnotation,
            classAsn1nnotation = enumDescriptor.asn1nnotation,
        )
        val element = tagTemplate?.let { Asn1.Enumerated(index).withImplicitTag(it) } ?: Asn1.Enumerated(index)
        buffer += Asn1ElementHolder.Element(element)
    }


    override fun <T> encodeSerializableValue(serializer: SerializationStrategy<T>, value: T) {
        val inlineAnnotation = pendingInlineAnnotation
        pendingInlineAnnotation = null
        val descriptorAndIndexSnapshot = descriptorAndIndex
        val propertyAnnotation = descriptorAndIndexSnapshot?.let { (descriptor, index) ->
            descriptor.asn1nnotation(index)
        }
        val propertyDescriptor = descriptorAndIndexSnapshot?.let { (descriptor, index) ->
            descriptor.getElementDescriptor(index)
        }
        val effectiveTagTemplate = resolveAsn1TagTemplate(
            inlineAsn1nnotation = inlineAnnotation,
            propertyAsn1nnotation = propertyAnnotation,
            classAsn1nnotation = serializer.descriptor.asn1nnotation,
        )
        requireAsn1ExplicitWrapperTag(
            descriptor = serializer.descriptor,
            tagTemplate = effectiveTagTemplate,
            ownerSerialName = descriptorAndIndexSnapshot?.first?.serialName ?: serializer.descriptor.serialName,
        )
        val nullAnalysisDescriptor = when {
            serializer.descriptor.isNullable -> serializer.descriptor
            propertyDescriptor?.isNullable == true -> propertyDescriptor
            else -> serializer.descriptor
        }
        val nullEncodingAnalysis = nullAnalysisDescriptor.analyzeAsn1NullableNullEncoding(
            propertyAsn1nnotation = propertyAnnotation,
            inlineAsn1nnotation = inlineAnnotation
        )
        if (nullEncodingAnalysis.isAmbiguous) {
            throw SerializationException(
                ambiguousAsn1NullEncodingMessage(
                    ownerSerialName = descriptorAndIndexSnapshot?.first?.serialName ?: serializer.descriptor.serialName,
                    propertyName = descriptorAndIndexSnapshot?.let { (descriptor, index) -> descriptor.getElementName(index) },
                    propertyIndex = descriptorAndIndexSnapshot?.second,
                )
            )
        }

        if (value == null) {
            if (!nullEncodingAnalysis.encodeNullEnabled) {
                descriptorAndIndex = null
                return
            }

            val nullElement = effectiveTagTemplate?.let { Asn1.Null().withImplicitTag(it) } ?: Asn1.Null()
            buffer += Asn1ElementHolder.Element(nullElement)
            descriptorAndIndex = null
            return
        }

        if (shouldEncodeAsChoice(serializer.descriptor, inlineAnnotation, propertyAnnotation)) {
            encodeChoiceSerializableValue(
                serializer = serializer,
                value = value,
                inlineAnnotation = inlineAnnotation,
                propertyAnnotation = propertyAnnotation,
            )
            return
        }

        if (serializer.descriptor == ByteArraySerializer().descriptor) {
            val bitset = inlineAnnotation?.asBitString == true ||
                    propertyAnnotation?.asBitString == true ||
                    (descriptorAndIndexSnapshot?.let { (descriptor, index) ->
                        descriptor.isAsn1BitString(index)
                    } ?: serializer.descriptor.isAsn1BitString)
            val byteArrayValue = value as ByteArray
            val baseElement: Asn1Element = if (bitset) Asn1BitString(byteArrayValue).encodeToTlv()
            else Asn1PrimitiveOctetString(byteArrayValue)
            val taggedElement = effectiveTagTemplate?.let { baseElement.withImplicitTag(it) } ?: baseElement
            buffer += Asn1ElementHolder.Element(taggedElement)
            descriptorAndIndex = null
            return
        } else if (value is Asn1Encodable<*> || value is Asn1Element) encodeValue(value)
        else super.encodeSerializableValue(serializer, value as T)
    }

    private fun shouldEncodeAsChoice(
        descriptor: SerialDescriptor,
        inlineAnnotation: Asn1nnotation?,
        propertyAnnotation: Asn1nnotation?,
    ): Boolean {
        return inlineAnnotation?.asChoice == true ||
                propertyAnnotation?.asChoice == true ||
                descriptor.asn1nnotation?.asChoice == true
    }

    @OptIn(InternalSerializationApi::class)
    @Suppress("UNCHECKED_CAST")
    private fun <T> encodeChoiceSerializableValue(
        serializer: SerializationStrategy<T>,
        value: T,
        inlineAnnotation: Asn1nnotation?,
        propertyAnnotation: Asn1nnotation?,
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

        descriptorAndIndex = null

        val tagTemplate = resolveAsn1TagTemplate(
            inlineAsn1nnotation = inlineAnnotation,
            propertyAsn1nnotation = propertyAnnotation,
            classAsn1nnotation = serializer.descriptor.asn1nnotation,
        )

        val selectedSerializer = sealedSerializer.findPolymorphicSerializerOrNull(this, value)
            ?: throw SerializationException(
                "Could not resolve concrete serializer for CHOICE value of ${serializer.descriptor.serialName}: ${(value as Any)::class}"
            )

        val childSerializer = DerEncoder(
            serializersModule = serializersModule,
            formatConfiguration = formatConfiguration
        )
        childSerializer.encodeSerializableValue(selectedSerializer as SerializationStrategy<Any?>, value as Any?)
        val elements = childSerializer.encodeToTLV()
        if (elements.size != 1) {
            throw SerializationException(
                "ASN.1 CHOICE arm must encode to exactly one element, got ${elements.size} for ${selectedSerializer.descriptor.serialName}"
            )
        }

        val element = tagTemplate?.let { elements.first().withImplicitTag(it) } ?: elements.first()
        buffer += Asn1ElementHolder.Element(element)
    }

    override fun beginStructure(descriptor: SerialDescriptor): DerEncoder {
        if (descriptor.kind is kotlinx.serialization.descriptors.StructureKind.CLASS ||
            descriptor.kind is kotlinx.serialization.descriptors.StructureKind.OBJECT
        ) {
            descriptor.ensureNoAsn1AmbiguousOptionalLayout()
        }
        val inlineAnnotation = pendingInlineAnnotation
        pendingInlineAnnotation = null
        val propertyAnnotation = descriptorAndIndex?.let { (parentDescriptor, index) ->
            parentDescriptor.asn1nnotation(index)
        }
        descriptorAndIndex = null
        val tagTemplate = resolveAsn1TagTemplate(
            inlineAsn1nnotation = inlineAnnotation,
            propertyAsn1nnotation = propertyAnnotation,
            classAsn1nnotation = descriptor.asn1nnotation,
        )

        val childSerializer = DerEncoder(
            serializersModule = serializersModule,
            formatConfiguration = formatConfiguration
        )
        val placeholder = Asn1ElementHolder.StructurePlaceholder(
            childSerializer = childSerializer,
            descriptor = descriptor,
            tagTemplate = tagTemplate,
        )
        buffer += placeholder
        return childSerializer
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
                val structureElement = if (holder.descriptor.isSetDescriptor) Asn1Set(childElements) else Asn1Sequence(childElements)
                holder.tagTemplate?.let { structureElement.withImplicitTag(it) } ?: structureElement
            }

        }
    }
}

private fun requireAsn1ExplicitWrapperTag(
    descriptor: SerialDescriptor,
    tagTemplate: Asn1Element.Tag.Template?,
    ownerSerialName: String,
) {
    if (!descriptor.isAsn1ExplicitWrapperDescriptor()) return
    if (tagTemplate == null) {
        throw SerializationException(
            "Asn1Explicit requires an implicit tag override in $ownerSerialName. " +
                    "Provide @Asn1nnotation(tagNumber=..., tagClass=CONTEXT_SPECIFIC, constructed=CONSTRUCTED)."
        )
    }
    val effectiveClass = tagTemplate.tagClass ?: TagClass.UNIVERSAL
    val effectiveConstructed = tagTemplate.constructed ?: true
    if (effectiveClass != TagClass.CONTEXT_SPECIFIC || !effectiveConstructed) {
        throw SerializationException(
            "Asn1Explicit requires CONTEXT_SPECIFIC + CONSTRUCTED tag in $ownerSerialName, " +
                    "but effective override is class=$effectiveClass, constructed=$effectiveConstructed."
        )
    }
}

private val setDescriptor: SerialDescriptor = SetSerializer(String.serializer()).descriptor
internal val SerialDescriptor.isSetDescriptor: Boolean get() = setDescriptor::class.isInstance(this)
