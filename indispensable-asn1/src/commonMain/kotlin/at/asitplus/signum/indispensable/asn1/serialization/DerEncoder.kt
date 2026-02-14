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
import kotlinx.serialization.descriptors.PolymorphicKind
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.AbstractEncoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.modules.EmptySerializersModule
import kotlinx.serialization.modules.SerializersModule
import kotlin.time.Instant


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

    private val inlineHintState = DerInlineHintState()

    @OptIn(ExperimentalSerializationApi::class)
    override fun encodeInline(descriptor: SerialDescriptor): Encoder {
        inlineHintState.recordFrom(descriptor)
        return this
    }

    override fun encodeValue(value: Any) {
        val inlineHints = inlineHintState.consume()

        val descriptorIndexSnapshot = descriptorAndIndex
        val propertyAnnotation = descriptorIndexSnapshot?.let { (descriptor, index) ->
            descriptor.asn1Tag(index)
        }
        val propertyAsBitString = descriptorIndexSnapshot?.let { (descriptor, index) ->
            descriptor.isAsn1BitString(index)
        } ?: false
        descriptorAndIndex = null

        if ((inlineHints.asBitString || propertyAsBitString) && value !is ByteArray) {
            throw SerializationException(
                "@Asn1BitString can only be used with ByteArray-compatible values, but got ${value::class}"
            )
        }
        val tagTemplate = resolveAsn1TagTemplate(
            inlineAsn1Tag = inlineHints.tag,
            propertyAsn1Tag = propertyAnnotation,
            classAsn1Tag = null
        )

        val element = when (value) {
            is Asn1Element -> value
            is Asn1Encodable<*> -> value.encodeToTlv()
            is ByteArray -> if (inlineHints.asBitString) Asn1BitString(value).encodeToTlv()
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
        val inlineHints = inlineHintState.consume()

        descriptorAndIndex?.let { (descriptor, index) ->
            descriptorAndIndex = null
            val propertyDescriptor = descriptor.getElementDescriptor(index)
            val propertyAnnotation = descriptor.asn1Tag(index)
            val nullEncodingAnalysis = propertyDescriptor.analyzeAsn1NullableNullEncoding(
                propertyAsn1Tag = propertyAnnotation,
                inlineAsn1Tag = inlineHints.tag,
                propertyAsBitString = descriptor.isAsn1BitString(index),
                inlineAsBitString = inlineHints.asBitString,
                formatExplicitNulls = formatConfiguration.explicitNulls,
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
                inlineAsn1Tag = inlineHints.tag,
                propertyAsn1Tag = propertyAnnotation,
                classAsn1Tag = propertyDescriptor.asn1Tag,
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
            ?.let { (descriptor, elementIndex) -> descriptor.asn1Tag(elementIndex) }
            .also { descriptorAndIndex = null }
        val tagTemplate = resolveAsn1TagTemplate(
            propertyAsn1Tag = propertyAnnotation,
            classAsn1Tag = enumDescriptor.asn1Tag,
        )
        val element = tagTemplate?.let { Asn1.Enumerated(index).withImplicitTag(it) } ?: Asn1.Enumerated(index)
        buffer += Asn1ElementHolder.Element(element)
    }


    override fun <T> encodeSerializableValue(serializer: SerializationStrategy<T>, value: T) {
        val inlineHints = inlineHintState.consume()
        val descriptorAndIndexSnapshot = descriptorAndIndex
        val propertyAnnotation = descriptorAndIndexSnapshot?.let { (descriptor, index) ->
            descriptor.asn1Tag(index)
        }
        val propertyAsBitString = descriptorAndIndexSnapshot?.let { (descriptor, index) ->
            descriptor.isAsn1BitString(index)
        } ?: false
        val propertyAsChoice = descriptorAndIndexSnapshot?.let { (descriptor, index) ->
            descriptor.isAsn1Choice(index)
        } ?: false
        val propertyDescriptor = descriptorAndIndexSnapshot?.let { (descriptor, index) ->
            descriptor.getElementDescriptor(index)
        }
        val bitStringRequested = inlineHints.asBitString || propertyAsBitString || serializer.descriptor.isAsn1BitString
        if (bitStringRequested && !serializer.descriptor.isAsn1BitStringCompatibleDescriptor()) {
            throw SerializationException(
                "@Asn1BitString can only be used with ByteArray-compatible serializers, but got ${serializer.descriptor.serialName}"
            )
        }
        val effectiveTagTemplate = resolveAsn1TagTemplate(
            inlineAsn1Tag = inlineHints.tag,
            propertyAsn1Tag = propertyAnnotation,
            classAsn1Tag = serializer.descriptor.asn1Tag,
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
            propertyAsn1Tag = propertyAnnotation,
            inlineAsn1Tag = inlineHints.tag,
            propertyAsBitString = propertyAsBitString,
            inlineAsBitString = inlineHints.asBitString,
            formatExplicitNulls = formatConfiguration.explicitNulls,
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

        if (value is Instant && serializer.descriptor.isKotlinTimeInstantDescriptor()) {
            val timeElement = Asn1Time(value).encodeToTlv()
            val taggedElement = effectiveTagTemplate?.let { timeElement.withImplicitTag(it) } ?: timeElement
            buffer += Asn1ElementHolder.Element(taggedElement)
            descriptorAndIndex = null
            return
        }

        if (isAsn1ChoiceRequested(serializer.descriptor, inlineHints.asChoice, propertyAsChoice)) {
            encodeChoiceSerializableValue(
                serializer = serializer,
                value = value,
                inlineAnnotation = inlineHints.tag,
                propertyAnnotation = propertyAnnotation,
            )
            return
        }

        if (serializer.descriptor == ByteArraySerializer().descriptor) {
            val bitset = bitStringRequested
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

    @OptIn(InternalSerializationApi::class)
    @Suppress("UNCHECKED_CAST")
    private fun <T> encodeChoiceSerializableValue(
        serializer: SerializationStrategy<T>,
        value: T,
        inlineAnnotation: Asn1Tag?,
        propertyAnnotation: Asn1Tag?,
    ) {
        if (serializer.descriptor.kind !is PolymorphicKind.SEALED) {
            throw SerializationException(
                "@Asn1Choice requires a sealed polymorphic serializer, but got ${serializer.descriptor.kind}"
            )
        }
        val sealedSerializer = serializer as? SealedClassSerializer<Any>
            ?: throw SerializationException(
                "@Asn1Choice only supports kotlinx SealedClassSerializer"
            )

        descriptorAndIndex = null

        val tagTemplate = resolveAsn1TagTemplate(
            inlineAsn1Tag = inlineAnnotation,
            propertyAsn1Tag = propertyAnnotation,
            classAsn1Tag = serializer.descriptor.asn1Tag,
        )
        val selectedSerializer = sealedSerializer.findPolymorphicSerializerOrNull(this, value as Any)
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
            descriptor.ensureNoAsn1AmbiguousOptionalLayout(
                formatExplicitNulls = formatConfiguration.explicitNulls,
            )
        }
        val inlineAnnotation = inlineHintState.consume().tag
        val propertyAnnotation = descriptorAndIndex?.let { (parentDescriptor, index) ->
            parentDescriptor.asn1Tag(index)
        }
        descriptorAndIndex = null
        val tagTemplate = resolveAsn1TagTemplate(
            inlineAsn1Tag = inlineAnnotation,
            propertyAsn1Tag = propertyAnnotation,
            classAsn1Tag = descriptor.asn1Tag,
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
