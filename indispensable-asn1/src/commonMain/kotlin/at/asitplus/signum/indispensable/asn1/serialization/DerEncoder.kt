package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.encoding.encodeToAsn1Primitive
import kotlinx.io.Sink
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.InternalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SealedClassSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.SerializationStrategy
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.descriptors.PolymorphicKind
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.AbstractEncoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.internal.AbstractPolymorphicSerializer
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
    private var prependOid: ObjectIdentifier? = null
    internal fun prependOidToNextStructure(oid: ObjectIdentifier) {
       prependOid = oid
    }



    @OptIn(ExperimentalSerializationApi::class)
    override fun encodeInline(descriptor: SerialDescriptor): Encoder {
        inlineHintState.recordFrom(descriptor)
        return this
    }

    override fun encodeBoolean(value: Boolean) {
        encodeValue(value)
    }

    override fun encodeByte(value: Byte) {
        encodeValue(value)
    }

    override fun encodeShort(value: Short) {
        encodeValue(value)
    }

    override fun encodeInt(value: Int) {
        encodeValue(value)
    }

    override fun encodeLong(value: Long) {
        encodeValue(value)
    }

    override fun encodeDouble(value: Double) {
        encodeRealValue(value.encodeToAsn1Primitive())
    }

    override fun encodeFloat(value: Float) {
        encodeRealValue(value.encodeToAsn1Primitive())
    }

    override fun encodeChar(value: Char) {
        encodeValue(value)
    }

    override fun encodeString(value: String) {
        encodeValue(value)
    }

    override fun encodeValue(value: Any) {
        val inlineHints = inlineHintState.consume()
        val propertyContext = consumePropertyContextOrNull()
        val propertyAsBitString = propertyContext?.propertyAsBitString == true

        if ((inlineHints.asBitString || propertyAsBitString) && value !is ByteArray) {
            throw SerializationException(
                "@Asn1BitString can only be used with ByteArray-compatible values, but got ${value::class}"
            )
        }
        val tagTemplate = resolveAsn1TagTemplate(
            inlineAsn1Tag = inlineHints.tag,
            propertyAsn1Tag = propertyContext?.propertyAsn1Tag,
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

        appendElement(element, tagTemplate)
    }

    private fun encodeRealValue(element: Asn1Element) {
        val inlineHints = inlineHintState.consume()
        val propertyContext = consumePropertyContextOrNull()
        val propertyAsBitString = propertyContext?.propertyAsBitString == true
        if (inlineHints.asBitString || propertyAsBitString) {
            throw SerializationException(
                "@Asn1BitString can only be used with ByteArray-compatible values, but got ${element::class}"
            )
        }
        val tagTemplate = resolveAsn1TagTemplate(
            inlineAsn1Tag = inlineHints.tag,
            propertyAsn1Tag = propertyContext?.propertyAsn1Tag,
            classAsn1Tag = null
        )
        appendElement(element, tagTemplate)
    }

    override fun encodeNull() {
        val inlineHints = inlineHintState.consume()
        val propertyContext = consumePropertyContextOrNull() ?: return
        val propertyDescriptor = propertyContext.propertyDescriptor
        val nullEncodingAnalysis = propertyDescriptor.analyzeAsn1NullableNullEncoding(
            propertyAsn1Tag = propertyContext.propertyAsn1Tag,
            inlineAsn1Tag = inlineHints.tag,
            propertyAsBitString = propertyContext.propertyAsBitString,
            inlineAsBitString = inlineHints.asBitString,
            formatExplicitNulls = formatConfiguration.explicitNulls,
        )
        if (nullEncodingAnalysis.isAmbiguous) {
            throw SerializationException(
                ambiguousAsn1NullEncodingMessage(
                    ownerSerialName = propertyContext.ownerSerialName,
                    propertyName = propertyContext.propertyName ?: propertyDescriptor.serialName,
                    propertyIndex = propertyContext.index,
                )
            )
        }
        if (!nullEncodingAnalysis.encodeNullEnabled) return

        val tagTemplate = resolveAsn1TagTemplate(
            inlineAsn1Tag = inlineHints.tag,
            propertyAsn1Tag = propertyContext.propertyAsn1Tag,
            classAsn1Tag = propertyDescriptor.asn1Tag,
        )
        appendElement(Asn1.Null(), tagTemplate)
    }

    override fun encodeElement(descriptor: SerialDescriptor, index: Int): Boolean {
        this.descriptorAndIndex = descriptor to index
        return super.encodeElement(descriptor, index)
    }

    override fun shouldEncodeElementDefault(descriptor: SerialDescriptor, index: Int): Boolean =
        formatConfiguration.encodeDefaults

    override fun encodeEnum(enumDescriptor: SerialDescriptor, index: Int) {
        val propertyAnnotation = consumePropertyContextOrNull()?.propertyAsn1Tag
        val tagTemplate = resolveAsn1TagTemplate(
            propertyAsn1Tag = propertyAnnotation,
            classAsn1Tag = enumDescriptor.asn1Tag,
        )
        appendElement(Asn1.Enumerated(index), tagTemplate)
    }


    override fun <T> encodeSerializableValue(serializer: SerializationStrategy<T>, value: T) {
        val inlineHints = inlineHintState.consume()
        val propertyContext = descriptorAndIndex?.toDerPropertyContext()
        val propertyAnnotation = propertyContext?.propertyAsn1Tag
        val propertyAsBitString = propertyContext?.propertyAsBitString == true
        val propertyAsChoice = propertyContext?.propertyAsChoice == true
        val propertyDescriptor = propertyContext?.propertyDescriptor
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
            ownerSerialName = propertyContext?.ownerSerialName ?: serializer.descriptor.serialName,
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
                    ownerSerialName = propertyContext?.ownerSerialName ?: serializer.descriptor.serialName,
                    propertyName = propertyContext?.propertyName,
                    propertyIndex = propertyContext?.index,
                )
            )
        }

        if (value == null) {
            if (!nullEncodingAnalysis.encodeNullEnabled) {
                descriptorAndIndex = null
                return
            }

            descriptorAndIndex = null
            appendElement(Asn1.Null(), effectiveTagTemplate)
            return
        }

        if (value is Instant && serializer.descriptor.isKotlinTimeInstantDescriptor()) {
            descriptorAndIndex = null
            val timeElement = Asn1Time(value).encodeToTlv()
            appendElement(timeElement, effectiveTagTemplate)
            return
        }

        resolveOpenPolymorphicAsn1SerializerOrNull(serializer)?.let { openSerializer ->
            if (openSerializer.descriptor == serializer.descriptor) {
                throw SerializationException(
                    "Open polymorphism for ${serializer.descriptor.serialName} resolved to itself. " +
                            "Register an ASN.1 open-polymorphic serializer in DER { serializersModule = ... }."
                )
            }
            @Suppress("UNCHECKED_CAST")
            return encodeSerializableValue(openSerializer as SerializationStrategy<T>, value)
        }

        if (serializer.descriptor.kind is PolymorphicKind.OPEN) {
            throw SerializationException(
                "Open polymorphism for ${serializer.descriptor.serialName} requires an ASN.1 serializer " +
                        "registered in DER { serializersModule = ... } via polymorphicByTag(...) " +
                        "or polymorphicByOid(...)."
            )
        }

        if (isAsn1ChoiceRequested(serializer.descriptor, inlineHints.asChoice, propertyAsChoice)) {
            descriptorAndIndex = null
            encodeChoiceSerializableValue(
                serializer = serializer,
                value = value,
                inlineAnnotation = inlineHints.tag,
                propertyAnnotation = propertyAnnotation,
            )
            return
        }

        if (serializer.descriptor == ByteArraySerializer().descriptor) {
            descriptorAndIndex = null
            val byteArrayValue = value as ByteArray
            val baseElement: Asn1Element = if (bitStringRequested) Asn1BitString(byteArrayValue).encodeToTlv()
            else Asn1PrimitiveOctetString(byteArrayValue)
            appendElement(baseElement, effectiveTagTemplate)
            return
        } else if (value is Asn1Encodable<*> || value is Asn1Element) {
            descriptorAndIndex = null
            val baseElement = when (value) {
                is Asn1Element -> value
                is Asn1Encodable<*> -> value.encodeToTlv()
                else -> error("unreachable")
            }
            appendElement(baseElement, effectiveTagTemplate)
        }
        else super.encodeSerializableValue(serializer, value as T)
    }

    @OptIn(InternalSerializationApi::class)
    private fun <T> resolveOpenPolymorphicAsn1SerializerOrNull(
        serializer: SerializationStrategy<T>,
    ): SerializationStrategy<*>? {
        if (serializer.descriptor.kind !is PolymorphicKind.OPEN) return null
        val polymorphicSerializer = serializer as? AbstractPolymorphicSerializer<*> ?: return null
        return serializersModule.getContextual(polymorphicSerializer.baseClass, emptyList())
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
                "ASN.1 CHOICE requires a sealed polymorphic serializer, but got ${serializer.descriptor.kind}"
            )
        }
        val sealedSerializer = serializer as? SealedClassSerializer<Any>
            ?: throw SerializationException(
                "ASN.1 CHOICE only supports kotlinx SealedClassSerializer"
            )

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

        appendElement(elements.first(), tagTemplate)
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
        val propertyAnnotation = consumePropertyContextOrNull()?.propertyAsn1Tag
        val tagTemplate = resolveAsn1TagTemplate(
            inlineAsn1Tag = inlineAnnotation,
            propertyAsn1Tag = propertyAnnotation,
            classAsn1Tag = descriptor.asn1Tag,
        )

        val childSerializer = DerEncoder(
            serializersModule = serializersModule,
            formatConfiguration = formatConfiguration
        )

        prependOid?.let { elem ->
            // prepend as the *first* element in the child structure
            childSerializer.buffer.add(0, Asn1ElementHolder.Element(elem.encodeToTlv()))
            prependOid = null
        }

        val placeholder = Asn1ElementHolder.StructurePlaceholder(
            childSerializer = childSerializer,
            descriptor = descriptor,
            tagTemplate = tagTemplate,
        )
        buffer += placeholder
        return childSerializer
    }

    private fun consumePropertyContextOrNull(): DerPropertyContext? =
        descriptorAndIndex?.toDerPropertyContext().also { descriptorAndIndex = null }

    private fun appendElement(
        element: Asn1Element,
        tagTemplate: Asn1Element.Tag.Template? = null,
    ) {
        val taggedElement = tagTemplate?.let { element.withImplicitTag(it) } ?: element
        buffer += Asn1ElementHolder.Element(taggedElement)
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
