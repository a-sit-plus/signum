package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.encoding.*
import kotlinx.io.Source
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.InternalSerializationApi
import kotlinx.serialization.SealedClassSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.descriptors.*
import kotlinx.serialization.encoding.AbstractDecoder
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.modules.EmptySerializersModule
import kotlinx.serialization.modules.SerializersModule


@ExperimentalSerializationApi
/**
 * ASN.1 DER decoder used by [Der] format operations.
 *
 * This decoder supports:
 * - annotation-driven implicit tag override processing via [Asn1Tag]
 * - sealed CHOICE decoding via [Asn1Choice]
 * - runtime ambiguity checks for nullable/optional class layouts
 */
class DerDecoder internal constructor(
    private val elements: List<Asn1Element>,
    override val serializersModule: SerializersModule = EmptySerializersModule()
) : AbstractDecoder() {

    private data class InlineHints(
        val tag: Asn1Tag?,
        val asBitString: Boolean,
        val encodeNull: Boolean,
        val asChoice: Boolean,
    )


    internal constructor(
        source: Source,
        serializersModule: SerializersModule = EmptySerializersModule()
    ) : this(source.readFullyToAsn1Elements().first, serializersModule)

    private var elementIndex = 0
    private var descriptorIndex = 0
    private lateinit var propertyDescriptor: SerialDescriptor
    private var propertyAsn1Tag: Asn1Tag? = null
    private var propertyAsBitString: Boolean = false
    private var propertyEncodeNull: Boolean = false
    private var propertyAsChoice: Boolean = false
    private var inlineAsn1Tag: Asn1Tag? = null
    private var inlineAsBitString: Boolean = false
    private var inlineEncodeNull: Boolean = false
    private var inlineAsChoice: Boolean = false
    private var couldBeNull = false
    private var currentOwnerSerialName: String? = null
    private var currentPropertyName: String? = null
    private var currentPropertyIndex: Int? = null
    private var currentPropertyIsTrailing = true

    @OptIn(ExperimentalSerializationApi::class)
    override fun decodeInline(descriptor: SerialDescriptor): Decoder {
        inlineAsn1Tag = descriptor.annotations.asn1Tag
        inlineAsBitString = descriptor.isAsn1BitString
        inlineEncodeNull = descriptor.isAsn1EncodeNull
        inlineAsChoice = descriptor.isAsn1Choice
        return this
    }

    private fun consumeInlineHints(): InlineHints {
        val hints = InlineHints(
            tag = inlineAsn1Tag,
            asBitString = inlineAsBitString,
            encodeNull = inlineEncodeNull,
            asChoice = inlineAsChoice,
        )
        inlineAsn1Tag = null
        inlineAsBitString = false
        inlineEncodeNull = false
        inlineAsChoice = false
        return hints
    }


    override fun beginStructure(descriptor: SerialDescriptor): CompositeDecoder {

        // 1. Pick the element that belongs to *this* level
        val element = elements[elementIndex]

        // 2. hand over decoding of the children to a *new* decoder
        elementIndex++

        return when (descriptor.kind) {
            is StructureKind.CLASS,
            is StructureKind.OBJECT,
            is StructureKind.LIST,
            is StructureKind.MAP -> {
                if (element is Asn1Structure) {
                    DerDecoder(
                        element.children,
                        serializersModule = serializersModule
                    )
                } else {
                    throw SerializationException(
                        "Expected an ASN.1 structure for ${descriptor.serialName}, " +
                                "but got ${element::class.simpleName}"
                    )
                }
            }

            is PolymorphicKind -> {
                DerDecoder(
                    element.asStructure().children,
                    serializersModule = serializersModule
                )
            }

            // Primitive wrappers (CHOICE, ENUM, etc.) keep using the same instance
            else -> this

        }
    }

    override fun decodeElementIndex(descriptor: SerialDescriptor): Int {
        return when (descriptor.kind) {
            is StructureKind.CLASS, is StructureKind.OBJECT -> {
                if (descriptorIndex == 0) descriptor.ensureNoAsn1AmbiguousOptionalLayout()
                if (descriptorIndex >= descriptor.elementsCount) {
                    if (elementIndex < elements.size) {
                        throw SerializationException(
                            "Too many ASN.1 elements for ${descriptor.serialName}: " +
                                    "all ${descriptor.elementsCount} properties decoded, " +
                                    "but ${elements.size - elementIndex} element(s) remain"
                        )
                    }
                    return CompositeDecoder.DECODE_DONE
                }
                val currentDescriptorIndex = descriptorIndex++
                val asn1Tag = try {
                    descriptor.asn1Tag(currentDescriptorIndex)
                } catch (t: IndexOutOfBoundsException) {
                    throw SerializationException(t.toString())
                }

                propertyDescriptor = descriptor.getElementDescriptor(currentDescriptorIndex)
                propertyAsn1Tag = asn1Tag
                propertyAsBitString = descriptor.isAsn1BitString(currentDescriptorIndex)
                propertyEncodeNull = descriptor.isAsn1EncodeNull(currentDescriptorIndex)
                propertyAsChoice = descriptor.isAsn1Choice(currentDescriptorIndex)
                currentOwnerSerialName = descriptor.serialName
                currentPropertyName = descriptor.getElementName(currentDescriptorIndex)
                currentPropertyIndex = currentDescriptorIndex
                currentPropertyIsTrailing = currentDescriptorIndex >= descriptor.elementsCount - 1
                couldBeNull =
                    !propertyEncodeNull &&
                            !propertyDescriptor.isAsn1EncodeNull &&
                            propertyDescriptor.isNullable

                if (elementIndex >= elements.size && !couldBeNull) {
                    couldBeNull = false
                    CompositeDecoder.DECODE_DONE
                } else {
                    currentDescriptorIndex
                }
            }

            else -> {
                // list-like descriptors always have elementCount = 1 because
                // they can never know how long the list actually is
                val max = if (descriptor.elementsCount > elements.size) descriptor.elementsCount else elements.size
                if (elementIndex >= max) return CompositeDecoder.DECODE_DONE

                val asn1Tag = try {
                    descriptor.asn1Tag(elementIndex)
                } catch (t: IndexOutOfBoundsException) {
                    throw SerializationException(t.toString())
                }
                if (elementIndex >= elements.size) return CompositeDecoder.DECODE_DONE
                couldBeNull = false

                propertyDescriptor = descriptor.getElementDescriptor(elementIndex)
                propertyAsn1Tag = asn1Tag
                propertyAsBitString = descriptor.isAsn1BitString(elementIndex)
                propertyEncodeNull = descriptor.isAsn1EncodeNull(elementIndex)
                propertyAsChoice = descriptor.isAsn1Choice(elementIndex)
                currentOwnerSerialName = descriptor.serialName
                currentPropertyName = runCatching { descriptor.getElementName(elementIndex) }.getOrNull()
                currentPropertyIndex = elementIndex
                currentPropertyIsTrailing = true
                if (elementIndex < elements.size) elementIndex else CompositeDecoder.DECODE_DONE
            }
        }
    }


    override fun decodeValue(): Any {
        val inlineAnnotation = consumeInlineHints().tag

        val currentAnnotatedElement = elements[elementIndex]
        val processedElement = currentAnnotatedElement

        val effectiveDescriptor =
            if (propertyDescriptor.isInline && propertyDescriptor.elementsCount == 1) {
                propertyDescriptor.getElementDescriptor(0)
            } else {
                propertyDescriptor
            }

        val expectedTag = validateAndResolveImplicitTagOverride(
            actualTag = processedElement.tag,
            inlineAsn1Tag = inlineAnnotation,
            propertyAsn1Tag = propertyAsn1Tag,
            classAsn1Tag = effectiveDescriptor.asn1Tag,
        )

        val decoded = when (effectiveDescriptor.kind) {
            PolymorphicKind.OPEN -> TODO("Polymorphic decoding not yet implemented")
            PolymorphicKind.SEALED -> TODO("Sealed class decoding not yet implemented")
            PrimitiveKind.BOOLEAN -> processedElement.asPrimitive()
                .decodeToBoolean(expectedTag ?: Asn1Element.Tag.BOOL)

            PrimitiveKind.BYTE -> processedElement.asPrimitive().decodeToInt(expectedTag ?: Asn1Element.Tag.INT)
                .toByte()

            PrimitiveKind.CHAR -> processedElement.asPrimitive().decodeString(expectedTag)
                .also { if (it.length != 1) throw SerializationException("String is not a char") }[0]

            PrimitiveKind.DOUBLE -> processedElement.asPrimitive()
                .decodeToDouble(expectedTag ?: Asn1Element.Tag.REAL)

            PrimitiveKind.FLOAT -> processedElement.asPrimitive().decodeToFloat(expectedTag ?: Asn1Element.Tag.REAL)
            PrimitiveKind.INT -> processedElement.asPrimitive().decodeToInt(expectedTag ?: Asn1Element.Tag.INT)
            PrimitiveKind.LONG -> processedElement.asPrimitive().decodeToLong(expectedTag ?: Asn1Element.Tag.INT)
            PrimitiveKind.SHORT -> processedElement.asPrimitive().decodeToInt(expectedTag ?: Asn1Element.Tag.INT)
                .toShort()

            PrimitiveKind.STRING -> processedElement.asPrimitive().decodeString(expectedTag)
            SerialKind.ENUM -> processedElement.asPrimitive()
                .decodeToEnumOrdinal(expectedTag ?: Asn1Element.Tag.ENUM)

            else -> TODO("Unsupported kind: ${propertyDescriptor.kind}")
        } as Any
        elementIndex++
        return decoded

    }

    @OptIn(InternalSerializationApi::class)
    override fun <T : Any?> decodeSerializableValue(
        deserializer: DeserializationStrategy<T>,
        previousValue: T?
    ): T {

        val nullableCouldBeAbsent = couldBeNull
        val descriptorEncodesNull = deserializer.descriptor.isAsn1EncodeNull
        if (nullableCouldBeAbsent) {
            couldBeNull = false
            if (elementIndex == elements.size) {
                return null as T
            }

            when (val expectedLeadingTags = propertyDescriptor.possibleLeadingTagsForAsn1(
                propertyAsn1Tag = propertyAsn1Tag,
                inlineAsn1Tag = inlineAsn1Tag,
                propertyAsBitString = propertyAsBitString,
                inlineAsBitString = inlineAsBitString,
                propertyAsChoice = propertyAsChoice,
                inlineAsChoice = inlineAsChoice,
            )) {
                is Asn1LeadingTagsResolution.Exact -> {
                    val actualTag = elements[elementIndex].tag
                    if (actualTag !in expectedLeadingTags.tags) {
                        return null as T
                    }
                }

                Asn1LeadingTagsResolution.UnknownInfer -> {
                    if (!currentPropertyIsTrailing) {
                        throw SerializationException(
                            undecidableAsn1NullableDecodingMessage(
                                ownerSerialName = currentOwnerSerialName
                                    ?: deserializer.descriptor.serialName,
                                propertyName = currentPropertyName
                                    ?: propertyDescriptor.serialName,
                                propertyIndex = currentPropertyIndex ?: -1,
                                reason = expectedLeadingTags.reason(),
                            )
                        )
                    }
                }
            }
        }
        val currentAnnotatedElement = elements[elementIndex]
        if (currentAnnotatedElement.isAsn1NullElement()) {
            val propertyDescriptorEncodesNull =
                ::propertyDescriptor.isInitialized && propertyDescriptor.isAsn1EncodeNull
            if (!propertyDescriptorEncodesNull && !propertyEncodeNull && !descriptorEncodesNull) {
                throw SerializationException("Null value found, but target value should not have been present!")
            }
            elementIndex++
            return null as T
        }
        return decodeSerializableValue(deserializer)
    }

    @OptIn(InternalSerializationApi::class)
    override fun <T> decodeSerializableValue(deserializer: DeserializationStrategy<T>): T {
        if (elements.isEmpty() && deserializer.descriptor.isNullable) return null as T
        val currentAnnotatedElement = elements[elementIndex]
        val inlineHints = consumeInlineHints()
        val effectiveTagTemplate = resolveAsn1TagTemplate(
            inlineAsn1Tag = inlineHints.tag,
            propertyAsn1Tag = propertyAsn1Tag,
            classAsn1Tag = deserializer.descriptor.asn1Tag,
        )
        requireAsn1ExplicitWrapperTag(
            descriptor = deserializer.descriptor,
            tagTemplate = effectiveTagTemplate,
            ownerSerialName = currentOwnerSerialName ?: deserializer.descriptor.serialName,
            propertyName = currentPropertyName,
            propertyIndex = currentPropertyIndex,
        )
        val isBitString = inlineHints.asBitString || propertyAsBitString
        if (isBitString && !deserializer.descriptor.isAsn1BitStringCompatibleDescriptor()) {
            throw SerializationException(
                "@Asn1BitString can only be used with ByteArray-compatible serializers, but got ${deserializer.descriptor.serialName}"
            )
        }
        val descriptorAllowsNull =
            deserializer.descriptor.isNullable || (::propertyDescriptor.isInitialized && propertyDescriptor.isNullable)
        val descriptorEncodesNull = descriptorAllowsNull && deserializer.descriptor.isAsn1EncodeNull
        val propertyEncodesNull =
            if (::propertyDescriptor.isInitialized) {
                propertyDescriptor.isNullable &&
                        (propertyEncodeNull || propertyDescriptor.isAsn1EncodeNull)
            } else {
                false
            }
        val nullAnalysisDescriptor = when {
            deserializer.descriptor.isNullable -> deserializer.descriptor
            ::propertyDescriptor.isInitialized && propertyDescriptor.isNullable -> propertyDescriptor
            else -> deserializer.descriptor
        }
        val nullEncodingAnalysis = nullAnalysisDescriptor.analyzeAsn1NullableNullEncoding(
            propertyAsn1Tag = propertyAsn1Tag,
            inlineAsn1Tag = inlineHints.tag,
            propertyEncodeNull = propertyEncodeNull,
            inlineEncodeNull = inlineHints.encodeNull,
            propertyAsBitString = propertyAsBitString,
            inlineAsBitString = inlineHints.asBitString,
        )
        if (nullEncodingAnalysis.isAmbiguous) {
            throw SerializationException(
                ambiguousAsn1NullEncodingMessage(ownerSerialName = nullAnalysisDescriptor.serialName)
            )
        }

        if (shouldDecodeAsChoice(deserializer.descriptor, inlineHints.asChoice)) {
            return decodeChoiceSerializableValue(deserializer, currentAnnotatedElement, inlineHints.tag)
        }

        if (deserializer.descriptor.isInline) {
            // Let the framework do its inline-class magic
            return deserializer.deserialize(this)
        }

        val processedElement = currentAnnotatedElement
        val expectedTag = validateAndResolveImplicitTagOverride(
            actualTag = processedElement.tag,
            inlineAsn1Tag = inlineHints.tag,
            propertyAsn1Tag = propertyAsn1Tag,
            classAsn1Tag = deserializer.descriptor.asn1Tag,
        )
        val hasTagOverride = expectedTag != null

        val isEncodedNull =
            processedElement.isAsn1NullElement() ||
                    (nullEncodingAnalysis.canDecodeNullByZeroLength && processedElement.length == 0) ||
                    (nullEncodingAnalysis.canDecodeNullByConstructedBit && !processedElement.tag.isConstructed)

        if ((descriptorEncodesNull || propertyEncodesNull) && isEncodedNull) {
            elementIndex++
            return null as T
        }

        if (deserializer == Asn1ElementSerializer) {
            expectedTag?.let { ex ->
                if (processedElement.tag != ex) {
                    throw SerializationException(Asn1TagMismatchException(ex, processedElement.tag))
                }
            }
            elementIndex++
            return processedElement as T
        }

        if (deserializer is Asn1Serializer<*, T>) {
            expectedTag?.let { ex ->
                if (processedElement.tag != ex) {
                    throw SerializationException(Asn1TagMismatchException(ex, processedElement.tag))
                }
            }
            val encodable = when (processedElement) {
                is Asn1Primitive -> (deserializer as Asn1Decodable<Asn1Primitive, T>).decodeFromTlv(processedElement)
                is Asn1Structure -> (deserializer as Asn1Decodable<Asn1Structure, T>).decodeFromTlv(processedElement)
            }
            elementIndex++
            return encodable
        }

        // Tag-check for explicitly / implicitly tagged primitives
        val tagToValidate = expectedTag ?: run {
            // If no explicit tag is specified, we should still validate against the default tag
            // for the type being deserialized (when no annotations are present)
            if (!hasTagOverride) {
                if (isBitString) Asn1Element.Tag.BIT_STRING
                else getDefaultTagForDescriptor(deserializer.descriptor)
            } else {
                null
            }
        }

        tagToValidate?.let { expected ->
            if (processedElement.tag != expected) {
                throw SerializationException(Asn1TagMismatchException(expected, processedElement.tag))
            }
        }
        // (2) Fast paths for primitive *unsigned* surrogates & helpers
        when (deserializer) {
            UByte.serializer() -> return processedElement.asPrimitive()
                .decodeToUInt(expectedTag ?: Asn1Element.Tag.INT)
                .toUByte()
                .also { elementIndex++ } as T

            UShort.serializer() -> return processedElement.asPrimitive()
                .decodeToUInt(expectedTag ?: Asn1Element.Tag.INT)
                .toUShort()
                .also { elementIndex++ } as T

            UInt.serializer() -> return processedElement.asPrimitive()
                .decodeToUInt(expectedTag ?: Asn1Element.Tag.INT)
                .also { elementIndex++ } as T

            ULong.serializer() -> return processedElement.asPrimitive()
                .decodeToULong(expectedTag ?: Asn1Element.Tag.INT)
                .also { elementIndex++ } as T

            ByteArraySerializer() -> {
                // Decode BitSet from ASN.1 BitString and convert to ByteArray
                return if (isBitString) {
                    processedElement.asPrimitive()
                        .asAsn1BitString(tagToValidate ?: Asn1Element.Tag.BIT_STRING).rawBytes.also { elementIndex++ } as T
                } else {
                    // Regular ByteArray decoding (OCTET STRING)
                    processedElement.asPrimitive().content.also { elementIndex++ } as T
                }
            }
        }

        if (deserializer.descriptor.kind == SerialKind.ENUM) {
            val ordinal = processedElement.asPrimitive()
                .decodeToEnumOrdinal(expectedTag ?: Asn1Element.Tag.ENUM)
                .toInt()
            val enumDecoder = object : AbstractDecoder() {
                override val serializersModule: SerializersModule = this@DerDecoder.serializersModule
                override fun decodeEnum(enumDescriptor: SerialDescriptor): Int = ordinal
                override fun decodeElementIndex(descriptor: SerialDescriptor): Int = CompositeDecoder.DECODE_DONE
            }
            elementIndex++
            return deserializer.deserialize(enumDecoder)
        }

        // (3) Primitive kinds → defer to decodeValue()
        if (deserializer.descriptor.kind is PrimitiveKind) {
            if (!::propertyDescriptor.isInitialized) {
                propertyDescriptor = deserializer.descriptor
                propertyAsBitString = deserializer.descriptor.isAsn1BitString
                propertyEncodeNull = deserializer.descriptor.isAsn1EncodeNull
                propertyAsChoice = deserializer.descriptor.isAsn1Choice
            }
            if (propertyAsn1Tag == null) {
                propertyAsn1Tag = deserializer.descriptor.annotations.asn1Tag
            }
            return decodeValue() as T
        }


        val childDecoder = DerDecoder(
            elements = mutableListOf(processedElement),
            serializersModule = serializersModule,
        )
        val value = deserializer.deserialize(childDecoder)
        elementIndex++
        return value
    }

    private fun shouldDecodeAsChoice(
        descriptor: SerialDescriptor,
        inlineAsChoice: Boolean,
    ): Boolean {
        return inlineAsChoice || propertyAsChoice || descriptor.isAsn1Choice
    }

    @OptIn(InternalSerializationApi::class)
    @Suppress("UNCHECKED_CAST")
    private fun <T> decodeChoiceSerializableValue(
        deserializer: DeserializationStrategy<T>,
        currentAnnotatedElement: Asn1Element,
        inlineAnnotation: Asn1Tag?,
    ): T {
        if (deserializer.descriptor.kind !is PolymorphicKind.SEALED) {
            throw SerializationException(
                "@Asn1Choice requires a sealed polymorphic descriptor, but got ${deserializer.descriptor.kind}"
            )
        }

        val sealedSerializer = deserializer as? SealedClassSerializer<T>
            ?: throw SerializationException(
                "@Asn1Choice only supports kotlinx SealedClassSerializer"
            )

        validateAndResolveImplicitTagOverride(
            actualTag = currentAnnotatedElement.tag,
            inlineAsn1Tag = inlineAnnotation,
            propertyAsn1Tag = propertyAsn1Tag,
            classAsn1Tag = deserializer.descriptor.asn1Tag,
        )
        val processedElement = currentAnnotatedElement
        val subtypeDescriptor = deserializer.descriptor.findLikelySealedAlternativesDescriptor()
            ?: throw SerializationException(
                "Could not inspect sealed CHOICE alternatives for ${deserializer.descriptor.serialName}"
            )
        val matches = mutableListOf<Pair<String, T>>()
        for (i in 0 until subtypeDescriptor.elementsCount) {
            val serialName = subtypeDescriptor.getElementName(i)
            val subtypeDeserializer = sealedSerializer.findPolymorphicSerializerOrNull(this, serialName) ?: continue
            val candidate = catchingUnwrapped {
                DerDecoder(
                    elements = listOf(processedElement),
                    serializersModule = serializersModule
                ).decodeSerializableValue(subtypeDeserializer)
            }.getOrNull() ?: continue

            matches += serialName to candidate
        }

        when (matches.size) {
            0 -> throw Asn1ChoiceNoMatchingAlternativeException(
                "No CHOICE alternative of ${deserializer.descriptor.serialName} matches tag ${processedElement.tag}"
            )

            1 -> {
                elementIndex++
                return matches.single().second
            }

            else -> throw SerializationException(
                "Ambiguous CHOICE decode for ${deserializer.descriptor.serialName} and tag ${processedElement.tag}: ${matches.joinToString { it.first }}"
            )
        }
    }

}

private class Asn1ChoiceNoMatchingAlternativeException(message: String) : SerializationException(message)

private fun validateAndResolveImplicitTagOverride(
    actualTag: Asn1Element.Tag,
    inlineAsn1Tag: Asn1Tag? = null,
    propertyAsn1Tag: Asn1Tag? = null,
    classAsn1Tag: Asn1Tag? = null,
): Asn1Element.Tag? {
    val tagTemplate = resolveAsn1TagTemplate(
        inlineAsn1Tag = inlineAsn1Tag,
        propertyAsn1Tag = propertyAsn1Tag,
        classAsn1Tag = classAsn1Tag,
    ) ?: return null

    val expectedTag = Asn1Element.Tag(
        tagValue = tagTemplate.tagValue,
        tagClass = tagTemplate.tagClass ?: actualTag.tagClass,
        constructed = tagTemplate.constructed ?: actualTag.isConstructed,
    )
    if (actualTag != expectedTag) {
        throw SerializationException(Asn1TagMismatchException(expectedTag, actualTag))
    }
    return expectedTag
}

private fun requireAsn1ExplicitWrapperTag(
    descriptor: SerialDescriptor,
    tagTemplate: Asn1Element.Tag.Template?,
    ownerSerialName: String,
    propertyName: String?,
    propertyIndex: Int?,
) {
    if (!descriptor.isAsn1ExplicitWrapperDescriptor()) return
    val location = if (propertyName != null && propertyIndex != null) {
        "property '$propertyName' (index $propertyIndex) in $ownerSerialName"
    } else {
        ownerSerialName
    }
    if (tagTemplate == null) {
        throw SerializationException(
            "Asn1Explicit requires an implicit tag override at $location. " +
                    "Provide @Asn1Tag(tagNumber=..., tagClass=CONTEXT_SPECIFIC, constructed=CONSTRUCTED)."
        )
    }
    val effectiveClass = tagTemplate.tagClass ?: TagClass.UNIVERSAL
    val effectiveConstructed = tagTemplate.constructed ?: true
    if (effectiveClass != TagClass.CONTEXT_SPECIFIC || !effectiveConstructed) {
        throw SerializationException(
            "Asn1Explicit requires CONTEXT_SPECIFIC + CONSTRUCTED tag at $location, " +
                    "but effective override is class=$effectiveClass, constructed=$effectiveConstructed."
        )
    }
}

private fun Asn1Element.isAsn1NullElement(): Boolean =
    this is Asn1Primitive && tag == Asn1Element.Tag.NULL && length == 0

private fun getDefaultTagForDescriptor(descriptor: SerialDescriptor): Asn1Element.Tag? {

    return if (descriptor.isSetDescriptor) Asn1Element.Tag.SET
    else if (descriptor == ByteArraySerializer().descriptor) if (descriptor.isAsn1BitString) Asn1Element.Tag.BIT_STRING else Asn1Element.Tag.OCTET_STRING
    else when (descriptor.kind) {
        is StructureKind.CLASS, is StructureKind.OBJECT -> Asn1Element.Tag.SEQUENCE
        is StructureKind.LIST -> Asn1Element.Tag.SEQUENCE
        is StructureKind.MAP -> Asn1Element.Tag.SEQUENCE
        else -> null // For primitive types, tag validation happens in decodeValue()
    }
}


private fun Asn1Primitive.decodeString(implicitTagOverride: Asn1Element.Tag?): String =
    if (implicitTagOverride == null) {
        when (tag) {
            Asn1Element.Tag.STRING_UTF8,
            Asn1Element.Tag.STRING_BMP,
            Asn1Element.Tag.STRING_NUMERIC,
            Asn1Element.Tag.STRING_T61,
            Asn1Element.Tag.STRING_VISIBLE,
            Asn1Element.Tag.STRING_UNIVERSAL,
            Asn1Element.Tag.STRING_PRINTABLE,
            Asn1Element.Tag.STRING_IA5,
                -> decodeToString()

            else -> throw SerializationException(Asn1TagMismatchException(Asn1Element.Tag.STRING_UTF8, tag))
        }
    } else {
        if (tag != implicitTagOverride) throw SerializationException(Asn1TagMismatchException(implicitTagOverride, tag))
        String.decodeFromAsn1ContentBytes(content)
    }
