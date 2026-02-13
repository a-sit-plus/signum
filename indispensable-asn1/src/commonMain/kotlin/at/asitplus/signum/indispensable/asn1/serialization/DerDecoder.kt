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
 * - annotation-driven tag/layer processing via [Asn1nnotation]
 * - sealed CHOICE decoding (`asChoice = true`)
 * - runtime ambiguity checks for nullable/optional class layouts
 */
class DerDecoder internal constructor(
    private val elements: List<Asn1Element>,
    override val serializersModule: SerializersModule = EmptySerializersModule()
) : AbstractDecoder() {


    internal constructor(
        source: Source,
        serializersModule: SerializersModule = EmptySerializersModule()
    ) : this(source.readFullyToAsn1Elements().first, serializersModule)

    private var elementIndex = 0
    private var descriptorIndex = 0
    private lateinit var propertyDescriptor: SerialDescriptor
    private var propertyAsn1nnotation: Asn1nnotation? = null
    private var inlineAsn1nnotation: Asn1nnotation? = null
    private var couldBeNull = false
    private var currentOwnerSerialName: String? = null
    private var currentPropertyName: String? = null
    private var currentPropertyIndex: Int? = null
    private var currentPropertyIsTrailing = true

    @OptIn(ExperimentalSerializationApi::class)
    override fun decodeInline(descriptor: SerialDescriptor): Decoder {
        val annotation = descriptor.annotations.find { it is Asn1nnotation } as? Asn1nnotation
        inlineAsn1nnotation = annotation
        return this
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
                val asn1nnotation = try {
                    descriptor.asn1nnotation(currentDescriptorIndex)
                } catch (t: IndexOutOfBoundsException) {
                    throw SerializationException(t.toString())
                }

                propertyDescriptor = descriptor.getElementDescriptor(currentDescriptorIndex)
                propertyAsn1nnotation = asn1nnotation
                currentOwnerSerialName = descriptor.serialName
                currentPropertyName = descriptor.getElementName(currentDescriptorIndex)
                currentPropertyIndex = currentDescriptorIndex
                currentPropertyIsTrailing = currentDescriptorIndex >= descriptor.elementsCount - 1
                couldBeNull =
                    asn1nnotation?.encodeNull != true &&
                            propertyDescriptor.asn1nnotation?.encodeNull != true &&
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

                val asn1nnotation = try {
                    descriptor.asn1nnotation(elementIndex)
                } catch (t: IndexOutOfBoundsException) {
                    throw SerializationException(t.toString())
                }
                if (elementIndex >= elements.size) return CompositeDecoder.DECODE_DONE
                couldBeNull = false

                propertyDescriptor = descriptor.getElementDescriptor(elementIndex)
                propertyAsn1nnotation = asn1nnotation
                currentOwnerSerialName = descriptor.serialName
                currentPropertyName = runCatching { descriptor.getElementName(elementIndex) }.getOrNull()
                currentPropertyIndex = elementIndex
                currentPropertyIsTrailing = true
                if (elementIndex < elements.size) elementIndex else CompositeDecoder.DECODE_DONE
            }
        }
    }


    override fun decodeValue(): Any {
        val inlineAnnotation = inlineAsn1nnotation
        inlineAsn1nnotation = null

        val currentAnnotatedElement = elements[elementIndex]


        // Process annotations to get the actual element and expected tag
        val annotations =
            (propertyAsn1nnotation?.layers?.toList() ?: emptyList<Layer>()) + (inlineAnnotation?.layers?.toList()
                ?: emptyList())
        val (processedElement, expectedTag) = processAnnotationsForDecoding(
            currentAnnotatedElement,
            annotations
        )

        val effectiveDescriptor =
            if (propertyDescriptor.isInline && propertyDescriptor.elementsCount == 1) {
                propertyDescriptor.getElementDescriptor(0)
            } else {
                propertyDescriptor
            }

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
        val descriptorEncodesNull = deserializer.descriptor.asn1nnotation?.encodeNull == true
        if (nullableCouldBeAbsent) {
            couldBeNull = false
            if (elementIndex == elements.size) {
                return null as T
            }

            when (val expectedLeadingTags = propertyDescriptor.possibleLeadingTagsForAsn1(propertyAsn1nnotation)) {
                is Asn1LeadingTagsResolution.Exact -> {
                    val actualTag = elements[elementIndex].tag
                    if (actualTag !in expectedLeadingTags.tags) {
                        return null as T
                    }
                }

                Asn1LeadingTagsResolution.ValueDependent,
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
                ::propertyDescriptor.isInitialized && propertyDescriptor.asn1nnotation?.encodeNull == true
            if (!propertyDescriptorEncodesNull && !(propertyAsn1nnotation?.encodeNull ?: false) && !descriptorEncodesNull) {
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
        val inlineAnnotation = inlineAsn1nnotation.also { inlineAsn1nnotation = null }
        val isBitString = (inlineAnnotation?.asBitString ?: false) || (propertyAsn1nnotation?.asBitString ?: false)
        val propertyAnnotations = propertyAsn1nnotation?.layers?.toList() ?: emptyList()
        val classLevelAnnotations = deserializer.descriptor.annotations.asn1Layers
        val descriptorAllowsNull =
            deserializer.descriptor.isNullable || (::propertyDescriptor.isInitialized && propertyDescriptor.isNullable)
        val descriptorEncodesNull = descriptorAllowsNull && deserializer.descriptor.asn1nnotation?.encodeNull == true
        val propertyEncodesNull =
            if (::propertyDescriptor.isInitialized) {
                propertyDescriptor.isNullable &&
                        (propertyAsn1nnotation?.encodeNull == true || propertyDescriptor.asn1nnotation?.encodeNull == true)
            } else {
                false
            }
        val nullAnalysisDescriptor = when {
            deserializer.descriptor.isNullable -> deserializer.descriptor
            ::propertyDescriptor.isInitialized && propertyDescriptor.isNullable -> propertyDescriptor
            else -> deserializer.descriptor
        }
        val nullEncodingAnalysis = nullAnalysisDescriptor.analyzeAsn1NullableNullEncoding(
            propertyAsn1nnotation = propertyAsn1nnotation,
            inlineAsn1nnotation = inlineAnnotation,
        )
        if (nullEncodingAnalysis.isAmbiguous) {
            throw SerializationException(
                ambiguousAsn1NullEncodingMessage(ownerSerialName = nullAnalysisDescriptor.serialName)
            )
        }

        // Combine property and class-level annotations for processing
        val allAnnotations =
            (inlineAnnotation?.layers?.toList() ?: emptyList()) + propertyAnnotations + classLevelAnnotations

        if (shouldDecodeAsChoice(deserializer.descriptor, inlineAnnotation)) {
            return decodeChoiceSerializableValue(deserializer, currentAnnotatedElement, allAnnotations)
        }

        if (deserializer.descriptor.isInline) {
            // Let the framework do its inline-class magic
            return deserializer.deserialize(this)
        }

        /* your old custom handling for non-inline cases */
        val (processedElement, expectedTag) = processAnnotationsForDecoding(
            currentAnnotatedElement,
            allAnnotations
        )

        val isEncodedNull =
            processedElement.isAsn1NullElement() ||
                    (nullEncodingAnalysis.canDecodeNullByZeroLength && processedElement.length == 0) ||
                    (nullEncodingAnalysis.canDecodeNullByConstructedBit && !processedElement.tag.isConstructed)

        if ((descriptorEncodesNull || propertyEncodesNull) && isEncodedNull) {
            elementIndex++
            return null as T
        }

        // Tag-check for explicitly / implicitly tagged primitives
        val tagToValidate = expectedTag ?: run {

            if (deserializer is Asn1Serializer<*, T>) {
                val encodable = when (processedElement) {
                    is Asn1Primitive -> (deserializer as Asn1Decodable<Asn1Primitive, T>).decodeFromTlv(processedElement)
                    is Asn1Structure -> (deserializer as Asn1Decodable<Asn1Structure, T>).decodeFromTlv(processedElement)
                }
                elementIndex++
                return encodable
            }

            // If no explicit tag is specified, we should still validate against the default tag
            // for the type being deserialized (when no annotations are present)
            if (allAnnotations.isEmpty()) {
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

            Asn1ElementSerializer -> return processedElement
                .also {
                    expectedTag?.let { ex ->
                        if (it.tag != ex) throw SerializationException(Asn1TagMismatchException(ex, it.tag))
                    }
                }
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
            }
            if (propertyAsn1nnotation == null) {
                propertyAsn1nnotation =
                    deserializer.descriptor.annotations.find { it is Asn1nnotation } as? Asn1nnotation
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
        inlineAnnotation: Asn1nnotation?
    ): Boolean {
        return inlineAnnotation?.asChoice == true ||
                propertyAsn1nnotation?.asChoice == true ||
                descriptor.asn1nnotation?.asChoice == true
    }

    @OptIn(InternalSerializationApi::class)
    @Suppress("UNCHECKED_CAST")
    private fun <T> decodeChoiceSerializableValue(
        deserializer: DeserializationStrategy<T>,
        currentAnnotatedElement: Asn1Element,
        allAnnotations: List<Layer>,
    ): T {
        if (deserializer.descriptor.kind !is PolymorphicKind.SEALED) {
            throw SerializationException(
                "@Asn1nnotation(asChoice=true) requires a sealed polymorphic descriptor, but got ${deserializer.descriptor.kind}"
            )
        }

        val sealedSerializer = deserializer as? SealedClassSerializer<T>
            ?: throw SerializationException(
                "@Asn1nnotation(asChoice=true) only supports kotlinx SealedClassSerializer"
            )

        val (processedElement, _) = processAnnotationsForDecoding(currentAnnotatedElement, allAnnotations)
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

    /**
     * Process annotations to determine expected tag for primitives
     * Returns the processed element and the expected tag (if any)
     */
    private fun processAnnotationsForDecoding(
        element: Asn1Element,
        annotations: List<Layer>
    ): Pair<Asn1Element, Asn1Element.Tag?> {
        if (annotations.isEmpty()) {
            return element to null
        }

        var currentElement = element
        var currentTag = currentElement.tag
        annotations.forEachIndexed { i, annotation ->

            when (annotation.type) {
                Type.OCTET_STRING -> {
                    if (currentTag != Asn1Element.Tag.OCTET_STRING) {
                        throw SerializationException(
                            Asn1TagMismatchException(
                                Asn1Element.Tag.OCTET_STRING,
                                currentElement.tag
                            )
                        )
                    }
                    val octetString = currentElement.asEncapsulatingOctetString().iterator()
                    currentElement = octetString.next()
                    if (octetString.hasNext()) throw SerializationException(Asn1StructuralException("Octet string should only contain one child"))
                    currentTag = currentElement.tag

                }

                Type.EXPLICIT_TAG -> {
                    val expectedTag =
                        Asn1Element.Tag(annotation.tag, currentTag.isConstructed, currentTag.tagClass)
                    if (currentTag != expectedTag) {
                        throw Asn1TagMismatchException(expectedTag, currentElement.tag)
                    }
                    val octetString = currentElement.asStructure().iterator()
                    currentElement = octetString.next()
                    if (octetString.hasNext()) throw SerializationException(Asn1StructuralException("Explicit tag should only contain one child"))
                    currentTag = currentElement.tag

                }

                Type.IMPLICIT_TAG -> {

                    val expectedTag = Asn1Element.Tag(annotation.tag, currentTag.isConstructed, currentTag.tagClass)
                    if (currentTag != expectedTag) {
                        throw SerializationException(Asn1TagMismatchException(expectedTag, currentElement.tag))
                    }
                    if (annotations.size > i + 1) {
                        val nextTag = annotations[i + 1]
                        when (nextTag.type) {
                            Type.OCTET_STRING -> currentTag = Asn1Element.Tag(nextTag.tag, false)
                            Type.EXPLICIT_TAG -> currentTag =
                                Asn1Element.Tag(nextTag.tag, true, tagClass = TagClass.CONTEXT_SPECIFIC)

                            Type.IMPLICIT_TAG -> currentTag =
                                Asn1Element.Tag(nextTag.tag, currentTag.isConstructed, tagClass = currentTag.tagClass)

                        }
                    } else {
                        currentElement = currentElement.withImplicitTag(currentTag)
                    }
                }
            }
        }

        return currentElement to currentTag
    }
}

private class Asn1ChoiceNoMatchingAlternativeException(message: String) : SerializationException(message)

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
