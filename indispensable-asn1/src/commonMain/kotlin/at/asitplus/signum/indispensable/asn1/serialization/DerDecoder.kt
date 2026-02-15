package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.encoding.*
import kotlinx.io.Source
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.InternalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SealedClassSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.descriptors.*
import kotlinx.serialization.encoding.AbstractDecoder
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.internal.AbstractPolymorphicSerializer
import kotlinx.serialization.modules.EmptySerializersModule
import kotlinx.serialization.modules.SerializersModule
import kotlin.time.Instant


@ExperimentalSerializationApi
/**
 * ASN.1 DER decoder used by [Der] format operations.
 *
 * This decoder supports:
 * - annotation-driven implicit tag override processing via [Asn1Tag]
 * - sealed CHOICE decoding via sealed polymorphism
 * - runtime ambiguity checks for nullable/optional class layouts
 */
class DerDecoder internal constructor(
    private val elements: List<Asn1Element>,
    override val serializersModule: SerializersModule = EmptySerializersModule(),
    private val formatConfiguration: DerConfiguration = DerConfiguration(),
) : AbstractDecoder() {

    internal constructor(
        source: Source,
        serializersModule: SerializersModule = EmptySerializersModule(),
        formatConfiguration: DerConfiguration = DerConfiguration(),
    ) : this(source.readFullyToAsn1Elements().first, serializersModule, formatConfiguration)

    private var elementIndex = 0
    private var descriptorIndex = 0
    private lateinit var propertyDescriptor: SerialDescriptor
    private var propertyAsn1Tag: Asn1Tag? = null
    private var propertyAsBitString: Boolean = false
    private var propertyAsChoice: Boolean = false
    private val inlineHintState = DerInlineHintState()
    private var couldBeNull = false
    private var currentOwnerSerialName: String? = null
    private var currentPropertyName: String? = null
    private var currentPropertyIndex: Int? = null
    private var currentPropertyIsTrailing = true
    private var dropFirstChildInNextStructure: Boolean = false
    internal fun dropOidFromNextStructure() {
        dropFirstChildInNextStructure = true
    }



    internal fun peekCurrentElementTagOrNull(): Asn1Element.Tag? = elements.getOrNull(elementIndex)?.tag
    internal fun peekCurrentElementOrNull(): Asn1Element? = elements.getOrNull(elementIndex)

    internal fun <T> decodeCurrentElementWith(deserializer: DeserializationStrategy<T>): T {
        val current = elements.getOrNull(elementIndex)
            ?: throw SerializationException("No ASN.1 element left while decoding ${deserializer.descriptor.serialName}")
        val isolated = DerDecoder(
            elements = listOf(current),
            serializersModule = serializersModule,
            formatConfiguration = formatConfiguration,
        )
        isolated.initializeStandalonePropertyState(deserializer.descriptor)
        isolated.currentOwnerSerialName = deserializer.descriptor.serialName
        isolated.currentPropertyName = deserializer.descriptor.serialName
        isolated.currentPropertyIndex = 0
        isolated.dropFirstChildInNextStructure = this.dropFirstChildInNextStructure
        this.dropFirstChildInNextStructure = false
        val decoded = isolated.decodeSerializableValue(deserializer)
        elementIndex++
        return decoded
    }

    @OptIn(ExperimentalSerializationApi::class)
    override fun decodeInline(descriptor: SerialDescriptor): Decoder {
        inlineHintState.recordFrom(descriptor)
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
                    val children = element.children

                    val effectiveChildren =
                        if (dropFirstChildInNextStructure) {
                            dropFirstChildInNextStructure = false
                            if (children.isEmpty()) children else children.drop(1)
                        } else children

                    DerDecoder(
                        effectiveChildren,
                        serializersModule = serializersModule,
                        formatConfiguration = formatConfiguration,
                    )
                } else {
                    throw SerializationException(
                        "Expected an ASN.1 structure for ${descriptor.serialName}, " +
                                "but got ${element::class.simpleName}"
                    )
                }
            }

            is PolymorphicKind -> {
                val children = element.asStructure().children
                val effectiveChildren =
                    if (dropFirstChildInNextStructure) {
                        dropFirstChildInNextStructure = false
                        if (children.isEmpty()) children else children.drop(1)
                    } else children

                DerDecoder(
                    effectiveChildren,
                    serializersModule = serializersModule,
                    formatConfiguration = formatConfiguration,
                )
            }

            // Primitive wrappers (CHOICE, ENUM, etc.) keep using the same instance
            else -> this

        }
    }

    override fun decodeElementIndex(descriptor: SerialDescriptor): Int {
        return when (descriptor.kind) {
            is StructureKind.CLASS, is StructureKind.OBJECT -> {
                if (descriptorIndex == 0) {
                    descriptor.ensureNoAsn1AmbiguousOptionalLayout(
                        formatExplicitNulls = formatConfiguration.explicitNulls,
                    )
                }
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
                val propertyContext = applyCurrentPropertyContext(
                    ownerDescriptor = descriptor,
                    propertyIndex = currentDescriptorIndex,
                    isTrailing = currentDescriptorIndex >= descriptor.elementsCount - 1,
                )
                val nullEncodingAnalysis = propertyContext.propertyDescriptor.analyzeAsn1NullableNullEncoding(
                    propertyAsn1Tag = propertyContext.propertyAsn1Tag,
                    propertyAsBitString = propertyContext.propertyAsBitString,
                    formatExplicitNulls = formatConfiguration.explicitNulls,
                )
                couldBeNull = propertyContext.propertyDescriptor.isNullable && !nullEncodingAnalysis.encodeNullEnabled

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

                if (elementIndex >= elements.size) return CompositeDecoder.DECODE_DONE
                couldBeNull = false

                applyCurrentPropertyContext(
                    ownerDescriptor = descriptor,
                    propertyIndex = elementIndex,
                    isTrailing = true,
                    safePropertyNameLookup = true,
                )
                if (elementIndex < elements.size) elementIndex else CompositeDecoder.DECODE_DONE
            }
        }
    }


    override fun decodeValue(): Any {
        val inlineAnnotation = inlineHintState.consume().tag

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
            PolymorphicKind.OPEN -> throw SerializationException(
                "Open polymorphic decoding is not supported via primitive decode path for ${effectiveDescriptor.serialName}. " +
                        "Register an ASN.1 open-polymorphic serializer in DER { serializersModule = ... } " +
                        "via olymorphicByTag(...) or lymorphicByOid(...)."
            )

            PolymorphicKind.SEALED -> throw SerializationException(
                "Sealed polymorphic decoding is not supported via primitive decode path for ${effectiveDescriptor.serialName}. " +
                        "ASN.1 CHOICE is supported for sealed types in composite decoding paths."
            )
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

            else -> throw SerializationException(
                "Unsupported descriptor kind ${propertyDescriptor.kind} for ${effectiveDescriptor.serialName} in decodeValue(). " +
                        "Provide a custom serializer or use a supported ASN.1 mapping shape."
            )
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
        val descriptorNullEncodingAnalysis = deserializer.descriptor.analyzeAsn1NullableNullEncoding(
            formatExplicitNulls = formatConfiguration.explicitNulls,
        )
        if (nullableCouldBeAbsent) {
            val pendingInlineHints = inlineHintState.peek()
            couldBeNull = false
            if (elementIndex == elements.size) {
                return null as T
            }

            when (val expectedLeadingTags = propertyDescriptor.possibleLeadingTagsForAsn1(
                propertyAsn1Tag = propertyAsn1Tag,
                inlineAsn1Tag = pendingInlineHints.tag,
                propertyAsBitString = propertyAsBitString,
                inlineAsBitString = pendingInlineHints.asBitString,
                propertyAsChoice = propertyAsChoice,
                inlineAsChoice = pendingInlineHints.asChoice,
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
            val propertyDescriptorEncodesNull = ::propertyDescriptor.isInitialized &&
                    propertyDescriptor.analyzeAsn1NullableNullEncoding(
                        propertyAsn1Tag = propertyAsn1Tag,
                        propertyAsBitString = propertyAsBitString,
                        formatExplicitNulls = formatConfiguration.explicitNulls,
                    ).encodeNullEnabled
            if (!propertyDescriptorEncodesNull && !descriptorNullEncodingAnalysis.encodeNullEnabled) {
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
        val inlineHints = inlineHintState.consume()
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
        val descriptorNullEncodingAnalysis = deserializer.descriptor.analyzeAsn1NullableNullEncoding(
            inlineAsn1Tag = inlineHints.tag,
            inlineAsBitString = inlineHints.asBitString,
            formatExplicitNulls = formatConfiguration.explicitNulls,
        )
        val propertyNullEncodingAnalysis = if (::propertyDescriptor.isInitialized) {
            propertyDescriptor.analyzeAsn1NullableNullEncoding(
                propertyAsn1Tag = propertyAsn1Tag,
                inlineAsn1Tag = inlineHints.tag,
                propertyAsBitString = propertyAsBitString,
                inlineAsBitString = inlineHints.asBitString,
                formatExplicitNulls = formatConfiguration.explicitNulls,
            )
        } else {
            null
        }
        val nullEncodingAnalysis = propertyNullEncodingAnalysis ?: descriptorNullEncodingAnalysis
        val nullAnalysisOwnerSerialName = if (::propertyDescriptor.isInitialized) {
            propertyDescriptor.serialName
        } else {
            deserializer.descriptor.serialName
        }
        if (nullEncodingAnalysis.isAmbiguous) {
            throw SerializationException(
                ambiguousAsn1NullEncodingMessage(ownerSerialName = nullAnalysisOwnerSerialName)
            )
        }

        resolveOpenPolymorphicAsn1SerializerOrNull(deserializer)?.let { openSerializer ->
            if (openSerializer.descriptor == deserializer.descriptor) {
                throw SerializationException(
                    "Open polymorphism for ${deserializer.descriptor.serialName} resolved to itself. " +
                            "Register a concrete ASN.1 open-polymorphic serializer in DER { serializersModule = ... }."
                )
            }
            @Suppress("UNCHECKED_CAST")
            return decodeCurrentElementWith(openSerializer as DeserializationStrategy<T>)
        }

        if (deserializer.descriptor.kind is PolymorphicKind.OPEN) {
            throw SerializationException(
                "Open polymorphism for ${deserializer.descriptor.serialName} requires an ASN.1 serializer " +
                        "registered in DER { serializersModule = ... } via polymorphicByTag(...) " +
                        "or polymorphicByOid(...)."
            )
        }

        if (isAsn1ChoiceRequested(deserializer.descriptor, inlineHints.asChoice, propertyAsChoice)) {
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

        if (nullEncodingAnalysis.encodeNullEnabled && isEncodedNull) {
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

        if (deserializer.descriptor.isKotlinTimeInstantDescriptor()) {
            val primitive = processedElement as? Asn1Primitive
                ?: throw SerializationException(
                    "Expected ASN.1 primitive for kotlin.time.Instant, but got ${processedElement::class.simpleName}"
                )
            val decodedInstant = primitive.decodeInstantWithOptionalImplicitTag(expectedTag)
            elementIndex++
            return decodedInstant as T
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

        // (3) Primitive kinds → let deserializer consume primitive decoder APIs.
        // This preserves custom primitive-wrapper serializers (e.g. value classes / wrappers
        // with PrimitiveSerialDescriptor) instead of short-circuiting to raw primitive values.
        if (deserializer.descriptor.kind is PrimitiveKind) {
            if (!::propertyDescriptor.isInitialized) {
                initializeStandalonePropertyState(deserializer.descriptor)
            }
            if (propertyAsn1Tag == null) {
                propertyAsn1Tag = deserializer.descriptor.annotations.asn1Tag
            }
            return deserializer.deserialize(this)
        }


        val childDecoder = DerDecoder(
            elements = mutableListOf(processedElement),
            serializersModule = serializersModule,
            formatConfiguration = formatConfiguration,
        )
        if(dropFirstChildInNextStructure){
            childDecoder.dropFirstChildInNextStructure = dropFirstChildInNextStructure
            dropFirstChildInNextStructure = false
        }
        val value = deserializer.deserialize(childDecoder)
        elementIndex++
        return value
    }

    private fun initializeStandalonePropertyState(descriptor: SerialDescriptor) {
        propertyDescriptor = descriptor
        propertyAsn1Tag = descriptor.annotations.asn1Tag
        propertyAsBitString = descriptor.isAsn1BitString
        propertyAsChoice = descriptor.isSealed
    }

    private fun applyCurrentPropertyContext(
        ownerDescriptor: SerialDescriptor,
        propertyIndex: Int,
        isTrailing: Boolean,
        safePropertyNameLookup: Boolean = false,
    ): DerPropertyContext {
        val context = try {
            (ownerDescriptor to propertyIndex).toDerPropertyContext(
                safePropertyNameLookup = safePropertyNameLookup
            )
        } catch (t: IndexOutOfBoundsException) {
            throw SerializationException(t.toString())
        }
        propertyDescriptor = context.propertyDescriptor
        propertyAsn1Tag = context.propertyAsn1Tag
        propertyAsBitString = context.propertyAsBitString
        propertyAsChoice = context.propertyAsChoice
        currentOwnerSerialName = context.ownerSerialName
        currentPropertyName = context.propertyName
        currentPropertyIndex = context.index
        currentPropertyIsTrailing = isTrailing
        return context
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
                "ASN.1 CHOICE requires a sealed polymorphic descriptor, but got ${deserializer.descriptor.kind}"
            )
        }

        val sealedSerializer = deserializer as? SealedClassSerializer<Any>
            ?: throw SerializationException(
                "ASN.1 CHOICE only supports kotlinx SealedClassSerializer"
            )

        validateAndResolveImplicitTagOverride(
            actualTag = currentAnnotatedElement.tag,
            inlineAsn1Tag = inlineAnnotation,
            propertyAsn1Tag = propertyAsn1Tag,
            classAsn1Tag = deserializer.descriptor.asn1Tag,
        )
        val alternativesDescriptor = deserializer.descriptor.findLikelySealedAlternativesDescriptor()
            ?: throw SerializationException(
                "Could not inspect sealed CHOICE alternatives for ${deserializer.descriptor.serialName}"
            )
        val dispatch = buildSealedChoiceDispatch<Any>(
            ownerSerialName = deserializer.descriptor.serialName,
            alternativesDescriptor = alternativesDescriptor,
            resolveSerializerByName = { serialName ->
                sealedSerializer.findPolymorphicSerializerOrNull(this, serialName) as? KSerializer<out Any>
            },
        )
        val selected = dispatch.serializerForDecodeOrNull(currentAnnotatedElement.tag)
            ?: throw Asn1ChoiceNoMatchingAlternativeException(
                "No CHOICE alternative of ${deserializer.descriptor.serialName} matches tag ${currentAnnotatedElement.tag}"
            )

        return decodeCurrentElementWith(selected as DeserializationStrategy<T>)
    }

    @OptIn(InternalSerializationApi::class)
    private fun <T> resolveOpenPolymorphicAsn1SerializerOrNull(
        deserializer: DeserializationStrategy<T>,
    ): DeserializationStrategy<*>? {
        if (deserializer.descriptor.kind !is PolymorphicKind.OPEN) return null
        val polymorphicSerializer = deserializer as? AbstractPolymorphicSerializer<*> ?: return null
        return serializersModule.getContextual(polymorphicSerializer.baseClass, emptyList())
    }

}

private class Asn1ChoiceNoMatchingAlternativeException(message: String) : SerializationException(message)

private fun Asn1Primitive.decodeInstantWithOptionalImplicitTag(expectedTag: Asn1Element.Tag?): Instant {
    if (expectedTag == null) return decodeToInstant()

    val utc = catchingUnwrapped { Instant.decodeUtcTimeFromAsn1ContentBytes(content) }.getOrNull()
    if (utc != null) return utc

    val generalized = catchingUnwrapped { Instant.decodeGeneralizedTimeFromAsn1ContentBytes(content) }.getOrNull()
    if (generalized != null) return generalized

    throw SerializationException(
        "Failed to decode implicitly tagged ASN.1 TIME for kotlin.time.Instant: " +
                "content is neither UTCTime nor GeneralizedTime"
    )
}

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
