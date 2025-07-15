package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.encoding.*
import kotlinx.io.Source
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.ExperimentalSerializationApi
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
class DerDecoder internal constructor(
    private val elements: List<Asn1Element>,
    private val indent: String = "",
    override val serializersModule: SerializersModule = EmptySerializersModule()
) : AbstractDecoder() {


    constructor(
        source: Source,
        serializersModule: SerializersModule = EmptySerializersModule()
    ) : this(source.readFullyToAsn1Elements().first, "", serializersModule)

    private var index = 0
    private lateinit var propertyDescriptor: SerialDescriptor
    private var propertyAnnotations: List<Annotation> = emptyList()


    override fun beginStructure(descriptor: SerialDescriptor): CompositeDecoder {

        // 1. Pick the element that belongs to *this* level
        val element = elements[index]

        // 2. hand over decoding of the children to a *new* decoder
        index++

        return when (descriptor.kind) {
            is StructureKind.CLASS,
            is StructureKind.OBJECT,
            is StructureKind.LIST,
            is StructureKind.MAP -> {
                if (element is Asn1Structure) {
                    DerDecoder(
                        element.children,
                        indent = "$indent  ",
                        serializersModule = serializersModule
                    )
                } else {
                    throw SerializationException(
                        "Expected an ASN.1 structure for ${descriptor.serialName}, " +
                                "but got ${element::class.simpleName}"
                    )
                }
            }

            // Primitive wrappers (CHOICE, ENUM, etc.) keep using the same instance
            else -> this

        }
    }

    override fun decodeElementIndex(descriptor: SerialDescriptor): Int {
        if (index >= elements.size) return CompositeDecoder.DECODE_DONE

        propertyDescriptor = descriptor.getElementDescriptor(index)
        propertyAnnotations = descriptor.getElementAnnotations(index)

        return if (index < elements.size) index else CompositeDecoder.DECODE_DONE
    }


    override fun decodeValue(): Any {
        val inlineLayers = if (pendingInlineAnnotations.isNotEmpty())
            pendingInlineAnnotations.removeLast() else emptyList()

        val currentAnnotatedElement = elements[index]
        index++

        // Process annotations to get the actual element and expected tag
        val annotations = propertyAnnotations.asn1Layers + inlineLayers
        val (processedElement, expectedTag) = processAnnotationsForDecoding(
            currentAnnotatedElement,
            annotations
        )

        return when (propertyDescriptor.kind) {
            PolymorphicKind.OPEN -> TODO("Polymorphic decoding not yet implemented")
            PolymorphicKind.SEALED -> TODO("Sealed class decoding not yet implemented")
            PrimitiveKind.BOOLEAN -> processedElement.asPrimitive().decodeToBoolean(expectedTag ?: Asn1Element.Tag.BOOL)
            PrimitiveKind.BYTE -> processedElement.asPrimitive().decodeToInt(expectedTag ?: Asn1Element.Tag.INT)
                .toByte()

            PrimitiveKind.CHAR -> processedElement.asPrimitive().decodeString(expectedTag)
                .also { if (it.length != 1) throw SerializationException("String is not a char") }[0]

            PrimitiveKind.DOUBLE -> processedElement.asPrimitive().decodeToDouble(expectedTag ?: Asn1Element.Tag.REAL)
            PrimitiveKind.FLOAT -> processedElement.asPrimitive().decodeToFloat(expectedTag ?: Asn1Element.Tag.REAL)
            PrimitiveKind.INT -> processedElement.asPrimitive().decodeToInt(expectedTag ?: Asn1Element.Tag.INT)
            PrimitiveKind.LONG -> processedElement.asPrimitive().decodeToLong(expectedTag ?: Asn1Element.Tag.INT)
            PrimitiveKind.SHORT -> processedElement.asPrimitive().decodeToInt(expectedTag ?: Asn1Element.Tag.INT)
                .toShort()

            PrimitiveKind.STRING -> processedElement.asPrimitive().decodeString(expectedTag)
            SerialKind.ENUM -> processedElement.asPrimitive().decodeToEnumOrdinal(expectedTag ?: Asn1Element.Tag.INT)
            else -> TODO("Unsupported kind: ${propertyDescriptor.kind}")
        } as Any
    }


    private val pendingInlineAnnotations: ArrayDeque<List<Layer>> = ArrayDeque()
    private var pendingInlineAsn1BitString = false

    // ---------------------------------------------------------------------------
// ADD inside the class body
    @OptIn(ExperimentalSerializationApi::class)
    override fun decodeInline(descriptor: SerialDescriptor): Decoder {
        /*
         * Mirrors the encoder logic: push the annotations that belong to the
         * value-class so that the next decode*() call can honour them.
         */
        pendingInlineAsn1BitString = descriptor.isAsn1BitString
        pendingInlineAnnotations.addLast(descriptor.annotations.asn1Layers)
        return this
    }


    override fun <T : Any?> decodeSerializableValue(
        deserializer: DeserializationStrategy<T>,
        previousValue: T?
    ): T {

        val currentAnnotatedElement = elements[index]
        if (currentAnnotatedElement == Asn1Null) {
            if (!propertyDescriptor.doEncodeNull && !propertyAnnotations.doEncodeNull) {
                throw SerializationException("Null value found, but target value should not have been present!")
            }
            index++
            return null as T
        }
        return decodeSerializableValue(deserializer)
    }

    override fun <T> decodeSerializableValue(deserializer: DeserializationStrategy<T>): T {

        val currentAnnotatedElement = elements[index]
        val isBitString = propertyAnnotations.isAsn1BitString||pendingInlineAsn1BitString
        pendingInlineAsn1BitString=false
        val propertyAnnotations = propertyAnnotations.asn1Layers
        val classLevelAnnotations = deserializer.descriptor.annotations.asn1Layers

        // Combine property and class-level annotations for processing
        val allAnnotations = (if (pendingInlineAnnotations.isNotEmpty())
            pendingInlineAnnotations.removeLast() else emptyList()) +propertyAnnotations + classLevelAnnotations

        if (deserializer.descriptor.isInline) {
            // Let the framework do its inline-class magic
            return deserializer.deserialize(this)
        }

        /* your old custom handling for non-inline cases */
        val (processedElement, expectedTag) = processAnnotationsForDecoding(
            currentAnnotatedElement,
            allAnnotations
        )

        // Tag-check for explicitly / implicitly tagged primitives
        val tagToValidate = expectedTag ?: run {

            if (deserializer is Asn1Serializer<*, T>) {
                val encodable = when (processedElement) {
                    is Asn1Primitive -> (deserializer as Asn1Decodable<Asn1Primitive, T>).decodeFromTlv(processedElement)
                    is Asn1Structure -> (deserializer as Asn1Decodable<Asn1Structure, T>).decodeFromTlv(processedElement)
                }
                index++
                return encodable
            }

            // If no explicit tag is specified, we should still validate against the default tag
            // for the type being deserialized (when no annotations are present)
            if (allAnnotations.isEmpty()) {
                if (isBitString) Asn1Element.Tag.BIT_STRING
               else  getDefaultTagForDescriptor(deserializer.descriptor)
            } else {
                null
            }
        }

        tagToValidate?.let { expected ->
            if (processedElement.tag != expected) {
                throw Asn1TagMismatchException(expected, processedElement.tag)
            }
        }

        // (2) Fast paths for primitive *unsigned* surrogates & helpers
        when (deserializer) {
            UByte.serializer() -> return processedElement.asPrimitive()
                .decodeToUInt(expectedTag ?: Asn1Element.Tag.INT)
                .toUByte()
                .also { index++ } as T

            UShort.serializer() -> return processedElement.asPrimitive()
                .decodeToUInt(expectedTag ?: Asn1Element.Tag.INT)
                .toUShort()
                .also { index++ } as T

            UInt.serializer() -> return processedElement.asPrimitive()
                .decodeToUInt(expectedTag ?: Asn1Element.Tag.INT)
                .also { index++ } as T

            ULong.serializer() -> return processedElement.asPrimitive()
                .decodeToULong(expectedTag ?: Asn1Element.Tag.INT)
                .also { index++ } as T

            Asn1ElementSerializer -> return processedElement
                .also {
                    expectedTag?.let { ex ->
                        if (it.tag != ex) throw Asn1TagMismatchException(ex, it.tag)
                    }
                }
                .also { index++ } as T

            ByteArraySerializer() -> {
                if (isBitString) {
                    // Decode BitSet from ASN.1 BitString and convert to ByteArray
                    val bitSet = processedElement.asPrimitive().asAsn1BitString().toBitSet()
                    return bitSet.toByteArray().also { index++ } as T
                } else {
                    // Regular ByteArray decoding (OCTET STRING)
                    return processedElement.asPrimitive().content.also { index++ } as T
                }
            }
        }

        // (3) Primitive kinds → defer to decodeValue()
        if (deserializer.descriptor.kind is PrimitiveKind) {
            propertyDescriptor = deserializer.descriptor
            this.propertyAnnotations = deserializer.descriptor.annotations.asn1Layers
            return decodeValue() as T
        }


        val childDecoder = DerDecoder(
            elements = mutableListOf(processedElement),
            indent = "$indent  ",
            serializersModule = serializersModule,
        )

        val value = deserializer.deserialize(childDecoder)
        index++
        return value
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
                        throw Asn1TagMismatchException(Asn1Element.Tag.OCTET_STRING, currentElement.tag)
                    }
                    val octetString = currentElement.asEncapsulatingOctetString()
                    currentElement = octetString.nextChild()
                    if (octetString.hasMoreChildren()) throw Asn1StructuralException("Octet string should only contain one child")
                    currentTag = currentElement.tag

                }

                Type.EXPLICIT_TAG -> {
                    val expectedTag =
                        Asn1Element.Tag(annotation.tag, currentTag.isConstructed, currentTag.tagClass)
                    if (currentTag != expectedTag) {
                        throw Asn1TagMismatchException(expectedTag, currentElement.tag)
                    }
                    val octetString = currentElement.asStructure()
                    currentElement = octetString.nextChild()
                    if (octetString.hasMoreChildren()) throw Asn1StructuralException("Explicit tag should only contain one child")
                    currentTag = currentElement.tag

                }

                Type.IMPLICIT_TAG -> {

                    val expectedTag = Asn1Element.Tag(annotation.tag, currentTag.isConstructed, currentTag.tagClass)
                    if (currentTag != expectedTag) {
                        throw Asn1TagMismatchException(expectedTag, currentElement.tag)
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

            else -> throw Asn1TagMismatchException(Asn1Element.Tag.STRING_UTF8, tag)
        }
    } else {
        if (tag != implicitTagOverride) throw Asn1TagMismatchException(implicitTagOverride, tag)
        String.decodeFromAsn1ContentBytes(content)
    }