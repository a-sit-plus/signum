package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.encoding.*
import kotlinx.io.Buffer
import kotlinx.io.Source
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerializationException
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.descriptors.*
import kotlinx.serialization.encoding.AbstractDecoder
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.modules.EmptySerializersModule
import kotlinx.serialization.modules.SerializersModule
import kotlinx.serialization.serializer

/**
 * Represents the current element being processed with its annotation context
 */
private data class AnnotatedElement(
    val element: Asn1Element,
    val remainingAnnotations: List<Layer> = emptyList()
)

@ExperimentalSerializationApi
class DerDecoder private constructor(
    private val annotatedElements: List<AnnotatedElement>,
    private val indent: String = "",
    override val serializersModule: SerializersModule = EmptySerializersModule()
) : AbstractDecoder() {

    constructor(
        elements: List<Asn1Element>,
        serializersModule: SerializersModule = EmptySerializersModule(),
        indent: String = ""
    ) : this(elements.map { AnnotatedElement(it) }, indent, serializersModule)

    constructor(
        source: Source,
        serializersModule: SerializersModule = EmptySerializersModule()
    ) : this(source.readFullyToAsn1Elements().first, serializersModule)

    private var index = 0
    private lateinit var propertyDescriptor: SerialDescriptor
    private var propertyAnnotations: List<Annotation> = emptyList()


    override fun beginStructure(descriptor: SerialDescriptor): CompositeDecoder {

        // 1. Pick the element that belongs to *this* level
        val currentAnnotated = annotatedElements[index]
        val element = currentAnnotated.element

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
        if (index >= annotatedElements.size) return CompositeDecoder.DECODE_DONE

        propertyDescriptor = descriptor.getElementDescriptor(index)
        propertyAnnotations = descriptor.getElementAnnotations(index)

        return if (index < annotatedElements.size) index else CompositeDecoder.DECODE_DONE
    }


    override fun decodeValue(): Any {

        val currentAnnotatedElement = annotatedElements[index]
        index++

        // Process annotations to get the actual element and expected tag
        val annotations = propertyAnnotations.asn1Layers
        val (processedElement, expectedTag) = processAnnotationsForDecoding(
            currentAnnotatedElement.element,
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

    override fun <T : Any?> decodeSerializableValue(
        deserializer: DeserializationStrategy<T>,
        previousValue: T?
    ): T {

        val currentAnnotatedElement = annotatedElements[index]
        if (currentAnnotatedElement.element == Asn1Null) {
            if (!propertyDescriptor.doEncodeNull && !propertyAnnotations.doEncodeNull) {
                throw SerializationException("Null value found, but target value should not have been present!")
            }
            index++
            return null as T
        }
        return decodeSerializableValue(deserializer)
    }

    override fun <T> decodeSerializableValue(deserializer: DeserializationStrategy<T>): T {

        val currentAnnotatedElement = annotatedElements[index]
        val propertyAnnotations = propertyAnnotations.asn1Layers
        val classLevelAnnotations = deserializer.descriptor.annotations.asn1Layers

        // Combine property and class-level annotations for processing
        val allAnnotations = propertyAnnotations + classLevelAnnotations
        val (processedElement, expectedTag) = processAnnotationsForDecoding(
            currentAnnotatedElement.element,
            allAnnotations
        )

        // Tag-check for explicitly / implicitly tagged primitives
        val tagToValidate = expectedTag ?: run {

            if(deserializer is Asn1Serializer<*,T>){
                val encodable = when(processedElement) {
                    is Asn1Primitive ->  (deserializer as Asn1Decodable<Asn1Primitive,T>).decodeFromTlv(processedElement)
                    is Asn1Structure ->  (deserializer as Asn1Decodable<Asn1Structure,T>).decodeFromTlv(processedElement)
                }
                index++
                return encodable
            }

            // If no explicit tag is specified, we should still validate against the default tag
            // for the type being deserialized (when no annotations are present)
            if (allAnnotations.isEmpty()) {
                getDefaultTagForDescriptor(deserializer.descriptor)
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
        }

        // (3) Primitive kinds → defer to decodeValue()
        if (deserializer.descriptor.kind is PrimitiveKind) {
            propertyDescriptor = deserializer.descriptor
            this.propertyAnnotations = deserializer.descriptor.annotations.asn1Layers
            return decodeValue() as T
        }


        val childDecoder = DerDecoder(
            elements = mutableListOf(processedElement),
            serializersModule = serializersModule,
            indent = "$indent  "
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
    else when (descriptor.kind) {
        is StructureKind.CLASS, is StructureKind.OBJECT -> Asn1Element.Tag.SEQUENCE
        is StructureKind.LIST -> Asn1Element.Tag.SEQUENCE
        is StructureKind.MAP -> Asn1Element.Tag.SEQUENCE
        else -> null // For primitive types, tag validation happens in decodeValue()
    }
}

@ExperimentalSerializationApi
fun <T> decodeFromDer(source: ByteArray, deserializer: DeserializationStrategy<T>): T {
    val decoder = DerDecoder(Buffer().also { it.write(source) })
    return decoder.decodeSerializableValue(deserializer)
}

@ExperimentalSerializationApi
inline fun <reified T> decodeFromDer(source: ByteArray): T = decodeFromDer(source, serializer())

fun Asn1Primitive.decodeString(implicitTagOverride: Asn1Element.Tag?): String =
    if (implicitTagOverride == null) {
        if (tag != Asn1Element.Tag.STRING_UTF8) throw Asn1TagMismatchException(Asn1Element.Tag.STRING_UTF8, tag)
        decodeToString()
    } else {
        if (tag != implicitTagOverride) throw Asn1TagMismatchException(implicitTagOverride, tag)
        String.decodeFromAsn1ContentBytes(content)
    }