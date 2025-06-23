package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.encoding.*
import kotlinx.io.Buffer
import kotlinx.io.Source
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerializationException
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.descriptors.*
import kotlinx.serialization.encoding.AbstractDecoder
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.modules.EmptySerializersModule
import kotlinx.serialization.modules.SerializersModule
import kotlinx.serialization.serializer

@ExperimentalSerializationApi
class Asn1Deserializer(
    private val elements: List<Asn1Element>,
    override val serializersModule: SerializersModule = EmptySerializersModule(),
    private val indent: String = ""
) : AbstractDecoder() {

    //TODO nestign through annotations
    //TODO unsigned (inline) decoding
    //TODO implicit tagging
    //TODO clean index incrementation
    //TODO asn1encodable and decodable

    constructor(
        source: Source,
        serializersModule: SerializersModule = EmptySerializersModule()
    ) : this(source.readFullyToAsn1Elements().first, serializersModule)


    private var index = 0
    private lateinit var propertyDescriptor: SerialDescriptor
    private var propertyAnnptations: List<Annotation> = emptyList()

    init {
        //  println("### ELEMENTS: ${elements.joinToString { it.toString() }}")
    }

    // ----------------------------------------------------------------------
    // CompositeDecoder
    // ----------------------------------------------------------------------
    override fun beginStructure(descriptor: SerialDescriptor): CompositeDecoder {
        println("$indent$this beginStructure(${descriptor.serialName})")
        val tagToCheck = (propertyAnnptations.implicitTag?:descriptor.implicitTag)?.let {
            val implcitTag = elements[index].withImplicitTag(it).tag
            if (elements[index].tag.tagValue != it) throw Asn1TagMismatchException(elements[index].tag, implcitTag)
            implcitTag
        }
            ?: if (descriptor.isAsn1OctetString) Asn1Element.Tag.OCTET_STRING else if (descriptor.isAsn1Set) Asn1Element.Tag.SET else Asn1Element.Tag.SEQUENCE


        if (elements[index].tag != tagToCheck) throw Asn1TagMismatchException(elements[index].tag, tagToCheck)


        return Asn1Deserializer(
            elements[index].asStructure().children,
            serializersModule,
            indent + "  "
        )                    // this decoder is its own composite
    }

    override fun decodeElementIndex(descriptor: SerialDescriptor): Int {
        println("$indent$this decodeElementIndex(idx=$index), descriptor=${descriptor.serialName} ")
        if (index >= elements.size) return CompositeDecoder.DECODE_DONE
        propertyDescriptor = descriptor.getElementDescriptor(index)
        propertyAnnptations = descriptor.getElementAnnotations(index)

        return if (index < elements.size) index else CompositeDecoder.DECODE_DONE
    }

    override fun endStructure(descriptor: SerialDescriptor) {
        println("$indent$this endStructure(${descriptor.serialName})")
    }

    // ----------------------------------------------------------------------
    // Primitive decoders
    // ----------------------------------------------------------------------
    override fun decodeValue(): Any {
        println("$indent$this decodeValue(descriptor=");println("\t$propertyDescriptor, idx=$index)")
        val currentElement = elements[index]
        index++
        //todo: move this to decodeSerializableValue
        //TODO inefficient. make the annotation store a tag template! to then construct only the real tag
        val implicitTag = (propertyAnnptations.implicitTag
            ?: propertyDescriptor.implicitTag)?.let { currentElement.withImplicitTag(it).tag }

        return when (propertyDescriptor.kind) {
            PolymorphicKind.OPEN -> TODO()
            PolymorphicKind.SEALED -> TODO()
            PrimitiveKind.BOOLEAN -> currentElement.asPrimitive().decodeToBoolean(implicitTag ?: Asn1Element.Tag.BOOL)
            PrimitiveKind.BYTE -> currentElement.asPrimitive().decodeToInt(implicitTag ?: Asn1Element.Tag.INT).toByte()
            PrimitiveKind.CHAR -> currentElement.asPrimitive().decodeString(implicitTag)
                .also { if (it.length != 1) throw SerializationException("Sting is not a char") }[0]

            PrimitiveKind.DOUBLE -> currentElement.asPrimitive().decodeToDouble(implicitTag ?: Asn1Element.Tag.REAL)
            PrimitiveKind.FLOAT -> currentElement.asPrimitive().decodeToFloat(implicitTag ?: Asn1Element.Tag.REAL)
            PrimitiveKind.INT -> currentElement.asPrimitive().decodeToInt(implicitTag ?: Asn1Element.Tag.INT)
            PrimitiveKind.LONG -> currentElement.asPrimitive().decodeToLong(implicitTag ?: Asn1Element.Tag.INT)
            PrimitiveKind.SHORT -> currentElement.asPrimitive().decodeToInt(implicitTag ?: Asn1Element.Tag.INT)
                .toShort()

            PrimitiveKind.STRING -> currentElement.asPrimitive().decodeString(implicitTag)
            SerialKind.CONTEXTUAL -> TODO()
            SerialKind.ENUM -> currentElement.asPrimitive().decodeToEnumOrdinal(implicitTag ?: Asn1Element.Tag.INT)
                .toInt()

            StructureKind.CLASS, StructureKind.OBJECT, StructureKind.LIST -> TODO()
            StructureKind.MAP -> TODO()
            StructureKind.OBJECT -> TODO()
        } as Any
    }


    override fun <T : Any?> decodeSerializableValue(
        deserializer: DeserializationStrategy<T>,
        previousValue: T?
    ): T {
        println("$indent$this decodeSerializableValue(deserializer=${deserializer.descriptor.serialName}, previousValue=$previousValue)")

        val currentElement = elements[index]
        if (currentElement == Asn1Null) {
            //TODO: global config
            if (!propertyDescriptor.doEncodeNull && !propertyAnnptations.doEncodeNull) throw SerializationException("Null value found, but target value should not have been present!")
            index++
            return null as T
        }
        return decodeSerializableValue(deserializer)
    }

    // ----------------------------------------------------------------------
    // Nested / child objects
    // ----------------------------------------------------------------------
    override fun <T> decodeSerializableValue(deserializer: DeserializationStrategy<T>): T {
        println("$indent$this decodeSerializableValue")
        val currentElement = elements[index]
        //TODO also check outer implict tags

        val implicitTag = (propertyAnnptations.implicitTag ?: deserializer.descriptor.implicitTag)?.let {
            currentElement.withImplicitTag(
                it
            ).tag
        }
        if (implicitTag != null) if (currentElement.tag != implicitTag) throw Asn1TagMismatchException(
            implicitTag,
            currentElement.tag
        )

        when (deserializer) {

            UByte.serializer() -> return currentElement.asPrimitive().decodeToUInt(implicitTag ?: Asn1Element.Tag.INT)
                .toUByte().also { index++ } as T

            UShort.serializer() -> return currentElement.asPrimitive().decodeToUInt(implicitTag ?: Asn1Element.Tag.INT)
                .toUShort().also { index++ } as T

            UInt.serializer() -> return currentElement.asPrimitive().decodeToUInt(implicitTag ?: Asn1Element.Tag.INT)
                .also { index++ } as T

            ULong.serializer() -> return currentElement.asPrimitive().decodeToULong(implicitTag ?: Asn1Element.Tag.INT)
                .also { index++ } as T

            Asn1ElementHexStringSerializer -> return currentElement.also {
                if (implicitTag != null && (it.tag != implicitTag)) throw Asn1TagMismatchException(implicitTag, it.tag)

                index++
            } as T
        }

        if (deserializer.descriptor.kind is PrimitiveKind) {
            propertyDescriptor = deserializer.descriptor
            propertyAnnptations = deserializer.descriptor.annotations
            return decodeValue() as T
        }

        index++
        if (deserializer.descriptor == ByteArraySerializer().descriptor) {
            println("$indent$this decoding ByteArray as octet string")
            val implicitTag = (propertyAnnptations.implicitTag ?: propertyDescriptor.implicitTag)?.let {
                currentElement.withImplicitTag(it).tag
            }
            return if (implicitTag != null) {
                if (currentElement.tag != implicitTag) throw Asn1TagMismatchException(implicitTag, currentElement.tag)
                currentElement.asPrimitive().content as T //TODO: this could inadvertently be valid structured ASN.1, so we need to add `.derEncodedContentBytes` or something similar to any ASN.1 element
            } else currentElement.asOctetString().content as T
        }
        println("$indent↳ spawn child decoder for ${deserializer.descriptor} (parent idx=${index})")

//TODO check toplevel enum
        return deserializer.deserialize(
            Asn1Deserializer(listOf(currentElement), serializersModule, indent + "  ").also {

                it.propertyAnnptations = propertyAnnptations
                if (deserializer.descriptor.kind == SerialKind.ENUM) {
                    it.propertyDescriptor = deserializer.descriptor
                }

            }
        )
    }
}

@ExperimentalSerializationApi
fun <T> decodeFromDer(source: ByteArray, deserializer: DeserializationStrategy<T>): T {
    val decoder = Asn1Deserializer(Buffer().also { it.write(source) })
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

