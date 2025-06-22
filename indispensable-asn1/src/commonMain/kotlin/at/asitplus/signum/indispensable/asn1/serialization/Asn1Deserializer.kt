package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1ElementHexStringSerializer
import at.asitplus.signum.indispensable.asn1.Asn1Null
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
    //TODO asn1element

    constructor(
        source: Source,
        serializersModule: SerializersModule = EmptySerializersModule()
    ) : this(source.readFullyToAsn1Elements().first, serializersModule)


    private var index = 0
    private lateinit var currentDescriptor: SerialDescriptor
    private lateinit var currentAnnotations: List<Annotation>
    private var isNested = false

    init {
        //  println("### ELEMENTS: ${elements.joinToString { it.toString() }}")
    }

    // ----------------------------------------------------------------------
    // CompositeDecoder
    // ----------------------------------------------------------------------
    override fun beginStructure(descriptor: SerialDescriptor): CompositeDecoder {
        isNested = true
        println("$indent$this beginStructure(${descriptor.serialName})")
        return Asn1Deserializer(
            elements[index].asStructure().children,
            serializersModule,
            indent + "  "
        )                    // this decoder is its own composite
    }

    override fun decodeElementIndex(descriptor: SerialDescriptor): Int {
        println("$indent$this decodeElementIndex(idx=$index), descriptor=${descriptor.serialName} ")
        if (index >= elements.size) return CompositeDecoder.DECODE_DONE
        currentDescriptor = descriptor.getElementDescriptor(index)
        currentAnnotations = descriptor.getElementAnnotations(index)

        return if (index < elements.size) index else CompositeDecoder.DECODE_DONE
    }

    override fun endStructure(descriptor: SerialDescriptor) {
        println("$indent$this endStructure(${descriptor.serialName})")
        isNested = false
    }

    // ----------------------------------------------------------------------
    // Primitive decoders
    // ----------------------------------------------------------------------
    override fun decodeValue(): Any {
        println("$indent$this decodeValue(descriptor=");println("\t$currentDescriptor, idx=$index)")
        val currentElement = elements[index]
        index++
        return when (currentDescriptor.kind) {
            PolymorphicKind.OPEN -> TODO()
            PolymorphicKind.SEALED -> TODO()
            PrimitiveKind.BOOLEAN -> currentElement.asPrimitive().decodeToBoolean()
            PrimitiveKind.BYTE -> currentElement.asPrimitive().decodeToInt().toByte()
            PrimitiveKind.CHAR -> currentElement.asPrimitive().decodeToString()
                .also { if (it.length != 1) throw SerializationException("Sting is not a char") }[0]
            PrimitiveKind.DOUBLE -> currentElement.asPrimitive().decodeToDouble()
            PrimitiveKind.FLOAT -> currentElement.asPrimitive().decodeToFloat()
            PrimitiveKind.INT -> currentElement.asPrimitive().decodeToInt()
            PrimitiveKind.LONG -> currentElement.asPrimitive().decodeToLong()
            PrimitiveKind.SHORT -> currentElement.asPrimitive().decodeToInt().toShort()
            PrimitiveKind.STRING -> currentElement.asPrimitive().decodeToString()
            SerialKind.CONTEXTUAL -> TODO()
            SerialKind.ENUM -> currentElement.asPrimitive().decodeToEnumOrdinal().toInt()
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
            if (!currentDescriptor.doEncodeNull && currentAnnotations.find { it is Asn1EncodeNull }==null) throw SerializationException("Null value found, but target value should not have been present!")
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

        when(deserializer) {
            UByte.serializer() -> return elements[index].asPrimitive().decodeToUInt().toUByte().also { index++ } as T
            UShort.serializer() -> return elements[index].asPrimitive().decodeToUInt().toUShort().also { index++ } as T
            UInt.serializer() -> return elements[index].asPrimitive().decodeToUInt().also { index++ } as T
            ULong.serializer() -> return elements[index].asPrimitive().decodeToULong().also { index++ } as T
            Asn1ElementHexStringSerializer -> return elements[index].also { index++ } as T
        }

        if (deserializer.descriptor.kind is PrimitiveKind) {
            currentDescriptor = deserializer.descriptor
            return decodeValue() as T
        }


        val currentElement = elements[index]
        index++
        if (deserializer.descriptor == ByteArraySerializer().descriptor) {
            println("$indent$this decoding ByteArray as octet string")
            return currentElement.asOctetString().content as T
        }
        println("$indent↳ spawn child decoder for ${deserializer.descriptor} (parent idx=${index})")


        return deserializer.deserialize(
            Asn1Deserializer(listOf(currentElement), serializersModule, indent + "  ").also {
                if (deserializer.descriptor.kind == SerialKind.ENUM) {
                    it.currentDescriptor = deserializer.descriptor
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