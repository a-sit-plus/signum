package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.encoding.decodeToBoolean
import at.asitplus.signum.indispensable.asn1.encoding.decodeToDouble
import at.asitplus.signum.indispensable.asn1.encoding.decodeToFloat
import at.asitplus.signum.indispensable.asn1.encoding.decodeToInt
import at.asitplus.signum.indispensable.asn1.encoding.decodeToLong
import at.asitplus.signum.indispensable.asn1.encoding.decodeToString
import at.asitplus.signum.indispensable.asn1.encoding.readAsn1Element
import kotlinx.io.Buffer
import kotlinx.io.Source
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.AbstractDecoder
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.modules.EmptySerializersModule
import kotlinx.serialization.modules.SerializersModule
import kotlinx.serialization.serializer

class Asn1Deserializer(private var tlv : Asn1Element, override val serializersModule: SerializersModule = EmptySerializersModule(),) : AbstractDecoder(){
   constructor(source: Source, serializersModule: SerializersModule = EmptySerializersModule()) : this(source.readAsn1Element().first, serializersModule)
    private var elementIndex = 0

    override fun decodeValue(): Any {
        return super.decodeValue()
    }

    override fun <T> decodeSerializableValue(deserializer: DeserializationStrategy<T>): T {
        val kind = deserializer.descriptor.kind
        if(kind is PrimitiveKind) {
            return  when(kind) {
                PrimitiveKind.BOOLEAN -> tlv.asPrimitive().decodeToBoolean()
                PrimitiveKind.BYTE ->  tlv.asPrimitive().decodeToInt().toByte()
                PrimitiveKind.CHAR -> tlv.asPrimitive().decodeToString().let { if (it.length == 1) it[0] else throw IllegalArgumentException("String is not a char") }
                PrimitiveKind.DOUBLE -> tlv.asPrimitive().decodeToDouble()
                PrimitiveKind.FLOAT -> tlv.asPrimitive().decodeToFloat()
                PrimitiveKind.INT -> tlv.asPrimitive().decodeToInt()
                PrimitiveKind.LONG -> tlv.asPrimitive().decodeToLong()
                PrimitiveKind.SHORT -> tlv.asPrimitive().decodeToInt().toShort()
                PrimitiveKind.STRING -> tlv.asPrimitive().decodeToString()
            } as T
        }
        else TODO()
    }

    override fun beginStructure(descriptor: SerialDescriptor): CompositeDecoder {
        return super.beginStructure(descriptor)
    }

    override fun decodeElementIndex(descriptor: SerialDescriptor): Int {
        if (elementIndex == descriptor.elementsCount) return CompositeDecoder.DECODE_DONE
        return elementIndex++
    }

    override fun decodeBoolean(): Boolean {
        return super.decodeBoolean()
    }
}

@ExperimentalSerializationApi
fun <T> decodeFromList(source: ByteArray, deserializer: DeserializationStrategy<T>): T {
    val decoder = Asn1Deserializer(Buffer().also { it.write(source) })
    return decoder.decodeSerializableValue(deserializer)
}

@ExperimentalSerializationApi
inline fun <reified T> decodeFromDer(source: ByteArray): T = decodeFromList(source, serializer())