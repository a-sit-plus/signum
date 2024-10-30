package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.catchingUnwrappedAs
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Exception
import at.asitplus.signum.indispensable.asn1.BERTags
import at.asitplus.signum.indispensable.asn1.assertTag
import at.asitplus.signum.indispensable.asn1.encoding.*
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.AbstractDecoder
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.modules.EmptySerializersModule
import kotlinx.serialization.modules.SerializersModule

class Asn1Decoder(
    private val elements: List<Asn1Element>,
    override val serializersModule: SerializersModule = EmptySerializersModule()
) : AbstractDecoder() {
    private var elementIndex = 0
    private val iterator = elements.iterator()

    override fun decodeSequentially(): Boolean = true

    override fun decodeElementIndex(descriptor: SerialDescriptor): Int {
        if (elementIndex == elements.size) return CompositeDecoder.DECODE_DONE
        return elementIndex++
    }

    override fun decodeNull(): Nothing? {
        decode {
            if (iterator.next().asPrimitive().assertTag(Asn1Element.Tag.NULL).content.isNotEmpty())
                throw Asn1Exception("Illegal NULL")
        }
        return null
    }

    override fun decodeBoolean(): Boolean = decode {
        iterator.next().asPrimitive().decodeToBoolean()
    }

    override fun decodeLong(): Long = decode {
        iterator.next().asPrimitive().decodeToLong()
    }

    override fun decodeByte(): Byte = decodeLong().toByte()
    override fun decodeShort(): Short = decodeLong().toShort()
    override fun decodeChar(): Char = decodeLong().toInt().toChar()
    override fun decodeInt(): Int = decodeLong().toInt()
    override fun decodeDouble(): Double {
        TODO()
    }

    override fun decodeFloat(): Float = decodeLong().toFloat()

    override fun decodeEnum(enumDescriptor: SerialDescriptor): Int = decode {
        iterator.next().asPrimitive().decode(BERTags.ENUMERATED.toULong()) {
            Int.decodeFromAsn1ContentBytes(it)
        }
    }

    override fun decodeString(): String=decode {
        iterator.next().asPrimitive().decodeToString()
    }

    override fun beginStructure(descriptor: SerialDescriptor): CompositeDecoder= decode {
        //TODO evaluate descriptor
        Asn1Decoder(iterator.next().asStructure().children, serializersModule)
    }
}

internal inline fun <reified T> decode(block: () -> T) =
    catchingUnwrappedAs(::SerializationException, block).getOrThrow()