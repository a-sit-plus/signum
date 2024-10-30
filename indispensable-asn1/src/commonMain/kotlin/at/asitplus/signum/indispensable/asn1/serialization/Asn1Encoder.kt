package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Primitive
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.BERTags
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.encoding.encodeToAsn1ContentBytes
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.AbstractEncoder
import kotlinx.serialization.encoding.CompositeEncoder
import kotlinx.serialization.modules.EmptySerializersModule
import kotlinx.serialization.modules.SerializersModule

class Asn1Encoder(
    val parent: MutableList<Asn1Element>,
    override val serializersModule: SerializersModule = EmptySerializersModule()
) : AbstractEncoder() {
    internal val elements = mutableListOf<Asn1Element>()

    override fun encodeNull() {
        elements += Asn1.Null()
    }

    override fun beginStructure(descriptor: SerialDescriptor): CompositeEncoder =
        Asn1Encoder(elements, serializersModule)


    override fun endStructure(descriptor: SerialDescriptor) {

        //TODO evaluate descriptor for tags, make set sorted by default, etc
        val sequence = Asn1Sequence(elements)

        parent += sequence
    }

    override fun encodeBoolean(value: Boolean) {
        elements + Asn1.Bool(value)
    }

    override fun encodeLong(value: Long) {
        elements += Asn1.Int(value)
    }

    override fun encodeByte(value: Byte) = encodeLong(value.toLong())

    override fun encodeChar(value: Char) = encodeLong(value.code.toLong())

    override fun encodeDouble(value: Double) {
        TODO()
    }

    override fun encodeElement(descriptor: SerialDescriptor, index: Int): Boolean {
        //TODO
        return true
    }

    override fun encodeEnum(enumDescriptor: SerialDescriptor, index: Int) {
        elements += Asn1Primitive(BERTags.ENUMERATED, index.encodeToAsn1ContentBytes())
    }

    override fun encodeFloat(value: Float) = encodeDouble(value.toDouble())

    override fun encodeInt(value: Int) = encodeLong(value.toLong())

    override fun encodeShort(value: Short) = encodeLong(value.toLong())

    override fun encodeString(value: String) {
        elements += Asn1.Utf8String(value)
    }

}