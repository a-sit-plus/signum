package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.Asn1ExplicitlyTagged
import at.asitplus.signum.indispensable.asn1.Asn1OctetString
import at.asitplus.signum.indispensable.asn1.Asn1Set
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.encoding.encodeToAsn1Primitive
import at.asitplus.signum.internals.ImplementationError
import kotlinx.io.Buffer
import kotlinx.io.Sink
import kotlinx.io.readByteArray
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerializationException
import kotlinx.serialization.SerializationStrategy
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.AbstractEncoder
import kotlinx.serialization.modules.EmptySerializersModule
import kotlinx.serialization.modules.SerializersModule
import kotlinx.serialization.serializer

//TODO: proper encapsulation of with octet strings and explicit tags as class-level annotations

//TODO value classes proper!
@ExperimentalSerializationApi
class Asn1Serializer(
    override val serializersModule: SerializersModule = EmptySerializersModule(),
) : AbstractEncoder() {

    private val buffer = mutableListOf<() -> Asn1Element>()
    private var descriptorAndIndex: Pair<SerialDescriptor, Int>? = null

    override fun encodeValue(value: Any) {

        val implicitTag = descriptorAndIndex?.first?.implicitTag(descriptorAndIndex!!.second)

        val buffer = descriptorAndIndex?.let {
            if (it.isStructurallyAnnotated) {
                buffer.beginAsn1NestedStructure(it.first, it.second).buffer
            } else buffer
        } ?: buffer

        descriptorAndIndex = null
        return when (value) {
            is Asn1Element -> buffer += implicitTag.tagImplicitly { value }
            is Asn1Encodable<*> -> buffer += implicitTag.tagImplicitly(value::encodeToTlv)
            is ByteArray -> buffer += implicitTag.tagImplicitly { Asn1PrimitiveOctetString(value) }

            is Boolean -> buffer += implicitTag.tagImplicitly(value::encodeToAsn1Primitive)

            is Byte -> buffer += implicitTag.tagImplicitly(value.toInt()::encodeToAsn1Primitive)
            is UByte -> buffer += implicitTag.tagImplicitly(value.toUInt()::encodeToAsn1Primitive)

            is Short -> buffer += implicitTag.tagImplicitly(value.toInt()::encodeToAsn1Primitive)
            is UShort -> buffer += implicitTag.tagImplicitly(value.toUInt()::encodeToAsn1Primitive)

            is Int -> buffer += implicitTag.tagImplicitly(value::encodeToAsn1Primitive)
            is UInt -> buffer += implicitTag.tagImplicitly(value::encodeToAsn1Primitive)

            is Float -> buffer += implicitTag.tagImplicitly(value::encodeToAsn1Primitive)

            is Long -> buffer += implicitTag.tagImplicitly(value::encodeToAsn1Primitive)
            is ULong -> buffer += implicitTag.tagImplicitly(value::encodeToAsn1Primitive)

            is Double -> buffer += implicitTag.tagImplicitly(value::encodeToAsn1Primitive)

            is String -> buffer += implicitTag.tagImplicitly(value::encodeToAsn1Primitive)
            is Char -> buffer += implicitTag.tagImplicitly(value.toString()::encodeToAsn1Primitive)

            else -> super.encodeValue(value)
        }
    }

    override fun encodeNull() {
        descriptorAndIndex?.let { (descriptor, index) ->
            if (!descriptor.doEncodeNull(index)) return

            val buffer = if ((descriptor to index).isStructurallyAnnotated) {
                buffer.beginAsn1NestedStructure(descriptor, index).buffer
            } else buffer
            descriptorAndIndex = null

            if (descriptor.doEncodeNull(index)) buffer += Asn1::Null
        }
    }

    override fun encodeElement(descriptor: SerialDescriptor, index: Int): Boolean {
        this.descriptorAndIndex = descriptor to index
        return super.encodeElement(descriptor, index)
    }


    override fun encodeEnum(enumDescriptor: SerialDescriptor, index: Int) {
        val implicitTag = descriptorAndIndex?.first?.implicitTag(descriptorAndIndex!!.second)

        //this block here needs to be swapped with the other somehow
        val buffer = descriptorAndIndex?.let {
            if (it.isStructurallyAnnotated) {
                buffer.beginAsn1NestedStructure(it.first, it.second).buffer
            } else buffer
        } ?: buffer

        descriptorAndIndex = null

        //todo disallow tags on enum constants
        if (enumDescriptor.isStructurallyAnnotated) buffer.beginAsn1NestedStructure(
            enumDescriptor,
            null
        ).buffer += implicitTag.tagImplicitly { Asn1.Enumerated(index) }
        else buffer += implicitTag.tagImplicitly { enumDescriptor.implicitTag.tagImplicitly { Asn1.Enumerated(index) }() }
    }

    override fun <T> encodeSerializableValue(serializer: SerializationStrategy<T>, value: T) {
        if (serializer.descriptor == ByteArraySerializer().descriptor) {
            if (serializer.descriptor.isAsn1BitSet) encodeValue(BitSet.from(value as ByteArray))
            else encodeValue(value as ByteArray)
        } else if (value is Asn1Encodable<*> || value is Asn1Element) encodeValue(value)
        else super.encodeSerializableValue(serializer, value)
    }

    override fun beginStructure(descriptor: SerialDescriptor): Asn1Serializer {

        val buffer = descriptorAndIndex?.let {
            if (it.isStructurallyAnnotated) {
                buffer.beginAsn1NestedStructure(it.first, it.second).buffer
            } else buffer
        } ?: buffer
        val implicitTag = descriptorAndIndex?.first?.implicitTag(descriptorAndIndex!!.second)
        descriptorAndIndex = null


        if (descriptor.explicitTag != null) {
            //explicit tag is always toplevel
            if (descriptor.implicitTag != null) {
                throw SerializationException("Explicitly and implicitly tagged at the same level makes no sense! Perhaps you want to implicitly tag a set or sequence?!")
            }
        }

        return Asn1Serializer(serializersModule).also {
            fun addChildren(): Asn1Element = (
                    if (descriptor.isAsn1Set) Asn1Set(it.buffer.map { it() })
                    else if (descriptor.isAsn1OctetString) Asn1OctetString(it.buffer.map { it() })
                    else Asn1Sequence(it.buffer.map { it() })
                    ).let {
                    if (descriptor.implicitTag != null) it.withImplicitTag(descriptor.implicitTag!!) else it
                }.let { implicitTag?.let { implicitTag -> it.withImplicitTag(implicitTag) } ?: it }

            buffer += {
                if (descriptor.explicitTag != null) Asn1ExplicitlyTagged(
                    descriptor.explicitTag!!,
                    listOf(addChildren())
                ) else addChildren()
            }
        }
    }

    private fun MutableList<() -> Asn1Element>.beginAsn1NestedStructure(
        descriptor: SerialDescriptor,
        index: Int?
    ): Asn1Serializer {
        val explicitTag = index?.let { descriptor.explicitTag(it) } ?: descriptor.explicitTag
        val implicitTag = index?.let { descriptor.implicitTag(it) } ?: descriptor.implicitTag
        if (explicitTag != null) {
            //explicit tag is always toplevel
            if (implicitTag != null) {
                throw SerializationException("Explicitly and implicitly tagged at the same level makes no sense! Perhaps you want to implicitly tag a set or sequence?!")
            }
        }

        return Asn1Serializer(serializersModule).also {
            fun addChildren(): Asn1Element {
                val isOctetString = index?.let { descriptor.isAsn1OctetString(it) } ?: descriptor.isAsn1OctetString
                return (
                        if (isOctetString) Asn1OctetString(it.buffer.map { it() })
                        else if (explicitTag != null) Asn1ExplicitlyTagged(explicitTag, it.buffer.map { it() })
                        else throw ImplementationError("ASN.1 serialization: Impossible state reached: ${descriptor.serialName}[$index] is neither explicitly tagged or octet string!")
                        ).let { implicitTag?.let { implicitTag -> it.withImplicitTag(implicitTag) } ?: it }
            }

            this += { addChildren() }
        }
    }

    internal fun writeTo(destination: Sink) {
        buffer.forEach { it().encodeTo(destination) }
    }
}

@ExperimentalSerializationApi
fun <T> encodeToAsn1Bytes(serializer: SerializationStrategy<T>, value: T): ByteArray {
    val encoder = Asn1Serializer()
    encoder.encodeSerializableValue(serializer, value)
    return Buffer().also { encoder.writeTo(it) }.readByteArray()
}

@ExperimentalSerializationApi
inline fun <reified T> encodeToDer(value: T) = encodeToAsn1Bytes(serializer(), value)

private fun ULong?.tagImplicitly(encode: () -> Asn1Element): () -> Asn1Element {
    return if (this == null) encode else
        return { encode().withImplicitTag(this) }
}