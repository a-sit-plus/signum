package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.encoding.parse
import kotlinx.serialization.BinaryFormat
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.SerializationStrategy
import kotlinx.serialization.modules.EmptySerializersModule
import kotlinx.serialization.modules.SerializersModule

class Asn1Serializer(override val serializersModule: SerializersModule) : BinaryFormat {

    override fun <T> decodeFromByteArray(deserializer: DeserializationStrategy<T>, bytes: ByteArray): T {
        val reader = Asn1Decoder(listOf(Asn1Element.parse(bytes)), serializersModule)
        return reader.decodeSerializableValue(deserializer)
    }

    override fun <T> encodeToByteArray(serializer: SerializationStrategy<T>, value: T): ByteArray {
        val elements = mutableListOf<Asn1Element>()
        val encoder = Asn1Encoder(elements,serializersModule)
        encoder.encodeSerializableValue(serializer, value)
        return encoder.elements.first().derEncoded

    }
}

fun Asn1.Serializer(serializersModule: SerializersModule= EmptySerializersModule()) = Asn1Serializer(serializersModule)