package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.internals.ImplementationError
import kotlinx.io.Buffer
import kotlinx.io.readByteArray
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerializationStrategy
import kotlinx.serialization.serializer


class Der {
    companion object {

    }
}

//all fo the below must be extensions that statically resolve to allow for shadowing

@ExperimentalSerializationApi
inline fun <reified T> Der.encodeToDer(value: T) = encodeToDer(serializer(), value)

@ExperimentalSerializationApi
inline fun <reified T> Der.encodeToTlv(value: T) = encodeToTlv(serializer(), value)


@ExperimentalSerializationApi
@Suppress("INVISIBLE_MEMBER", "INVISIBLE_REFERENCE")
@kotlin.internal.LowPriorityInOverloadResolution
inline fun <reified T> Der.decodeFromDer(source: ByteArray): T = decodeFromDer(source, serializer())

@ExperimentalSerializationApi
@Suppress("INVISIBLE_MEMBER", "INVISIBLE_REFERENCE")
@kotlin.internal.LowPriorityInOverloadResolution
inline fun <reified T> Der.decodeFromTlv(source: Asn1Element): T = decodeFromTlv(source, serializer())

@ExperimentalSerializationApi
fun <T> Der.encodeToDer(serializer: SerializationStrategy<T>, value: T): ByteArray {
    val encoder = DerEncoder()
    encoder.encodeSerializableValue(serializer, value)
    return Buffer().also { encoder.writeTo(it) }.readByteArray()
}

@ExperimentalSerializationApi
fun <T> Der.encodeToTlv(serializer: SerializationStrategy<T>, value: T): Asn1Element {
    val encoder = DerEncoder()
    encoder.encodeSerializableValue(serializer, value)
    return encoder.encodeToTLV()
        .also { if (it.size != 1) throw ImplementationError("DER serializer mutliple elements") }.first()
}


@ExperimentalSerializationApi
fun <T> Der.decodeFromDer(source: ByteArray, deserializer: DeserializationStrategy<T>): T {
    val decoder = DerDecoder(Buffer().also { it.write(source) })
    return decoder.decodeSerializableValue(deserializer)
}

@ExperimentalSerializationApi
fun <T> Der.decodeFromTlv(source: Asn1Element, deserializer: DeserializationStrategy<T>): T {
    val decoder = DerDecoder(listOf(source))
    return decoder.decodeSerializableValue(deserializer)
}
