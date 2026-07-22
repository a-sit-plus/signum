package at.asitplus.signum.indispensable

import at.asitplus.awesn1.*
import at.asitplus.awesn1.encoding.parse
import at.asitplus.awesn1.io.encodeToDer
import at.asitplus.awesn1.io.parse
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.Der
import at.asitplus.awesn1.serialization.encodeToTlv
import kotlinx.io.Sink
import kotlinx.io.Source
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.serializer
import kotlin.reflect.typeOf


/**
 * Interface providing methods to encode to ASN.1/DER using awesn1
 */
interface DerEncodable<Serializable> {

    val asn1Representation: Serializable

    /**
     * Encodes the implementing object into an [Asn1Element] through [der] serialization
     * @throws SerializationException in case an illegal ASN.1 Object was to be constructed
     */
    @Throws(SerializationException::class)
    fun encodeToTlv(serializer: KSerializer<Serializable>, der: Der = DER): Asn1Element =
        der.encodeToTlv(serializer, asn1Representation) as Asn1Element //won't ever be null
}

interface DerPemEncodable<Serializable> : DerEncodable<Serializable>, WithPemLabel

interface DerPemDecodable<Serializable, out T : DerEncodable<Serializable>> :
    DerDecodable<Serializable, T>, PemLabelSpec<T> {

    @Throws(Asn1Exception::class)
    fun decodeFromPemBlockPayload(
        serializer: KSerializer<Serializable>,
        src: PemBlock,
        limit: Long = src.payload.size.toLong(),
        der: Der = DER,
    ): T = decodeFromDer(serializer, src.payload, limit, der)
}

fun <Serializable> DerPemEncodable<Serializable>.encodeToPemBlock(
    serializer: KSerializer<Serializable>,
    der: Der = DER,
): PemBlock = PemBlock(pemLabel, payload = encodeToDer(serializer, der))

inline fun <reified Serializable> DerPemEncodable<Serializable>.encodeToPemBlock(
    der: Der = DER,
): PemBlock = encodeToPemBlock(
    der.configuration.serializersModule.serializer(typeOf<Serializable>()) as KSerializer<Serializable>,
    der,
)

fun <Serializable> DerPemEncodable<Serializable>.encodeToPem(
    serializer: KSerializer<Serializable>,
    der: Der = DER,
): String = encodeToPemBlock(serializer, der).encodeToPem()

inline fun <reified Serializable> DerPemEncodable<Serializable>.encodeToPem(
    der: Der = DER,
): String = encodeToPemBlock<Serializable>(der).encodeToPem()

fun <Serializable, T : DerEncodable<Serializable>> DerPemDecodable<Serializable, T>.decodeFromPemBlock(
    serializer: KSerializer<Serializable>,
    src: PemBlock,
    limit: Long = src.payload.size.toLong(),
    der: Der = DER,
): T {
    validate(src)
    require(!src.headers.any()) { "Unexpected PEM headers are present in the data" }
    return decodeFromPemBlockPayload(serializer, src, limit, der)
}

inline fun <reified Serializable, T : DerEncodable<Serializable>> DerPemDecodable<Serializable, T>.decodeFromPemBlock(
    src: PemBlock,
    limit: Long = src.payload.size.toLong(),
    der: Der = DER,
): T = decodeFromPemBlock(
    der.configuration.serializersModule.serializer(typeOf<Serializable>()) as KSerializer<Serializable>,
    src,
    limit,
    der,
)

fun <Serializable, T : DerEncodable<Serializable>> DerPemDecodable<Serializable, T>.decodeFromPem(
    serializer: KSerializer<Serializable>,
    src: String,
    limit: Long? = null,
    der: Der = DER,
): T = PemBlock.decodeFromPem(src).let { pemBlock ->
    decodeFromPemBlock(serializer, pemBlock, limit ?: pemBlock.payload.size.toLong(), der)
}

inline fun <reified Serializable, T : DerEncodable<Serializable>> DerPemDecodable<Serializable, T>.decodeFromPem(
    src: String,
    limit: Long? = null,
    der: Der = DER,
): T = PemBlock.decodeFromPem(src).let { pemBlock ->
    decodeFromPemBlock<Serializable, T>(pemBlock, limit ?: pemBlock.payload.size.toLong(), der)

}

/**
 * Encodes the implementing object into an [Asn1Element] through [der] serialization
 * @throws SerializationException in case an illegal ASN.1 Object was to be constructed
 */
@Throws(SerializationException::class)
inline fun <reified Serializable> DerEncodable<Serializable>.encodeToTlv(der: Der = DER): Asn1Element =
    der.encodeToTlv(asn1Representation) as Asn1Element //won't ever be null

/**
 * Encodes the implementing object into an DER-encoded bytes through [der] serialization
 * @throws SerializationException in case an illegal ASN.1 Object was to be constructed
 */
fun <Serializable> DerEncodable<Serializable>.encodeToDer(
    serializer: KSerializer<Serializable>,
    der: Der = DER
): ByteArray = encodeToTlv(serializer, der).derEncoded

/**
 * Encodes the implementing object into an DER-encoded bytes through [der] serialization
 * @throws SerializationException in case an illegal ASN.1 Object was to be constructed
 */
inline fun <reified Serializable> DerEncodable<Serializable>.encodeToDer(der: Der = DER): ByteArray =
    encodeToTlv(der).derEncoded

/**
 * DER-Encodes the implementing object into the specified [sink] through [der] serialization
 * @throws SerializationException in case an illegal ASN.1 Object was to be constructed
 */
inline fun <Serializable> DerEncodable<Serializable>.encodeToDer(
    serializer: KSerializer<Serializable>,
    sink: Sink,
    der: Der = DER
): Unit = encodeToTlv(serializer, der).encodeToDer(sink)

/**
 * DER-Encodes the implementing object into the specified [sink] through [der] serialization
 * @throws SerializationException in case an illegal ASN.1 Object was to be constructed
 */
inline fun <reified Serializable> DerEncodable<Serializable>.encodeToDer(sink: Sink, der: Der = DER): Unit =
    encodeToTlv(der).encodeToDer(sink)


/**
 * Interface providing convenience methods to decode from ASN.1.
 * Especially useful when companion objects of classes implementing [DerEncodable] implement it.
 */
interface DerDecodable<Serializable, out T : DerEncodable<Serializable>> {
    /**
     * Processes a [Serializable], parsing it into an instance of [T].
     * If recursive deserialization is done, it should use the [der] instance.
     */
    fun decodeFromTlv(element: Serializable, der: Der = DER): T
    /**
     * Processes an [Asn1Element], parsing it into an instance of [T] through [der] serialization
     * @throws SerializationException if invalid data is provided.
     */
    @Throws(Asn1Exception::class)
    fun decodeFromTlv(serializer: KSerializer<Serializable>, src: Asn1Element, der: Der = DER): T =
        decodeFromTlv(der.decodeFromTlv(serializer, src))
}

/**
 * Processes an [Asn1Element], parsing it into an instance of [T] through [der] serialization
 * @throws SerializationException if invalid data is provided.
 */
inline fun <reified Serializable, T : DerEncodable<Serializable>> DerDecodable<Serializable, T>.decodeFromTlv(
    src: Asn1Element,
    der: Der = DER
): T = decodeFromTlv(
    der.configuration.serializersModule.serializer<Serializable>(),
    src,
    der
)


fun <Serializable, T : DerEncodable<Serializable>> DerDecodable<Serializable, T>.decodeFromDer(
    serializer: KSerializer<Serializable>,
    bytes: ByteArray,
    limit: Long = bytes.size.toLong(),
    der: Der = DER
): T = decodeFromTlv(serializer, Asn1Element.parse(bytes, limit), der)

inline fun <reified Serializable, T : DerEncodable<Serializable>> DerDecodable<Serializable, T>.decodeFromDer(
    bytes: ByteArray,
    der: Der = DER
): T = decodeFromTlv(
    der.configuration.serializersModule.serializer<Serializable>(),
    Asn1Element.parse(bytes),
    der
)

fun <Serializable, T : DerEncodable<Serializable>> DerDecodable<Serializable, T>.decodeFromDer(
    serializer: KSerializer<Serializable>,
    source: Source,
    limit: Long = Long.MAX_VALUE,
    der: Der = DER
): T = decodeFromTlv(serializer, Asn1Element.parse(source, limit), der)

inline fun <reified Serializable, T : DerEncodable<Serializable>> DerDecodable<Serializable, T>.decodeFromDer(
    source: Source,
    limit: Long = Long.MAX_VALUE,
    der: Der = DER
): T = decodeFromTlv(
    der.configuration.serializersModule.serializer<Serializable>(),
    Asn1Element.parse(source, limit),
    der
)
