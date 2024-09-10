package at.asitplus.signum.indispensable.asn1

import at.asitplus.catching
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlin.experimental.and
import kotlin.experimental.or
import kotlin.math.ceil

/**
 * ASN.1 OBJECT IDENTIFIER featuring the most cursed encoding of numbers known to man, which probably surfaced due to an ungodly combination
 * of madness, cruelty and a twisted sense of humour. Courtesy of what were most probably tormented souls to begin with.
 *
 * @param nodes OID Tree nodes passed in order (e.g. 1u, 2u, 96u, …)
 * @throws Asn1Exception if less than two nodes are supplied, the first node is >2 or the second node is >39
 */
@Serializable(with = ObjectIdSerializer::class)
class ObjectIdentifier @Throws(Asn1Exception::class) constructor(@Transient vararg val nodes: UInt) :
    Asn1Encodable<Asn1Primitive> {

    init {
        if (nodes.size < 2) throw Asn1StructuralException("at least two nodes required!")
        if (nodes[0] * 40u > UByte.MAX_VALUE.toUInt()) throw Asn1Exception("first node too lage!")
        //TODO more sanity checks

        if (nodes.first() > 2u) throw Asn1Exception("OID must start with either 1 or 2")
        if (nodes[1] > 39u) throw Asn1Exception("Second segment must be <40")
    }

    /**
     * @param oid in human-readable format (e.g. "1.2.96")
     */
    constructor(oid: String) : this(*(oid.split(if (oid.contains('.')) '.' else ' ')).map { it.toUInt() }.toUIntArray())

    /**
     * @return human-readable format (e.g. "1.2.96")
     */
    override fun toString() = nodes.joinToString(separator = ".") { it.toString() }

    override fun equals(other: Any?): Boolean {
        if (other == null) return false
        if (other !is ObjectIdentifier) return false
        return nodes contentEquals other.nodes
    }

    override fun hashCode(): Int {
        return nodes.hashCode()
    }

    //based on the very concise explanation found on SO: https://stackoverflow.com/a/25786793
    private fun UInt.encodeOidNode(): ByteArray {
        if (this < 128u) return byteArrayOf(this.toByte())
        val septets = toCompactByteArray().toSeptets()
        for (i in 1..<septets.size) {
            septets[i] = septets[i].setBit(7)
        }
        return septets.reversedArray()
    }

    /**
     * Cursed encoding of OID nodes. A sacrifice of pristine numbers requested by past gods of the netherrealm
     */
    val bytes: ByteArray by lazy {
        nodes.slice(2..<nodes.size).map { it.encodeOidNode() }.fold(
            byteArrayOf(
                (nodes[0] * 40u + nodes[1]).toUByte().toByte()
            )
        ) { acc, bytes -> acc + bytes }
    }

    /**
     * @return an OBJECT IDENTIFIER [Asn1Primitive]
     */
    override fun encodeToTlv() = Asn1Primitive(BERTags.OBJECT_IDENTIFIER.toULong(), bytes)

    companion object : Asn1Decodable<Asn1Primitive, ObjectIdentifier> {

        /**
         * Parses an OBJECT IDENTIFIER contained in [src] to an [ObjectIdentifier]
         * @throws Asn1Exception  all sorts of errors on invalid input
         */
        @Throws(Asn1Exception::class)
        override fun decodeFromTlv(src: Asn1Primitive): ObjectIdentifier {
            if (src.tag.tagValue != BERTags.OBJECT_IDENTIFIER.toULong()) throw Asn1TagMismatchException(
                TLV.Tag(
                    BERTags.OBJECT_IDENTIFIER.toULong(),
                    constructed = false
                ), src.tag
            )
            if (src.length < 1) throw Asn1StructuralException("Empty OIDs are not supported")

            return parse(src.content)

        }

        /**
         * Casts out the evil demons that haunt OID components encoded into [rawValue]
         * @return ObjectIdentifier if decoding succeeded
         * @throws Asn1Exception all sorts of errors on invalid input
         */
        @Throws(Asn1Exception::class)
        fun parse(rawValue: ByteArray): ObjectIdentifier = runRethrowing {
            if (rawValue.isEmpty()) throw Asn1Exception("Empty OIDs are not supported")
            val (first, second) =
                if (rawValue[0] >= 80) {
                    2u to rawValue[0].toUByte() - 80u
                } else {
                    rawValue[0].toUByte() / 40u to rawValue[0].toUByte() % 40u
                }

            var index = 1
            val collected = mutableListOf(first, second)
            while (index < rawValue.size) {
                if (rawValue[index] >= 0) {
                    collected += rawValue[index].toUInt()
                    index++
                } else {
                    val currentNode = mutableListOf<Byte>()
                    while (rawValue[index] < 0) {
                        currentNode += rawValue[index] //+= parsed
                        index++
                    }
                    currentNode += rawValue[index]
                    index++
                    collected += currentNode.septetsToUInt()
                }
            }
            return ObjectIdentifier(*collected.toUIntArray())
        }
    }

}

object ObjectIdSerializer : KSerializer<ObjectIdentifier> {
    override val descriptor = PrimitiveSerialDescriptor("OID", PrimitiveKind.STRING)

    override fun deserialize(decoder: Decoder): ObjectIdentifier = ObjectIdentifier(decoder.decodeString())

    override fun serialize(encoder: Encoder, value: ObjectIdentifier) {
        encoder.encodeString(value.nodes.joinToString(separator = ".") { it.toString() })
    }

}


/**
 * Adds [oid] to the implementing class
 */
interface Identifiable {
    val oid: ObjectIdentifier
}

/**
 * decodes this [Asn1Primitive]'s content into an [ObjectIdentifier]
 *
 * @throws Asn1Exception on invalid input
 */
@Throws(Asn1Exception::class)
fun Asn1Primitive.readOid() = runRethrowing {
    decode(BERTags.OBJECT_IDENTIFIER.toULong()) { ObjectIdentifier.parse(it) }
}


private fun ByteArray.toSeptets(): ByteArray {
    var pos = 0
    val chunks = mutableListOf<Byte>()
    while (pos < this.size * 8) {
        var chunk = 0.toByte()

        var fresh = true
        while (fresh || (pos % 7 != 0)) {
            fresh = false
            if (this.getBit(pos)) chunk = chunk.setBit(pos % 7)
            pos++
        }
        if ((pos >= this.size * 8)) {
            if (chunk != 0.toByte()) chunks += chunk
        } else chunks += chunk
    }
    return chunks.toByteArray()
}

@Suppress("NOTHING_TO_INLINE")
private inline fun ByteArray.getBit(index: Int): Boolean =
    if (index < 0) throw IndexOutOfBoundsException("index = $index")
    else catching {
        this[getByteIndex(index)].getBit(getBitIndex(index))
    }.getOrElse { false }

@Suppress("NOTHING_TO_INLINE")
private inline fun ByteArray.setBit(i: Int) {
    this[getByteIndex(i)] = this[getByteIndex(i)].setBit(getBitIndex(i))
}

@Suppress("NOTHING_TO_INLINE")
private inline fun Byte.setBit(i: Int) = ((1 shl getBitIndex(i)).toByte() or this)

@Suppress("NOTHING_TO_INLINE")
private inline fun getByteIndex(i: Int) = (i / 8)

@Suppress("NOTHING_TO_INLINE")
private inline fun getBitIndex(i: Int) = (i % 8)

@Suppress("NOTHING_TO_INLINE")
private inline fun Byte.getBit(index: Int): Boolean = (((1 shl index).toByte() and this) != 0.toByte())

private fun UInt.toCompactByteArray(): ByteArray =
    if (this < 256u) byteArrayOf(this.toUByte().toByte())
    else if (this < 65535u) byteArrayOf((this).toByte(), (this shr 8).toByte())
    else if (this < 16777216u) byteArrayOf((this).toByte(), (this shr 8).toByte(), (this shr 16).toByte())
    else byteArrayOf((this).toByte(), (this shr 8).toByte(), (this shr 16).toByte(), (this shr 24).toByte())

private fun UInt.Companion.decodeFrom(input: ByteArray): UInt {
    var result = 0u
    for (i in input.indices.reversed()) {
        result = (result shl Byte.SIZE_BITS) or (input[i].toUByte().toUInt())
    }
    return result
}

private fun MutableList<Byte>.septetsToUInt(): UInt {
    val result = ByteArray(ceil(size.toFloat() * 7f / 8f).toInt())
    var globalIndex = 0
    for (index in indices.reversed()) {
        for (i in 0..<7) {
            if (this[index].getBit(i)) result.setBit(globalIndex)
            globalIndex++
        }
    }
    return UInt.decodeFrom(result)
}