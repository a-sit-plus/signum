package at.asitplus.signum.indispensable.asn1

import at.asitplus.signum.indispensable.asn1.encoding.decode
import at.asitplus.signum.indispensable.asn1.encoding.decodeAsn1VarBigInt
import at.asitplus.signum.indispensable.asn1.encoding.toAsn1VarInt
import at.asitplus.signum.indispensable.asn1.encoding.toBigInteger
import com.ionspin.kotlin.bignum.integer.BigInteger
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

private val BIGINT_40 = BigInteger.fromUByte(40u)

/**
 * ASN.1 OBJECT IDENTIFIER featuring the most cursed encoding of numbers known to man, which probably surfaced due to an ungodly combination
 * of madness, cruelty and a twisted sense of humour. Courtesy of what were most probably tormented souls to begin with.
 *
 * @param nodes OID Tree nodes passed in order (e.g. 1u, 2u, 96u, …)
 * @throws Asn1Exception if less than two nodes are supplied, the first node is >2 or the second node is >39
 */
@Serializable(with = ObjectIdSerializer::class)
class ObjectIdentifier @Throws(Asn1Exception::class) private constructor(
    val bytes: ByteArray,
    @Transient private val _nodes: List<BigInteger>? = null, dontVerify: Boolean = false
) :
    Asn1Encodable<Asn1Primitive> {

    init {
        if (_nodes == null || !dontVerify) {
            //Verify that everything can be parsed into nodes
            if (bytes.isEmpty()) throw Asn1Exception("Empty OIDs are not supported")
            var index = 1
            while (index < bytes.size) {
                if (bytes[index] >= 0) {
                    index++
                } else {
                    val currentNode = mutableListOf<Byte>()
                    while (bytes[index] < 0) {
                        currentNode += bytes[index] //+= parsed
                        index++
                    }
                    currentNode += bytes[index]
                    index++
                    val consumed = currentNode.iterator().consumeVarIntEncoded()
                    @OptIn(ExperimentalStdlibApi::class)
                    if (consumed != currentNode) throw Asn1Exception(
                        "Trailing bytes in OID Node ${
                            currentNode.toByteArray().toHexString(HexFormat.UpperCase)
                        }"
                    )
                }
            }
        }
    }

    /**
     * Creates an OID in the 2.25 subtree that requires no formal registration.
     * E.g. the UUID `550e8400-e29b-41d4-a716-446655440000` results in the OID
     * `2.25.113059749145936325402354257176981405696`
     */
    @OptIn(ExperimentalUuidApi::class)
    constructor(uuid: Uuid) : this(
        byteArrayOf((2 * 40 + 25).toUByte().toByte(), *uuid.toBigInteger().toAsn1VarInt())
    )

    /**
     * @param nodes OID Tree nodes passed in order (e.g. 1u, 2u, 96u, …)
     * @throws Asn1Exception if less than two nodes are supplied, the first node is >2 or the second node is >39
     */
    constructor(vararg nodes: UInt) : this(
        nodes.toOidBytes(),
        dontVerify = true
    )

    /**
     * @param nodes OID Tree nodes passed in order (e.g. 1, 2, 96, …)
     * @throws Asn1Exception if less than two nodes are supplied, the first node is >2, the second node is >39 or any node is negative
     */
    constructor(vararg nodes: BigInteger) : this(nodes.toOidBytes(), _nodes = nodes.asList())

    /**
     * @param oid in human-readable format (e.g. "1.2.96")
     */
    constructor(oid: String) : this(*(oid.split(if (oid.contains('.')) '.' else ' ')).map { BigInteger.parseString(it) }
        .toTypedArray())

    /**
     * Lazily evaluated list of OID nodes (e.g. `[1, 2, 35, 4654]`)
     */
    val nodes: List<BigInteger> by lazy {
        if (_nodes != null) _nodes else {
            val (first, second) =
                if (bytes[0] >= 80) {
                    BigInteger.fromUByte(2u) to BigInteger.fromUInt(bytes[0].toUByte() - 80u)
                } else {
                    BigInteger.fromUInt(bytes[0].toUByte() / 40u) to BigInteger.fromUInt(bytes[0].toUByte() % 40u)
                }
            var index = 1
            val collected = mutableListOf(first, second)
            while (index < bytes.size) {
                if (bytes[index] >= 0) {
                    collected += BigInteger.fromUInt(bytes[index].toUInt())
                    index++
                } else {
                    val currentNode = mutableListOf<Byte>()
                    while (bytes[index] < 0) {
                        currentNode += bytes[index] //+= parsed
                        index++
                    }
                    currentNode += bytes[index]
                    index++
                    collected += currentNode.decodeAsn1VarBigInt().first
                }
            }
            collected
        }
    }

    /**
     * @return human-readable format (e.g. "1.2.96")
     */
    override fun toString(): String {
        return nodes.joinToString(".")
    }

    override fun equals(other: Any?): Boolean {
        if (other == null) return false
        if (other !is ObjectIdentifier) return false
        return bytes contentEquals other.bytes
    }

    override fun hashCode(): Int {
        return bytes.contentHashCode()
    }

    /**
     * @return an OBJECT IDENTIFIER [Asn1Primitive]
     */
    override fun encodeToTlv() = Asn1Primitive(Asn1Element.Tag.OID, bytes)

    companion object : Asn1Decodable<Asn1Primitive, ObjectIdentifier> {

        /**
         * Parses an OBJECT IDENTIFIER contained in [src] to an [ObjectIdentifier]
         * @throws Asn1Exception  all sorts of errors on invalid input
         */
        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Primitive): ObjectIdentifier {
            if (src.length < 1) throw Asn1StructuralException("Empty OIDs are not supported")

            return parse(src.content)

        }

        /**
         * Casts out the evil demons that haunt OID components encoded into [rawValue]
         * @return ObjectIdentifier if decoding succeeded
         * @throws Asn1Exception all sorts of errors on invalid input
         */
        @Throws(Asn1Exception::class)
        fun parse(rawValue: ByteArray): ObjectIdentifier = ObjectIdentifier(rawValue)

        private fun Iterator<Byte>.consumeVarIntEncoded(): MutableList<Byte> {
            val accumulator = mutableListOf<Byte>()
            while (hasNext()) {
                val curByte = next()
                val current = BigInteger(curByte.toUByte().toInt())
                accumulator += curByte
                if (current < 0x80.toUByte()) break
            }
            return accumulator
        }

        private fun UIntArray.toOidBytes(): ByteArray {
            if (size < 2) throw Asn1StructuralException("at least two nodes required!")
            if (first() > 2u) throw Asn1Exception("OID must start with either 1 or 2")
            if (get(1) > 39u) throw Asn1Exception("Second segment must be <40")
            return slice(2..<size).map { it.toAsn1VarInt() }.fold(
                byteArrayOf((first() * 40u + get(1)).toUByte().toByte())
            ) { acc, bytes -> acc + bytes }
        }

        private fun Array<out BigInteger>.toOidBytes(): ByteArray {
            if (size < 2) throw Asn1StructuralException("at least two nodes required!")
            if (first() > 2u) throw Asn1Exception("OID must start with either 1 or 2")
            if (get(1) > 39u) throw Asn1Exception("Second segment must be <40")

            return slice(2..<size).map { if (it.isNegative) throw Asn1Exception("Negative Number encountered: $it") else it.toAsn1VarInt() }
                .fold(
                    byteArrayOf((first().intValue() * 40 + get(1).intValue()).toUByte().toByte())
                ) { acc, bytes -> acc + bytes }
        }
    }
}

object ObjectIdSerializer : KSerializer<ObjectIdentifier> {
    override val descriptor = PrimitiveSerialDescriptor("OID", PrimitiveKind.STRING)

    override fun deserialize(decoder: Decoder): ObjectIdentifier = ObjectIdentifier(decoder.decodeString())

    override fun serialize(encoder: Encoder, value: ObjectIdentifier) {
        encoder.encodeString(toString())
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
    decode(Asn1Element.Tag.OID) { ObjectIdentifier.parse(it) }
}