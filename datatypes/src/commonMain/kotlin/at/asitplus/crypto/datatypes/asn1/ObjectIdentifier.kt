package at.asitplus.crypto.datatypes.asn1

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

@Serializable(with = ObjectIdSerializer::class)
class ObjectIdentifier(@Transient vararg val nodes: UInt) {

    init {
        if (nodes.size < 2) throw IllegalArgumentException("at least two nodes required!")
        if (nodes[0] * 40u > UByte.MAX_VALUE.toUInt()) throw IllegalArgumentException("first node too lage!")
        //TODO more sanity checks

        if (nodes.first() > 2u) throw IllegalArgumentException("OID must start with either 1 or 2")
        if (nodes[1] > 39u) throw IllegalArgumentException("Second segment must be <40")
    }

    constructor(oid: String) : this(*(oid.split(if (oid.contains('.')) '.' else ' ')).map { it.toUInt() }.toUIntArray())

    override fun toString() = nodes.joinToString(separator = ".") { it.toString() }

    override fun equals(other: Any?): Boolean {
        if (other == null) return false
        if (other !is ObjectIdentifier) return false
        return nodes contentEquals other.nodes
    }

    //based on the very concise explanation found on SO: https://stackoverflow.com/a/25786793
    private fun UInt.encodeOidNode(): ByteArray {
        //TODO maybe move to BitSet to avoid const of stringification?
        if (this < 128u) return byteArrayOf(this.toByte())
        val septets = toString(2).reversed().chunked(7).map { it.reversed().toUByte(2) }.reversed()

        return septets.mapIndexed { i, b -> (if (i < septets.size - 1) b or 0x80u else b).toByte() }
            .toByteArray()

    }

    val bytes: ByteArray by lazy {
        nodes.slice(2..<nodes.size).map { it.encodeOidNode() }.fold(
            byteArrayOf(
                (nodes[0] * 40u + nodes[1]).toUByte().toByte()
            )
        ) { acc, bytes -> acc + bytes }
    }

    fun encodeToTlv() = Asn1Primitive(BERTags.OBJECT_IDENTIFIER, bytes)

    companion object {
        fun decodeFromTlv(oid: Asn1Primitive): ObjectIdentifier {
            if (oid.tag != BERTags.OBJECT_IDENTIFIER) throw IllegalArgumentException("Not an OID (tag: ${oid.tag}")
            if (oid.length < 1) throw IllegalArgumentException("Empty OIDs are not supported")

            return parse(oid.content)

        }

        fun parse(rawValue: ByteArray): ObjectIdentifier {
            if (rawValue.isEmpty()) throw IllegalArgumentException("Empty OIDs are not supported")
            val (first, second) =
                if (rawValue[0] >= 80) {
                    2u to rawValue[0].toUByte() - 80u
                } else {
                    rawValue[0].toUByte() / 40u to rawValue[0].toUByte() % 40u
                }

            var rest = rawValue.drop(1).map { it.toUByte() }
            val collected = mutableListOf(first, second)
            while (rest.isNotEmpty()) {
                if (rest[0].toUByte() < 128u) {
                    collected += rest[0].toUInt()
                    rest = rest.drop(1)
                } else {
                    var currentNode = mutableListOf<String>()
                    while (rest[0].toUByte() > 127u) {
                        val full = String(rest[0].toString(2).toCharArray())
                        val uInt = String(full.drop(1).toCharArray()).padStart(7, '0')
                        currentNode += uInt
                        rest = rest.drop(1)
                    }
                    currentNode += String(rest[0].toString(2).toCharArray()).padStart(7, '0')
                    rest = rest.drop(1)
                    collected += currentNode.fold("") { acc, s -> acc + s }.toUInt(2)
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