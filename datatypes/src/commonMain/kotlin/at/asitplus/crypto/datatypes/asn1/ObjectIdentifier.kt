package at.asitplus.crypto.datatypes.asn1

class ObjectIdentifier(vararg val nodes: Int) {

    init {
        if (nodes.size < 2) throw IllegalArgumentException("at least tow nodes required!")
        if (nodes[0] * 40 > UByte.MAX_VALUE.toInt()) throw IllegalArgumentException("first node too lage!")
        //TODO more sanity checks
    }

    constructor(oid: String) : this(*oid.split('.').map<String, Int> { it.toInt() }.toIntArray())

    val bytes: ByteArray = nodes.slice(2..<nodes.size).map { it.encodeLength() }.fold(
        byteArrayOf(
            (nodes[0] * 40 + nodes[1]).toUByte().toByte()
        )
    ) { acc, bytes -> acc + bytes }

    fun encodeToTlv() = Asn1Primitive(BERTags.OBJECT_IDENTIFIER, bytes)

}