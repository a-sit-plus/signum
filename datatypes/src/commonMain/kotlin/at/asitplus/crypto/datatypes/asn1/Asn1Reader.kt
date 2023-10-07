package at.asitplus.crypto.datatypes.asn1

import at.asitplus.crypto.datatypes.Asn1String
import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.EcCurve
import at.asitplus.crypto.datatypes.asn1.BERTags.BIT_STRING
import at.asitplus.crypto.datatypes.asn1.BERTags.INTEGER
import at.asitplus.crypto.datatypes.asn1.BERTags.NULL
import at.asitplus.crypto.datatypes.asn1.BERTags.OBJECT_IDENTIFIER
import at.asitplus.crypto.datatypes.asn1.BERTags.PRINTABLE_STRING
import at.asitplus.crypto.datatypes.asn1.BERTags.UTC_TIME
import at.asitplus.crypto.datatypes.asn1.BERTags.UTF8_STRING
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.datetime.Instant


class Asn1StructureReader(input: ByteArray) {

    private var rest = input

    @Throws(IllegalArgumentException::class)
    fun readAll(): List<ExtendedTlv> {
        val result = mutableListOf<ExtendedTlv>()
        while (rest.isNotEmpty()) {
            val tlv = read()
            if (tlv.isContainer() && tlv.content.isNotEmpty()) {
                result.add(ExtendedTlv(tlv, Asn1StructureReader(tlv.content).readAll()))
            } else {
                result.add(ExtendedTlv(tlv, listOf()))
            }
        }
        return result.toList()
    }

    private fun TLV.isContainer() = tag == 0x30.toByte() || tag == 0x31.toByte() || tag == 0xA0.toByte()

    @Throws(IllegalArgumentException::class)
    private fun read(): TLV {
        val tlv = rest.readTlv()
        if (tlv.overallLength > rest.size)
            throw IllegalArgumentException("Out of bytes")
        rest = rest.drop(tlv.overallLength).toByteArray()
        return tlv
    }
}



class Asn1Reader(input: ByteArray) {

    var rest: ByteArray private set

    init {
        rest = input
    }


    fun hasMore() = rest.isNotEmpty()
    fun <T> readSequence(func: (ByteArray) -> T?) = read(0x30, func)

    fun <T> readSet(func: (ByteArray) -> T?) = read(0x31, func)

    fun readOid() = read(OBJECT_IDENTIFIER) { bytes -> bytes.encodeToString(Base16) }

    fun readBitstring() = read(BIT_STRING, ::decodeBitString)

    fun readInt() = read(INTEGER, Int.Companion::decodeFromDer)

    fun readLong() = read(INTEGER, Long.Companion::decodeFromDer)

    fun readUtcTime() = read(UTC_TIME, Instant.Companion::decodeUtcTimeFromDer)

    fun readString(): Asn1String =
        if (rest[0] == UTF8_STRING.toByte()) Asn1String.UTF8(readUtf8String())
        else Asn1String.Printable(read(PRINTABLE_STRING) { bytes -> String(bytes) })


    fun readUtf8String() = read(UTF8_STRING) { bytes -> String(bytes) }

    fun readNull() = read(NULL) {}

    fun <T> read(tag: Int, func: (ByteArray) -> T?): T {
        val tlv = rest.readTlv()
        if (tlv.tag != tag.toByte())
            throw IllegalArgumentException("Expected tag $tag, got ${tlv.tag}")
        val obj =
            runCatching { func(tlv.content) }.getOrElse { throw IllegalArgumentException("Can't decode content", it) }
        if (tlv.overallLength > rest.size)
            throw IllegalArgumentException("Out of bytes")
        rest = rest.drop(tlv.overallLength).toByteArray()
        return obj ?: throw IllegalArgumentException("Can't decode content")
    }
}

fun decodeBitString(input: ByteArray) = input.drop(1).toByteArray()


@Throws(IllegalArgumentException::class)
fun CryptoPublicKey.Companion.decodeFromDer(src: Asn1Reader): CryptoPublicKey {
    val reader = src.readSequence { Asn1Reader(it) }
    val innerSequence = reader.readSequence { bytes -> bytes }
    val innerReader = Asn1Reader(innerSequence)
    val oid = innerReader.readOid()
    if (oid == "2A8648CE3D0201") {
        val curveOid = innerReader.readOid()
        val curve = when (curveOid) {
            "2A8648CE3D030107" -> EcCurve.SECP_256_R_1
            "2B81040022" -> EcCurve.SECP_384_R_1
            "2B81040023" -> EcCurve.SECP_521_R_1
            else -> throw IllegalArgumentException("Curve not supported: $curveOid")
        }
        val bitString = reader.readBitstring()
        val xAndY = bitString.drop(1).toByteArray()
        val coordLen = curve.coordinateLengthBytes.toInt()
        val x = xAndY.take(coordLen).toByteArray()
        val y = xAndY.drop(coordLen).take(coordLen).toByteArray()
        return CryptoPublicKey.Ec.fromCoordinates(curve, x, y)
    } else if (oid == "2A864886F70D010101") {
        innerReader.readNull()
        val rsaSequence = Asn1Reader(reader.readBitstring()).readSequence { Asn1Reader(it) }
        val n = rsaSequence.read(INTEGER) { it }
        val e = rsaSequence.readInt().toUInt()
        return CryptoPublicKey.Rsa(
            CryptoPublicKey.Rsa.Size.of(((n.size - 1) * 8).toUInt()) ?: throw IllegalArgumentException(
                "Illegal RSa key size: ${(n.size - 1) * 8}"
            ), n, e
        )

    } else {
        throw IllegalArgumentException("Non-EC Keys not supported")
    }
}

@Throws(IllegalArgumentException::class)
fun CryptoPublicKey.Companion.decodeFromDer(input: ByteArray): CryptoPublicKey = decodeFromDer(Asn1Reader(input))

@Throws(IllegalArgumentException::class)
fun Instant.Companion.decodeUtcTimeFromDer(input: ByteArray): Instant = runCatching {
    val s = String(input)
    val isoString =
        "20${s[0]}${s[1]}-${s[2]}${s[3]}-${s[4]}${s[5]}T${s[6]}${s[7]}:${s[8]}${s[9]}:${s[10]}${s[11]}${s[12]}"
    return Instant.parse(isoString)
}.getOrElse { throw IllegalArgumentException(it) }

fun Int.Companion.decodeFromDer(input: ByteArray): Int {
    var result = 0
    for (i in input.indices) {
        result = (result shl Byte.SIZE_BITS) or (input[i].toUByte().toInt())
    }
    return result
}

@Throws(IllegalArgumentException::class)
fun Long.Companion.decodeFromDer(input: ByteArray): Long = runCatching {
    var result = 0L
    for (i in input.indices) {
        result = (result shl Byte.SIZE_BITS) or (input[i].toUByte().toLong())
    }
    return result
}.getOrElse { throw IllegalArgumentException(it) }

fun ByteArray.readTlv(): TLV = runCatching {
    if (this.isEmpty()) throw IllegalArgumentException("Can't read TLV, input empty")
    val tag = this[0]
    if (this.size == 1) return TLV(tag, byteArrayOf())
    val firstLength = this[1]
    if (firstLength == 0x82.toByte()) {
        if (this.size < 4) throw IllegalArgumentException("Can't decode length")
        val length = (this[2].toUByte().toInt() shl 8) + this[3].toUByte().toInt()
        if (this.size < 4 + length) throw IllegalArgumentException("Out of bytes")
        val value = this.drop(4).take(length).toByteArray()
        return TLV(tag,value)
    }
    if (firstLength == 0x81.toByte()) {
        if (this.size < 3) throw IllegalArgumentException("Can't decode length")
        val length = this[2].toUByte().toInt()
        if (this.size < 3 + length) throw IllegalArgumentException("Out of bytes")
        val value = this.drop(3).take(length).toByteArray()
        return TLV(tag, value)
    }
    val length = firstLength.toUByte().toInt()
    if (this.size < 2 + length) throw IllegalArgumentException("Out of bytes")
    val value = this.drop(2).take(length).toByteArray()
    return TLV(tag, value)
}.getOrElse { throw if (it is IllegalArgumentException) it else IllegalArgumentException(it) }

