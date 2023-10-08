package at.asitplus.crypto.datatypes.asn1

import at.asitplus.crypto.datatypes.Asn1String
import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.EcCurve
import at.asitplus.crypto.datatypes.JwsAlgorithm
import at.asitplus.crypto.datatypes.asn1.BERTags.BIT_STRING
import at.asitplus.crypto.datatypes.asn1.BERTags.INTEGER
import at.asitplus.crypto.datatypes.asn1.BERTags.NULL
import at.asitplus.crypto.datatypes.asn1.BERTags.OBJECT_IDENTIFIER
import at.asitplus.crypto.datatypes.asn1.BERTags.PRINTABLE_STRING
import at.asitplus.crypto.datatypes.asn1.BERTags.UTC_TIME
import at.asitplus.crypto.datatypes.asn1.BERTags.UTF8_STRING
import at.asitplus.crypto.datatypes.asn1.DERTags.isContainer
import at.asitplus.crypto.datatypes.asn1.DERTags.toExplicitTag
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
            if (tlv.isSequence()) result.add(Asn1Sequence(Asn1StructureReader(tlv.content).readAll()))
            else if (tlv.isSet()) result.add(Asn1Set(Asn1StructureReader(tlv.content).readAll()))
            else if (tlv.isExplicitlyTagged()) result.add(
                Asn1Tagged(
                    tlv.tag,
                    Asn1StructureReader(tlv.content).readAll().let {
                        if (it.size != 1) throw IllegalArgumentException("TAGGED contains ${it.size} objects")
                        it.first()
                    })
            )
            else result.add(Asn1Primitive(tlv.tag, tlv.content))

        }
        return result.toList()
    }

    private fun TLV.isSet() = tag == DERTags.DER_SET
    private fun TLV.isSequence() = tag == DERTags.DER_SEQUENCE
    private fun TLV.isExplicitlyTagged() =
        tag.isContainer() //yes, this includes sequences and set, so we need to check this last!

    @Throws(IllegalArgumentException::class)
    private fun read(): TLV {
        val tlv = rest.readTlv()
        if (tlv.overallLength > rest.size)
            throw IllegalArgumentException("Out of bytes")
        rest = rest.drop(tlv.overallLength).toByteArray()
        return tlv
    }
}

fun Asn1Primitive.readOid() = decode(OBJECT_IDENTIFIER) {
    it.encodeToString(Base16)
}

fun Asn1Primitive.readInt() = decode(INTEGER) {
    Int.decodeFromDer(it)
}

fun Asn1Primitive.readLong() = decode(INTEGER) {
    Long.decodeFromDer(it)
}

fun Asn1Primitive.readString(): Asn1String =
    if (tag == UTF8_STRING) Asn1String.UTF8(String(content))
    else if (tag == PRINTABLE_STRING) Asn1String.Printable(String(content))
    else TODO("Support other string types!")

fun Asn1Primitive.readUtcTime() = decode(UTC_TIME, Instant.Companion::decodeUtcTimeFromDer)
fun Asn1Primitive.readBitString() = decode(BIT_STRING, ::decodeBitString)
fun Asn1Primitive.readNull() = decode(NULL) {}

fun Asn1Tagged.verify(tag: UByte): ExtendedTlv {
    if (this.tag != tag.toExplicitTag()) throw IllegalArgumentException("Tag ${this.tag} does not match expected tag ${tag.toExplicitTag()}")
    return this.contained
}

fun JwsAlgorithm.Companion.decodeFromTlv(input: Asn1Primitive) =
    when (input.readOid()) {
        "2A8648CE3D040303" -> JwsAlgorithm.ES384
        "2A8648CE3D040302" -> JwsAlgorithm.ES256
        else -> TODO("Implement remaining algorithm oids")
    }


inline fun <reified T> Asn1Primitive.decode(tag: UByte, decode: (content: ByteArray) -> T) = runCatching {
    if (tag != this.tag) throw IllegalArgumentException("Tag mismatch. Expected: $tag, is: ${this.tag}")
    decode(content)
}.getOrElse { if (it is IllegalArgumentException) throw it else throw IllegalArgumentException(it) }


class Asn1Reader(input: ByteArray) {

    var rest: ByteArray private set

    init {
        rest = input
    }


    fun hasMore() = rest.isNotEmpty()
    fun <T> readSequence(func: (ByteArray) -> T?) = read(0x30u, func)

    fun <T> readSet(func: (ByteArray) -> T?) = read(0x31u, func)

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

    fun <T> read(tag: UByte, func: (ByteArray) -> T?): T {
        val tlv = rest.readTlv()
        if (tlv.tag != tag)
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
fun CryptoPublicKey.Companion.decodeFromTlv(src: Asn1Sequence): CryptoPublicKey {
    if (src.children.size != 2) throw IllegalArgumentException("Invalid SPKI Structure!")
    val keyInfo = src.nextChild() as Asn1Sequence
    if (keyInfo.children.size != 2) throw IllegalArgumentException("Superfluous data in  SPKI!")

    val oid = (keyInfo.nextChild() as Asn1Primitive).readOid()

    if (oid == "2A8648CE3D0201") {
        val curveOid = (keyInfo.nextChild() as Asn1Primitive).readOid()
        val curve = when (curveOid) {
            "2A8648CE3D030107" -> EcCurve.SECP_256_R_1
            "2B81040022" -> EcCurve.SECP_384_R_1
            "2B81040023" -> EcCurve.SECP_521_R_1
            else -> throw IllegalArgumentException("Curve not supported: $curveOid")
        }
        val bitString = (src.nextChild() as Asn1Primitive).readBitString()


        val xAndY = bitString.drop(1).toByteArray()
        val coordLen = curve.coordinateLengthBytes.toInt()
        val x = xAndY.take(coordLen).toByteArray()
        val y = xAndY.drop(coordLen).take(coordLen).toByteArray()
        return CryptoPublicKey.Ec.fromCoordinates(curve, x, y)
    } else if (oid == "2A864886F70D010101") {
        (keyInfo.nextChild() as Asn1Primitive).readNull()
        val bitString = (src.nextChild() as Asn1Primitive).readBitString()
        Asn1StructureReader(bitString).readAll().let {
            if (it.size != 1) throw IllegalArgumentException("Superfluous data in SPKI!")
            val rsaSequence = it.first() as Asn1Sequence
            val n = (rsaSequence.nextChild() as Asn1Primitive).decode(INTEGER) { it }
            val e = (rsaSequence.nextChild() as Asn1Primitive).readInt().toUInt()
            if (rsaSequence.hasMoreChildren()) throw IllegalArgumentException("Superfluous data in SPKI!")
            return CryptoPublicKey.Rsa(
                CryptoPublicKey.Rsa.Size.of(((n.size - 1) * 8).toUInt()) ?: throw IllegalArgumentException(
                    "Illegal RSa key size: ${(n.size - 1) * 8}"
                ), n, e
            )
        }
    } else {
        throw IllegalArgumentException("Unsupported Key Type: $oid")
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
    val tag = this[0].toUByte()
    if (this.size == 1) return TLV(tag, byteArrayOf())
    val firstLength = this[1]
    if (firstLength == 0x82.toByte()) {
        if (this.size < 4) throw IllegalArgumentException("Can't decode length")
        val length = (this[2].toUByte().toInt() shl 8) + this[3].toUByte().toInt()
        if (this.size < 4 + length) throw IllegalArgumentException("Out of bytes")
        val value = this.drop(4).take(length).toByteArray()
        return TLV(tag, value)
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

