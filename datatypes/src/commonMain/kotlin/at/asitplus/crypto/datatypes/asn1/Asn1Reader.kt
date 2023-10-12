package at.asitplus.crypto.datatypes.asn1

import at.asitplus.crypto.datatypes.asn1.BERTags.BIT_STRING
import at.asitplus.crypto.datatypes.asn1.BERTags.BMP_STRING
import at.asitplus.crypto.datatypes.asn1.BERTags.GENERALIZED_TIME
import at.asitplus.crypto.datatypes.asn1.BERTags.IA5_STRING
import at.asitplus.crypto.datatypes.asn1.BERTags.INTEGER
import at.asitplus.crypto.datatypes.asn1.BERTags.NULL
import at.asitplus.crypto.datatypes.asn1.BERTags.NUMERIC_STRING
import at.asitplus.crypto.datatypes.asn1.BERTags.OBJECT_IDENTIFIER
import at.asitplus.crypto.datatypes.asn1.BERTags.PRINTABLE_STRING
import at.asitplus.crypto.datatypes.asn1.BERTags.T61_STRING
import at.asitplus.crypto.datatypes.asn1.BERTags.UNIVERSAL_STRING
import at.asitplus.crypto.datatypes.asn1.BERTags.UTC_TIME
import at.asitplus.crypto.datatypes.asn1.BERTags.UTF8_STRING
import at.asitplus.crypto.datatypes.asn1.BERTags.VISIBLE_STRING
import at.asitplus.crypto.datatypes.asn1.DERTags.isContainer
import at.asitplus.crypto.datatypes.asn1.DERTags.toExplicitTag
import kotlinx.datetime.Instant


fun Asn1Element.Companion.parse(input: ByteArray) = Asn1Reader(input).doParse().let {
    if (it.size != 1) throw IllegalArgumentException("Multiple ASN1 structures found")
    it.first()
}

private class Asn1Reader(input: ByteArray) {

    private var rest = input

    @Throws(IllegalArgumentException::class)
    fun doParse(): List<Asn1Element> {
        val result = mutableListOf<Asn1Element>()
        while (rest.isNotEmpty()) {
            val tlv = read()
            if (tlv.isSequence()) result.add(Asn1Sequence(Asn1Reader(tlv.content).doParse()))
            else if (tlv.isSet()) result.add(Asn1Set(Asn1Reader(tlv.content).doParse()))
            else if (tlv.isExplicitlyTagged()) result.add(
                Asn1Tagged(
                    tlv.tag,
                    Asn1Reader(tlv.content).doParse()
                )
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
    ObjectIdentifier.parse(it)
}

fun Asn1Primitive.readInt() = decode(INTEGER) {
    Int.decodeFromDer(it)
}

fun Asn1Primitive.readLong() = decode(INTEGER) {
    Long.decodeFromDer(it)
}

fun Asn1Primitive.readString(): Asn1String =
    if (tag == UTF8_STRING) Asn1String.UTF8(content.decodeToString())
    else if (tag == UNIVERSAL_STRING) Asn1String.Universal(content.decodeToString())
    else if (tag == IA5_STRING) Asn1String.IA5(content.decodeToString())
    else if (tag == BMP_STRING) Asn1String.BMP(content.decodeToString())
    else if (tag == T61_STRING) Asn1String.Teletex(content.decodeToString())
    else if (tag == PRINTABLE_STRING) Asn1String.Printable(content.decodeToString())
    else if (tag == NUMERIC_STRING) Asn1String.Numeric(content.decodeToString())
    else if (tag == VISIBLE_STRING) Asn1String.Visible(content.decodeToString())
    else TODO("Support other string tag $tag")

fun Asn1Primitive.readInstant() =
    if (tag == UTC_TIME) decode(UTC_TIME, Instant.Companion::decodeUtcTimeFromDer)
    else if (tag == GENERALIZED_TIME) decode(GENERALIZED_TIME, Instant.Companion::decodeGeneralizedTimeFromDer)
    else TODO("Support time tag $tag")

fun Asn1Primitive.readBitString() = decode(BIT_STRING, ::decodeBitString)
fun Asn1Primitive.readNull() = decode(NULL) {}

fun Asn1Tagged.verify(tag: UByte): List<Asn1Element> {
    if (this.tag != tag.toExplicitTag()) throw IllegalArgumentException("Tag ${this.tag} does not match expected tag ${tag.toExplicitTag()}")
    return this.children
}

inline fun <reified T> Asn1Primitive.decode(tag: UByte, decode: (content: ByteArray) -> T) = runCatching {
    if (tag != this.tag) throw IllegalArgumentException("Tag mismatch. Expected: $tag, is: ${this.tag}")
    decode(content)
}.getOrElse { if (it is IllegalArgumentException) throw it else throw IllegalArgumentException(it) }

fun decodeBitString(input: ByteArray) = input.drop(1).toByteArray()


@Throws(IllegalArgumentException::class)
fun Instant.Companion.decodeUtcTimeFromDer(input: ByteArray): Instant = runCatching {
    val s = input.decodeToString()
    if (s.length != 13) throw IllegalArgumentException("Input too short: $input")
    val year = "${s[0]}${s[1]}".toInt()
    val century = if (year <= 49) "20" else "19" // RFC 5280 4.1.2.5 Validity
    val isoString = "$century${s[0]}${s[1]}" + // year
            "-${s[2]}${s[3]}" + // month
            "-${s[4]}${s[5]}" + // day
            "T${s[6]}${s[7]}" + // hour
            ":${s[8]}${s[9]}" + // minute
            ":${s[10]}${s[11]}" + // seconds
            "${s[12]}" // time offset
    return parse(isoString)
}.getOrElse { throw IllegalArgumentException(it) }

@Throws(IllegalArgumentException::class)
fun Instant.Companion.decodeGeneralizedTimeFromDer(input: ByteArray): Instant = runCatching {
    val s = input.decodeToString()
    if (s.length != 15) throw IllegalArgumentException("Input too short: $input")
    val isoString = "${s[0]}${s[1]}${s[2]}${s[3]}" + // year
            "-${s[4]}${s[5]}" + // month
            "-${s[6]}${s[7]}" + // day
            "T${s[8]}${s[9]}" + // hour
            ":${s[10]}${s[11]}" + // minute
            ":${s[12]}${s[13]}" + // seconds
            "${s[14]}" // time offset
    return parse(isoString)
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

private fun ByteArray.readTlv(): TLV = runCatching {
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
    if (this.size < 2 + length)
        throw IllegalArgumentException("Out of bytes")
    val value = this.drop(2).take(length).toByteArray()
    return TLV(tag, value)
}.getOrElse { throw if (it is IllegalArgumentException) it else IllegalArgumentException(it) }

