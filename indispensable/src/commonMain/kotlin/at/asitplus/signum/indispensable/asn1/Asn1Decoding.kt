package at.asitplus.signum.indispensable.asn1

import at.asitplus.catching
import at.asitplus.io.UVarInt
import at.asitplus.io.varIntDecode
import at.asitplus.signum.indispensable.asn1.BERTags.ASN1_NULL
import at.asitplus.signum.indispensable.asn1.BERTags.BMP_STRING
import at.asitplus.signum.indispensable.asn1.BERTags.BOOLEAN
import at.asitplus.signum.indispensable.asn1.BERTags.GENERALIZED_TIME
import at.asitplus.signum.indispensable.asn1.BERTags.IA5_STRING
import at.asitplus.signum.indispensable.asn1.BERTags.INTEGER
import at.asitplus.signum.indispensable.asn1.BERTags.NUMERIC_STRING
import at.asitplus.signum.indispensable.asn1.BERTags.OCTET_STRING
import at.asitplus.signum.indispensable.asn1.BERTags.PRINTABLE_STRING
import at.asitplus.signum.indispensable.asn1.BERTags.T61_STRING
import at.asitplus.signum.indispensable.asn1.BERTags.UNIVERSAL_STRING
import at.asitplus.signum.indispensable.asn1.BERTags.UTC_TIME
import at.asitplus.signum.indispensable.asn1.BERTags.UTF8_STRING
import at.asitplus.signum.indispensable.asn1.BERTags.VISIBLE_STRING
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.util.fromTwosComplementByteArray
import kotlinx.datetime.Instant
import kotlin.experimental.and


/**
 * Parses the provides [input] into a single [Asn1Element]
 * @return the parsed [Asn1Element]
 *
 * @throws Asn1Exception on invalid input or if more than a single root structure was contained in the [input]
 */
@Throws(Asn1Exception::class)
fun Asn1Element.Companion.parse(input: ByteArray) = Asn1Reader(input).doParse().let {
    if (it.size != 1) throw Asn1StructuralException("Multiple ASN.1 structures found")
    it.first()
}

private class Asn1Reader(input: ByteArray) {

    private var rest = input

    @Throws(Asn1Exception::class)
    fun doParse(): List<Asn1Element> = runRethrowing {
        val result = mutableListOf<Asn1Element>()
        while (rest.isNotEmpty()) {
            val tlv = read()
            if (tlv.isSequence()) result.add(Asn1Sequence(Asn1Reader(tlv.content).doParse()))
            else if (tlv.isSet()) result.add(Asn1Set(Asn1Reader(tlv.content).doParse()))
            else if (tlv.isExplicitlyTagged()) result.add(
                Asn1Tagged(
                    tlv.tag.tagValue,
                    Asn1Reader(tlv.content).doParse()
                )
            )
            else if (tlv.tag.tagValue == OCTET_STRING.toUInt()) {
                kotlin.runCatching { //TODO: make catching again, not runCatching
                    result.add(Asn1EncapsulatingOctetString(Asn1Reader(tlv.content).doParse()))
                }.getOrElse {
                    result.add(Asn1PrimitiveOctetString(tlv.content))
                }
            } else result.add(Asn1Primitive(tlv.tag, tlv.content))

        }
        return result
    }

    private fun TLV.isSet() = tag.tagValue == BERTags.SET.toUInt() && tag.isConstructed
    private fun TLV.isSequence() = tag.tagValue == BERTags.SEQUENCE.toUInt() && tag.isConstructed
    private fun TLV.isExplicitlyTagged() = tag.isExplicitlyTagged

    @Throws(Asn1Exception::class)
    private fun read(): TLV = runRethrowing {
        val tlv = rest.readTlv()
        if (tlv.overallLength > rest.size)
            throw Asn1Exception("Out of bytes")
        rest = rest.drop(tlv.overallLength).toByteArray()
        return tlv
    }
}

/**
 * decodes this [Asn1Primitive]'s content into an [Int]
 *
 * @throws [Throwable] all sorts of exceptions on invalid input
 */
@Throws(Asn1Exception::class)
fun Asn1Primitive.readInt() = runRethrowing { decode(INTEGER.toUInt()) { Int.decodeFromDer(it) } }

/**
 * decodes this [Asn1Primitive]'s content into an [Boolean]
 *
 * @throws [Throwable] all sorts of exceptions on invalid input
 */
@Throws(Asn1Exception::class)
fun Asn1Primitive.readBool() = runRethrowing {
    decode(BOOLEAN.toUInt()) {
        if (it.size != 1) throw Asn1Exception("Not a Boolean!")
        when (it.first().toUByte()) {
            0.toUByte() -> false
            0xff.toUByte() -> true
            else -> throw Asn1Exception("${it.first().toString(16).uppercase()} is not a value!")
        }
    }
}

/**
 * Decode the [Asn1Primitive] as a [BigInteger]
 */
@Throws(Asn1Exception::class)
fun Asn1Primitive.readBigInteger() =
    decode(INTEGER.toUInt()) { BigInteger.fromTwosComplementByteArray(it) }

/**
 * Exception-free version of [readBigInteger]
 */
@Suppress("NOTHING_TO_INLINE")
inline fun Asn1Primitive.readBigIntegerOrNull() = catching { readBigInteger() }.getOrNull()

/**
 * Exception-free version of [readInt]
 */
fun Asn1Primitive.readIntOrNull() = catching { readInt() }.getOrNull()


/**
 * decodes this [Asn1Primitive]'s content into a [Long]
 *
 * @throws [Throwable] all sorts of exceptions on invalid input
 */
@Throws(Asn1Exception::class)
fun Asn1Primitive.readLong() = runRethrowing { decode(INTEGER.toUInt()) { Long.decodeFromDer(it) } }

/**
 * Exception-free version of [readLong]
 */
fun Asn1Primitive.readLongOrNull() = catching { readLong() }.getOrNull()


/**
 * decodes this [Asn1Primitive]'s content into an [Asn1String]
 *
 * @throws [Throwable] all sorts of exceptions on invalid input
 */
@Throws(Throwable::class)
fun Asn1Primitive.readString(): Asn1String = runRethrowing {
    if (tag.tagValue == UTF8_STRING.toUInt()) Asn1String.UTF8(content.decodeToString())
    else if (tag.tagValue == UNIVERSAL_STRING.toUInt()) Asn1String.Universal(content.decodeToString())
    else if (tag.tagValue == IA5_STRING.toUInt()) Asn1String.IA5(content.decodeToString())
    else if (tag.tagValue == BMP_STRING.toUInt()) Asn1String.BMP(content.decodeToString())
    else if (tag.tagValue == T61_STRING.toUInt()) Asn1String.Teletex(content.decodeToString())
    else if (tag.tagValue == PRINTABLE_STRING.toUInt()) Asn1String.Printable(content.decodeToString())
    else if (tag.tagValue == NUMERIC_STRING.toUInt()) Asn1String.Numeric(content.decodeToString())
    else if (tag.tagValue == VISIBLE_STRING.toUInt()) Asn1String.Visible(content.decodeToString())
    else TODO("Support other string tag $tag")
}

/**
 * Exception-free version of [readString]
 */
fun Asn1Primitive.readStringOrNull() = catching { readString() }.getOrNull()


/**
 * decodes this [Asn1Primitive]'s content into an [Instant] if it is encoded as UTC TIME or GENERALIZED TIME
 *
 * @throws Asn1Exception on invalid input
 */
@Throws(Asn1Exception::class)
fun Asn1Primitive.readInstant() =
    if (tag.tagValue == UTC_TIME.toUInt()) decode(UTC_TIME.toUInt(), Instant.Companion::decodeUtcTimeFromDer)
    else if (tag.tagValue == GENERALIZED_TIME.toUInt()) decode(
        GENERALIZED_TIME.toUInt(),
        Instant.Companion::decodeGeneralizedTimeFromDer
    )
    else TODO("Support time tag $tag")

/**
 * Exception-free version of [readInstant]
 */
fun Asn1Primitive.readInstantOrNull() = catching { readInstant() }.getOrNull()


/**
 * decodes this [Asn1Primitive]'s content into an [ByteArray], assuming it was encoded as BIT STRING
 *
 * @throws Asn1Exception  on invalid input
 */
@Throws(Asn1Exception::class)
fun Asn1Primitive.readBitString() = Asn1BitString.decodeFromTlv(this)

/**
 * Exception-free version of [readBitString]
 */
fun Asn1Primitive.readBitStringOrNull() = catching { readBitString() }.getOrNull()


/**
 * decodes this [Asn1Primitive] to null (i.e. verifies the tag to be [BERTags.ASN1_NULL] and the content to be empty
 *
 * @throws Asn1Exception  on invalid input
 */
@Throws(Asn1Exception::class)
fun Asn1Primitive.readNull() = decode(ASN1_NULL.toUInt()) {}

/**
 * Name seems odd, but this is just an exception-free version of [readNull]
 */
fun Asn1Primitive.readNullOrNull() = catching { readNull() }.getOrNull()


/**
 * Returns this [Asn1Tagged] children, if its tag matches [tag]
 *
 * @throws Asn1TagMismatchException if the tag does not match
 */
@Throws(Asn1TagMismatchException::class)
fun Asn1Tagged.verifyTag(tag: UInt): List<Asn1Element> {
    val explicitTag = TLV.Tag(tag, constructed = true, TagClass.CONTEXT_SPECIFIC)
    if (this.tag != explicitTag) throw Asn1TagMismatchException(explicitTag, this.tag)
    return this.children
}

/**
 * Exception-free version of [verifyTag]
 */
fun Asn1Tagged.verifyTagOrNull(tag: UInt) = catching { verifyTag(tag) }.getOrNull()


/**
 * Generic decoding function. Verifies that this [Asn1Primitive]'s tag matches [tag]
 * and transforms its content as per [transform]
 * @throws Asn1Exception all sorts of exceptions on invalid input
 */
@Throws(Asn1Exception::class)
inline fun <reified T> Asn1Primitive.decode(tag: UInt, transform: (content: ByteArray) -> T) = runRethrowing {
    if (tag != this.tag.tagValue) throw Asn1TagMismatchException(TLV.Tag(tag, constructed = false), this.tag)
    transform(content)
}

/**
 * Exception-free version of [decode]
 */
inline fun <reified T> Asn1Primitive.decodeOrNull(tag: UInt, transform: (content: ByteArray) -> T) =
    catching { decode(tag, transform) }.getOrNull()

@Throws(Asn1Exception::class)
private fun Instant.Companion.decodeUtcTimeFromDer(input: ByteArray): Instant = runRethrowing {
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
}

@Throws(Asn1Exception::class)
private fun Instant.Companion.decodeGeneralizedTimeFromDer(input: ByteArray): Instant = runRethrowing {
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
}

/**
 * @throws Asn1Exception if the byte array is too long to be parsed to an int (note that only rudimentary checking happens)
 */
@Throws(Asn1Exception::class)
fun Int.Companion.decodeFromDer(input: ByteArray): Int = runRethrowing {
    if (input.size > 5) throw IllegalArgumentException("Absolute value too large!")
    return Long.decodeFromDer(input).toInt()
}

/**
 * @throws IllegalArgumentException if the byte array is too long to be parsed to a long (note that only rudimentary checking happens)
 */
@Throws(Asn1Exception::class)
fun Long.Companion.decodeFromDer(bytes: ByteArray): Long = runRethrowing {
    val input = if (bytes.size == 8) bytes else {
        if (bytes.size > 9) throw IllegalArgumentException("Absolute value too large!")
        val padding = if (bytes.first() and 0x80.toByte() != 0.toByte()) 0xFF.toByte() else 0x00.toByte()
        ByteArray(9 - bytes.size) { padding } + bytes
    }
    var result = 0L
    for (i in input.indices) {
        result = (result shl Byte.SIZE_BITS) or (input[i].toUByte().toLong())
    }
    return result
}

fun UInt.Companion.decodeFromDer(bytes: ByteArray): UInt = runRethrowing {
    val input = if (bytes.size == 8) bytes else {
        if (bytes.size > 5) throw IllegalArgumentException("Absolute value too large!")
        val padding = 0x00.toByte()
        ByteArray(9 - bytes.size) { padding } + bytes
    }
    var result = 0L
    for (i in input.indices) {
        result = (result shl Byte.SIZE_BITS) or (input[i].toUByte().toLong())
    }
    return result.toUInt()
}

@Throws(Asn1Exception::class)
private fun ByteArray.readTlv(): TLV = runRethrowing {
    if (this.isEmpty()) throw IllegalArgumentException("Can't read TLV, input empty")
    if (this.size == 1) return TLV(TLV.Tag(byteArrayOf(this[0])), byteArrayOf())

    val decodedTag = decodeTag()
    val tagLength = decodedTag.encodedTagLength
    val tagBytes = sliceArray(0..<tagLength)

    val value = this.drop(tagLength).decodeLengthAndValue()
    return TLV(TLV.Tag(tagBytes), value.toByteArray())
}

@Throws(IllegalArgumentException::class)
private fun List<Byte>.decodeLengthAndValue(): List<Byte> {
    if (this[0] == 0x82.toByte()) {
        require(size >= 3) { "Can't decode length" }
        val length = (getInt(1) shl 8) + getInt(2)
        require(size >= 3 + length) { "Out of bytes" }
        return drop(3).take(length)
    } else if (this[0] == 0x81.toByte()) {
        require(size >= 2) { "Can't decode length" }
        val length = getInt(1)
        require(size >= 2 + length) { "Out of bytes" }
        return drop(2).take(length)
    } else {
        val length = getInt(0)
        require(size >= 1 + length) { "Out of bytes" }
        return drop(1).take(length)
    }
}

private fun List<Byte>.getInt(i: Int) = this[i].toUByte().toInt()

private infix fun UByte.ushr(bits: Int) = toInt() ushr bits

internal infix fun Byte.byteMask(mask: Int) = (this and mask.toUInt().toByte()).toUByte()

internal fun ByteArray.decodeTag(): UVarInt {
    val tagNumber = this[0] byteMask 0x1F
    return if (tagNumber <= 30U) {
        UVarInt(tagNumber.toUInt())
    } else {
        drop(1).toByteArray().varIntDecode()
    }
}

internal val UVarInt.encodedTagLength: Int get() = encodeToByteArray().size.let { if (it > 1) 1 + it else 1 }