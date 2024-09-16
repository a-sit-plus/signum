package at.asitplus.signum.indispensable.asn1.encoding

import at.asitplus.catching
import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.BERTags.BMP_STRING
import at.asitplus.signum.indispensable.asn1.BERTags.IA5_STRING
import at.asitplus.signum.indispensable.asn1.BERTags.NUMERIC_STRING
import at.asitplus.signum.indispensable.asn1.BERTags.PRINTABLE_STRING
import at.asitplus.signum.indispensable.asn1.BERTags.T61_STRING
import at.asitplus.signum.indispensable.asn1.BERTags.UNIVERSAL_STRING
import at.asitplus.signum.indispensable.asn1.BERTags.UTF8_STRING
import at.asitplus.signum.indispensable.asn1.BERTags.VISIBLE_STRING
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.util.fromTwosComplementByteArray
import kotlinx.datetime.Instant
import kotlin.experimental.and

/**
 * Result of parsing a single, toplevel [Asn1Element] from a bytearray
 */
typealias Asn1Parsed = Pair<Asn1Element, ByteArray>

/**
 * The parsed [Asn1Element]
 */
val Asn1Parsed.element get() = first

/**
 *  The remainder of the underlying bytearray (empty if, everything was consumed)
 */
val Asn1Parsed.remainingBytes get() = second

/**
 * Parses the provides [input] into a single [Asn1Element]
 * @return the parsed [Asn1Element]
 *
 * @throws Asn1Exception on invalid input or if more than a single root structure was contained in the [input]
 */
@Throws(Asn1Exception::class)
fun Asn1Element.Companion.parse(input: ByteArray): Asn1Element = Asn1Reader(input).doParse(single = true).let {
    if (it.size != 1) throw Asn1StructuralException("Multiple ASN.1 structures found")
    it.first()
}

/**
 * Parses the provides [input] into a single [Asn1Element]
 * @return the [Asn1Parsed] containing an element and remaining bytes
 *
 * @throws Asn1Exception on invalid input or if more than a single root structure was contained in the [input]
 */
//this only makes sense until we switch to kotlinx.io
@Throws(Asn1Exception::class)
fun Asn1Element.Companion.parseWithRemainder(input: ByteArray): Asn1Parsed = parse(input).let {
    it to input.drop(it.overallLength).toByteArray()
}


private class Asn1Reader(private val input: ByteArray) {

    private var rest = input

    @Throws(Asn1Exception::class)
    fun doParse(single: Boolean = false): List<Asn1Element> = runRethrowing {
        val result = mutableListOf<Asn1Element>()
        while (rest.isNotEmpty()) {
            val tlv = read()
            if (tlv.isSequence()) result.add(Asn1Sequence(Asn1Reader(tlv.content).doParse()))
            else if (tlv.isSet()) result.add(Asn1Set.fromPresorted(Asn1Reader(tlv.content).doParse()))
            else if (tlv.isExplicitlyTagged()) result.add(
                Asn1ExplicitlyTagged(
                    tlv.tag.tagValue,
                    Asn1Reader(tlv.content).doParse()
                )
            )
            else if (tlv.tag == Asn1Element.Tag.OCTET_STRING) {
                catching {
                    result.add(Asn1EncapsulatingOctetString(Asn1Reader(tlv.content).doParse()))
                }.getOrElse {
                    result.add(Asn1PrimitiveOctetString(tlv.content))
                }
            } else if (tlv.tag.isConstructed) { //custom tags, we don't know if it is a SET OF, SET, SEQUENCE,… so we default to sequence semantics
                result.add(Asn1CustomStructure(Asn1Reader(tlv.content).doParse(), tlv.tag.tagValue, tlv.tagClass))
            } else result.add(Asn1Primitive(tlv.tag, tlv.content))
            if (single) return result
        }
        return result
    }

    private fun TLV.isSet() = tag == Asn1Element.Tag.SET
    private fun TLV.isSequence() = (tag == Asn1Element.Tag.SEQUENCE)
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
 * decodes this [Asn1Primitive]'s content into an [Boolean]
 * @throws [Asn1Exception] all sorts of exceptions on invalid input
 */
@Throws(Asn1Exception::class)
fun Asn1Primitive.decodeToBoolean() = runRethrowing { decode(Asn1Element.Tag.BOOL) { Boolean.decodeFromAsn1ContentBytes(it) } }

/** Exception-free version of [decodeToBoolean] */
fun Asn1Primitive.decodeToBooleanOrNull() = runCatching { decodeToBoolean() }.getOrNull()

/**
 * decodes this [Asn1Primitive]'s content into an [Int]
 * @throws [Asn1Exception] on invalid input
 */
@Throws(Asn1Exception::class)
fun Asn1Primitive.decodeToInt() = runRethrowing { decode(Asn1Element.Tag.INT) { Int.decodeFromAsn1ContentBytes(it) } }

/** Exception-free version of [decodeToInt] */
fun Asn1Primitive.decodeToIntOrNull() = runCatching { decodeToInt() }.getOrNull()

/**
 * decodes this [Asn1Primitive]'s content into a [Long]
 * @throws [Asn1Exception] on invalid input
 */
@Throws(Asn1Exception::class)
fun Asn1Primitive.decodeToLong() = runRethrowing { decode(Asn1Element.Tag.INT) { Long.decodeFromAsn1ContentBytes(it) } }

/** Exception-free version of [decodeToLong] */
inline fun Asn1Primitive.decodeToLongOrNull() = runCatching { decodeToLong() }.getOrNull()

/**
 * decodes this [Asn1Primitive]'s content into an [UInt]
 * @throws [Asn1Exception] on invalid input
 */
@Throws(Asn1Exception::class)
fun Asn1Primitive.decodeToUInt() = runRethrowing { decode(Asn1Element.Tag.INT) { UInt.decodeFromAsn1ContentBytes(it) } }

/** Exception-free version of [decodeToUInt] */
inline fun Asn1Primitive.decodeToUIntOrNull() = runCatching { decodeToUInt() }.getOrNull()

/**
 * decodes this [Asn1Primitive]'s content into an [ULong]
 * @throws [Asn1Exception] on invalid input
 */
@Throws(Asn1Exception::class)
fun Asn1Primitive.decodeToULong() = runRethrowing { decode(Asn1Element.Tag.INT) { ULong.decodeFromAsn1ContentBytes(it) } }

/** Exception-free version of [decodeToULong] */
inline fun Asn1Primitive.decodeToULongOrNull() = runCatching { decodeToULong() }.getOrNull()

/** Decode the [Asn1Primitive] as a [BigInteger]
 * @throws [Asn1Exception] on invalid input */
@Throws(Asn1Exception::class)
fun Asn1Primitive.decodeToBigInteger() =
    runRethrowing { decode(Asn1Element.Tag.INT) { BigInteger.decodeFromAsn1ContentBytes(it) } }

/** Exception-free version of [decodeToBigInteger] */
inline fun Asn1Primitive.decodeToBigIntegerOrNull() = runCatching { decodeToBigInteger() }.getOrNull()

/**
 * transforms this [Asn1Primitive] into an [Asn1String] subtype based on its tag
 *
 * @throws [Asn1Exception] all sorts of exceptions on invalid input
 */
@Throws(Asn1Exception::class)
fun Asn1Primitive.asAsn1String(): Asn1String = runRethrowing {
    when (tag.tagValue) {
        UTF8_STRING.toULong() -> Asn1String.UTF8(String.decodeFromAsn1ContentBytes(content))
        UNIVERSAL_STRING.toULong() -> Asn1String.Universal(String.decodeFromAsn1ContentBytes(content))
        IA5_STRING.toULong() -> Asn1String.IA5(String.decodeFromAsn1ContentBytes(content))
        BMP_STRING.toULong() -> Asn1String.BMP(String.decodeFromAsn1ContentBytes(content))
        T61_STRING.toULong() -> Asn1String.Teletex(String.decodeFromAsn1ContentBytes(content))
        PRINTABLE_STRING.toULong() -> Asn1String.Printable(String.decodeFromAsn1ContentBytes(content))
        NUMERIC_STRING.toULong() -> Asn1String.Numeric(String.decodeFromAsn1ContentBytes(content))
        VISIBLE_STRING.toULong() -> Asn1String.Visible(String.decodeFromAsn1ContentBytes(content))
        else -> TODO("Support other string tag $tag")
    }
}

/**
 * Decodes this [Asn1Primitive]'s content into a String.
 * @throws [Asn1Exception] all sorts of exceptions on invalid input
 */
fun Asn1Primitive.decodeToString() = runRethrowing {asAsn1String().value}

/** Exception-free version of [decodeToString] */
fun Asn1Primitive.decodeToStringOrNull() = runCatching { decodeToString() }.getOrNull()



/**
 * decodes this [Asn1Primitive]'s content into an [Instant] if it is encoded as UTC TIME or GENERALIZED TIME
 *
 * @throws Asn1Exception on invalid input
 */
@Throws(Asn1Exception::class)
fun Asn1Primitive.decodeToInstant() =
    when (tag) {
        Asn1Element.Tag.TIME_UTC -> decode(Asn1Element.Tag.TIME_UTC, Instant.Companion::decodeUtcTimeFromAsn1ContentBytes)
        Asn1Element.Tag.TIME_GENERALIZED -> decode(
            Asn1Element.Tag.TIME_GENERALIZED,
            Instant.Companion::decodeGeneralizedTimeFromAsn1ContentBytes
        )

        else -> TODO("Support time tag $tag")
    }

/**
 * Exception-free version of [decodeToInstant]
 */
fun Asn1Primitive.decodeToInstantOrNull() = catching { decodeToInstant() }.getOrNull()


/**
 * Transforms this [Asn1Primitive]' into an [Asn1BitString], assuming it was encoded as BIT STRING
 * @throws Asn1Exception  on invalid input
 */
@Throws(Asn1Exception::class)
fun Asn1Primitive.asAsn1BitString() = Asn1BitString.decodeFromTlv(this, Asn1Element.Tag.BIT_STRING)

/**
 * decodes this [Asn1Primitive] to null (i.e. verifies the tag to be [BERTags.ASN1_NULL] and the content to be empty
 *
 * @throws Asn1Exception  on invalid input
 */
@Throws(Asn1Exception::class)
fun Asn1Primitive.readNull() = decode(Asn1Element.Tag.NULL) {}

/**
 * Name seems odd, but this is just an exception-free version of [readNull]
 */
fun Asn1Primitive.readNullOrNull() = catching { readNull() }.getOrNull()


/**
 * Generic decoding function. Verifies that this [Asn1Primitive]'s tag matches [tag]
 * and transforms its content as per [transform]
 * @throws Asn1Exception all sorts of exceptions on invalid input
 */
@Throws(Asn1Exception::class)
inline fun <reified T> Asn1Primitive.decode(tag: ULong, transform: (content: ByteArray) -> T): T =
    decode(Asn1Element.Tag(tag, constructed = false), transform)

/**
 * Generic decoding function. Verifies that this [Asn1Primitive]'s tag matches [tag]
 * and transforms its content as per [transform]
 * @throws Asn1Exception all sorts of exceptions on invalid input
 */
@Throws(Asn1Exception::class)
inline fun <reified T> Asn1Primitive.decode(tag: Asn1Element.Tag, transform: (content: ByteArray) -> T) =
    runRethrowing {
        if (tag.isConstructed) throw IllegalArgumentException("A primitive cannot have a CONSTRUCTED tag")
        if (tag != this.tag) throw Asn1TagMismatchException(tag, this.tag)
        transform(content)
    }

/**
 * Exception-free version of [decode]
 */
inline fun <reified T> Asn1Primitive.decodeOrNull(tag: ULong, transform: (content: ByteArray) -> T) =
    catching { decode(tag, transform) }.getOrNull()

/**
 * Decodes an [Instant] from [bytes] assuming the same encoding as the [Asn1Primitive.content] property of an [Asn1Primitive] containing an ASN.1 UTC TIME
 * @throws Asn1Exception if the input does not parse
 */
@Throws(Asn1Exception::class)
fun Instant.Companion.decodeUtcTimeFromAsn1ContentBytes(input: ByteArray): Instant = runRethrowing {
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

/**
 * Decodes an [Instant] from [bytes] assuming the same encoding as the [Asn1Primitive.content] property of an [Asn1Primitive] containing an ASN.1 GENERALIZED TIME
 * @throws Asn1Exception if the input does not parse
 */
@Throws(Asn1Exception::class)
fun Instant.Companion.decodeGeneralizedTimeFromAsn1ContentBytes(bytes: ByteArray): Instant = runRethrowing {
    val s = bytes.decodeToString()
    if (s.length != 15) throw IllegalArgumentException("Input too short: $bytes")
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
 * Decodes a signed [Int] from [bytes] assuming the same encoding as the [Asn1Primitive.content] property of an [Asn1Primitive] containing an ASN.1 INTEGER
 * @throws Asn1Exception if the byte array is out of bounds for a signed int
 */
@Throws(Asn1Exception::class)
fun Int.Companion.decodeFromAsn1ContentBytes(bytes: ByteArray): Int =
    runRethrowing { fromTwosComplementByteArray(bytes) }

/**
 * Decodes a signed [Long] from [bytes] assuming the same encoding as the [Asn1Primitive.content] property of an [Asn1Primitive] containing an ASN.1 INTEGER
 * @throws Asn1Exception if the byte array is out of bounds for a signed long
 */
@Throws(Asn1Exception::class)
fun Long.Companion.decodeFromAsn1ContentBytes(bytes: ByteArray): Long =
    runRethrowing { fromTwosComplementByteArray(bytes) }

/**
 * Decodes a [UInt] from [bytes] assuming the same encoding as the [Asn1Primitive.content] property of an [Asn1Primitive] containing an ASN.1 INTEGER
 * @throws Asn1Exception if the byte array is out of bounds for an unsigned int
 */
@Throws(Asn1Exception::class)
fun UInt.Companion.decodeFromAsn1ContentBytes(bytes: ByteArray): UInt =
    runRethrowing { fromTwosComplementByteArray(bytes) }

/**
 * Decodes a [ULong] from [bytes] assuming the same encoding as the [Asn1Primitive.content] property of an [Asn1Primitive] containing an ASN.1 INTEGER
 * @throws Asn1Exception if the byte array is out of bounds for an unsigned long
 */
@Throws(Asn1Exception::class)
fun ULong.Companion.decodeFromAsn1ContentBytes(bytes: ByteArray): ULong =
    runRethrowing { fromTwosComplementByteArray(bytes) }

/**
 * Decodes a [BigInteger] from [bytes] assuming the same encoding as the [Asn1Primitive.content] property of an [Asn1Primitive] containing an ASN.1 INTEGER
 */
@Throws(Asn1Exception::class)
fun BigInteger.Companion.decodeFromAsn1ContentBytes(bytes: ByteArray): BigInteger =
    runRethrowing { fromTwosComplementByteArray(bytes) }

/**
 * Decodes a [Boolean] from [bytes] assuming the same encoding as the [Asn1Primitive.content] property of an [Asn1Primitive] containing an ASN.1 BOOLEAN
 */
fun Boolean.Companion.decodeFromAsn1ContentBytes(bytes: ByteArray): Boolean {
    if (bytes.size != 1) throw Asn1Exception("Not a Boolean!")
    return when (bytes.first().toUByte()) {
        0.toUByte() -> false
        0xff.toUByte() -> true
        else -> throw Asn1Exception("${bytes.first().toString(16).uppercase()} is not a boolean value!")
    }
}


/**
 * Decodes a [String] from [bytes] assuming the same encoding as the [Asn1Primitive.content] property of an [Asn1Primitive] containing an ASN.1 STRING (any kind)
 */
fun String.Companion.decodeFromAsn1ContentBytes(bytes: ByteArray) = bytes.decodeToString()


@Throws(Asn1Exception::class)
private fun ByteArray.readTlv(): TLV = runRethrowing {
    if (this.isEmpty()) throw IllegalArgumentException("Can't read TLV, input empty")
    if (this.size == 1) return TLV(Asn1Element.Tag(byteArrayOf(this[0])), byteArrayOf())

    val iterator = iterator()
    val tag = iterator.decodeTag()
    val length = iterator.decodeLength()
    require(length < 1024 * 1024) { "Heap space" }
    val value = with(iterator) {
        ByteArray(length) {
            require(hasNext()) { "Out of bytes to decode" }
            next()
        }
    }
    return TLV(Asn1Element.Tag(tag.second), value)
}

@Throws(IllegalArgumentException::class)
private fun ByteIterator.decodeLength() =
    next().let { firstByte ->
        if (firstByte.isBerShortForm()) {
            firstByte.toUByte().toInt()
        } else { // its BER long form!
            val numberOfLengthOctets = (firstByte byteMask 0x7F).toInt()
            (0 until numberOfLengthOctets).fold(0) { acc, index ->
                require(hasNext()) { "Can't decode length" }
                acc + (next().toUByte().toInt() shl Byte.SIZE_BITS * (numberOfLengthOctets - index - 1))
            }
        }
    }

private fun Byte.isBerShortForm() = this byteMask 0x80 == 0x00.toUByte()

internal infix fun Byte.byteMask(mask: Int) = (this and mask.toUInt().toByte()).toUByte()

internal fun ByteIterator.decodeTag(): Pair<ULong, ByteArray> =
    next().let { firstByte ->
        (firstByte byteMask 0x1F).let { tagNumber ->
            if (tagNumber <= 30U) {
                tagNumber.toULong() to byteArrayOf(firstByte)
            } else {
                decodeAsn1VarULong().let { (l, b) -> l to byteArrayOf(firstByte, *b) }
            }
        }
    }
