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
import at.asitplus.signum.indispensable.asn1.wrapInUnsafeSource
import kotlinx.datetime.Instant
import kotlinx.io.Source
import kotlinx.io.readByteArray
import kotlinx.io.readUByte
import kotlin.experimental.and


/**
 * Convenience wrapper around [parse], taking a [ByteArray] as [source]
 * @see parse
 */
@Throws(Asn1Exception::class)
@Deprecated(
    "Use a ByteArray or (even better) a kotlinx.io Source as input when possible. This method copies all bytes from the input twice and is inefficient.",
    ReplaceWith("source.readAsn1Element(); require(source.exhausted())")
)
fun Asn1Element.Companion.parse(input: ByteIterator): Asn1Element =
    parse(mutableListOf<Byte>().also { while (input.hasNext()) it.add(input.nextByte()) }.toByteArray())

/**
 * Parses the provided [input] into a single [Asn1Element]. Consumes all Bytes and throws if more than one Asn.1 Structure was found or trailing bytes were detected
 * @return the parsed [Asn1Element]
 *
 * @throws Asn1Exception on invalid input or if more than a single root structure was contained in the [input]
 */
@Throws(Asn1Exception::class)
fun Asn1Element.Companion.parse(source: ByteArray): Asn1Element =
    source.wrapInUnsafeSource().readFullyToAsn1Elements().first.let {
        if (it.size != 1)
            throw Asn1StructuralException("Trailing bytes found after the first ASN.1 element")
        it.first()
    }

/**
 * Tries to parse the [input] into a list of [Asn1Element]s. Consumes all Bytes and throws if an invalid ASN.1 Structure is found at any point.
 * @return the parsed elements
 *
 * @throws Asn1Exception on invalid input or if more than a single root structure was contained in the [input]
 *
 */
@Deprecated(
    "Use a ByteArray or (even better) a kotlinx.io Source as input when possible. This method copies all bytes from the input twice and is inefficient.",
    ReplaceWith("source.readFullyToAsn1Elements()"),
    DeprecationLevel.WARNING
)
@Throws(Asn1Exception::class)
fun Asn1Element.Companion.parseAll(input: ByteIterator): List<Asn1Element> =
    mutableListOf<Byte>().also { while (input.hasNext()) it.add(input.nextByte()) }.toByteArray().wrapInUnsafeSource()
        .readFullyToAsn1Elements().first

/**
 * Convenience wrapper around [parseAll], taking a [ByteArray] as [source]
 * @see parse
 */
@Throws(Asn1Exception::class)
fun Asn1Element.Companion.parseAll(source: ByteArray): List<Asn1Element> =
    source.wrapInUnsafeSource().readFullyToAsn1Elements().first

/**
 * Convenience wrapper around [parseFirst], taking a [ByteArray] as [source].
 * @return a pair of the first parsed [Asn1Element] mapped to the remaining bytes
 * @see readAsn1Element
 */
@Throws(Asn1Exception::class)
fun Asn1Element.Companion.parseFirst(source: ByteArray): Pair<Asn1Element, ByteArray> =
    source.wrapInUnsafeSource().readAsn1Element()
        .let { Pair(it.first, source.copyOfRange(it.second.toInt(), source.size)) }

private fun Source.doParseExactly(nBytes: Long): List<Asn1Element> = mutableListOf<Asn1Element>().also { list ->
    var nBytesRead: Long = 0
    while (nBytesRead < nBytes) {
        val peekTagAndLen = peekTagAndLen()
        val numberOfNextBytesRead = peekTagAndLen.second + peekTagAndLen.first.length
        if (nBytesRead + numberOfNextBytesRead > nBytes) break
        skip(peekTagAndLen.second.toLong()) // we only peeked before, so now we need to skip,
        //                                     since we want to recycle the result below
        val (elem, read) = readAsn1Element(peekTagAndLen.first, peekTagAndLen.second)
        list.add(elem)
        nBytesRead += read
    }
    require(nBytesRead == nBytes) { "Indicated length ($nBytes) does not correspond to an ASN.1 element boundary ($nBytesRead)" }
}

/**
 * Reads all parsable ASN.1 elements from this source.
 *
 * @throws Asn1Exception on error if any illegal element or any trailing bytes are encountered
 */
@Throws(Asn1Exception::class)
fun Source.readFullyToAsn1Elements(): Pair<List<Asn1Element>, Long> = mutableListOf<Asn1Element>().let { list ->
    var bytesRead = 0L
    while (!exhausted()) readAsn1Element().also { (elem, nBytes) ->
        bytesRead += nBytes
        list.add(elem)
    }
    Pair(list, bytesRead)
}

/**
 * Reads a [TagAndLength] and the number of consumed bytes from the source without consuming it
 */
private fun Source.peekTagAndLen() = peek().readTagAndLength()

/**
 * Decodes a single [Asn1Element] from this source.
 *
 * @return the decoded element and the number of bytes read from the source
 */
@Throws(Asn1Exception::class)
fun Source.readAsn1Element(): Pair<Asn1Element, Long> = runRethrowing {
    val (readTagAndLength, bytesRead) = readTagAndLength()
    readAsn1Element(readTagAndLength, bytesRead)
}

/**
 * RAW decoding of an ASN.1 element after tag and length have already been decoded and consumed from the source
 */
@Throws(Asn1Exception::class)
private fun Source.readAsn1Element(tagAndLength: TagAndLength, tagAndLengthBytes: Int): Pair<Asn1Element, Long> =
    runRethrowing {
        val (tag, length) = tagAndLength

        //ASN.1 SEQUENCE
        (if (tag.isSequence()) Asn1Sequence(doParseExactly(length))

        //ASN.1 SET
        else if (tag.isSet()) Asn1Set.fromPresorted(doParseExactly(length))

        //ASN.1 TAGGED (explicitly)
        else if (tag.isExplicitlyTagged) Asn1ExplicitlyTagged(tag.tagValue, doParseExactly(length))

        //ASN.1 OCTET STRING
        else if (tag == Asn1Element.Tag.OCTET_STRING) catching {
            //try to decode recursively
            Asn1EncapsulatingOctetString(peek().doParseExactly(length)).also { skip(length) } as Asn1Element
        }.getOrElse {
            //recursive decoding failed, so we interpret is as primitive
            require(length <= Int.MAX_VALUE) { "Cannot read more than ${Int.MAX_VALUE} into an OCTET STRING" }
            Asn1PrimitiveOctetString(readByteArray(length.toInt())) as Asn1Element
        }

        //IMPLICIT-ly TAGGED ASN.1 CONSTRUCTED; we don't know if it is a SET OF, SET, SEQUENCE,… so we default to sequence semantics
        else if (tag.isConstructed) Asn1CustomStructure(doParseExactly(length), tag.tagValue, tag.tagClass)

        //IMPLICIT-ly TAGGED ASN.1 PRIMITIVE
        else {
            require(length <= Int.MAX_VALUE) { "Cannot read more than ${Int.MAX_VALUE} into a primitive" }
            Asn1Primitive(tag, readByteArray(length.toInt())) as Asn1Element
        }) to length + tagAndLengthBytes
    }

private fun Asn1Element.Tag.isSet() = this == Asn1Element.Tag.SET
private fun Asn1Element.Tag.isSequence() = (this == Asn1Element.Tag.SEQUENCE)

/**
 * decodes this [Asn1Primitive]'s content into an [Boolean]. [assertTag] defaults to [Asn1Element.Tag.BOOL], but can be
 * overridden (for implicitly tagged booleans, for example)
 * @throws [Asn1Exception] all sorts of exceptions on invalid input
 */
@Throws(Asn1Exception::class)
fun Asn1Primitive.decodeToBoolean(assertTag: Asn1Element.Tag = Asn1Element.Tag.BOOL) =
    runRethrowing { decode(assertTag) { Boolean.decodeFromAsn1ContentBytes(it) } }

/** Exception-free version of [decodeToBoolean] */
fun Asn1Primitive.decodeToBooleanOrNull(assertTag: Asn1Element.Tag = Asn1Element.Tag.BOOL) =
    catching { decodeToBoolean(assertTag) }.getOrNull()

/**
 * decodes this [Asn1Primitive]'s content into an [Int]. [assertTag] defaults to [Asn1Element.Tag.INT], but can be
 *  overridden (for implicitly tagged integers, for example)
 * @throws [Asn1Exception] on invalid input
 */
@Throws(Asn1Exception::class)
fun Asn1Primitive.decodeToInt(assertTag: Asn1Element.Tag = Asn1Element.Tag.INT) =
    runRethrowing { decode(assertTag) { Int.decodeFromAsn1ContentBytes(it) } }

/** Exception-free version of [decodeToInt] */
fun Asn1Primitive.decodeToIntOrNull(assertTag: Asn1Element.Tag = Asn1Element.Tag.INT) =
    catching { decodeToInt(assertTag) }.getOrNull()

/**
 * decodes this [Asn1Primitive]'s content into a [Long]. [assertTag] defaults to [Asn1Element.Tag.INT], but can be
 * overridden (for implicitly tagged longs, for example)
 * @throws [Asn1Exception] on invalid input
 */
@Throws(Asn1Exception::class)
fun Asn1Primitive.decodeToLong(assertTag: Asn1Element.Tag = Asn1Element.Tag.INT) =
    runRethrowing { decode(assertTag) { Long.decodeFromAsn1ContentBytes(it) } }

/** Exception-free version of [decodeToLong] */
inline fun Asn1Primitive.decodeToLongOrNull(assertTag: Asn1Element.Tag = Asn1Element.Tag.INT) =
    catching { decodeToLong(assertTag) }.getOrNull()

/**
 * decodes this [Asn1Primitive]'s content into an [UInt]√. [assertTag] defaults to [Asn1Element.Tag.INT], but can be
 * overridden (for implicitly tagged unsigned integers, for example)
 * @throws [Asn1Exception] on invalid input
 */
@Throws(Asn1Exception::class)
fun Asn1Primitive.decodeToUInt(assertTag: Asn1Element.Tag = Asn1Element.Tag.INT) =
    runRethrowing { decode(assertTag) { UInt.decodeFromAsn1ContentBytes(it) } }

/** Exception-free version of [decodeToUInt] */
inline fun Asn1Primitive.decodeToUIntOrNull(assertTag: Asn1Element.Tag = Asn1Element.Tag.INT) =
    catching { decodeToUInt(assertTag) }.getOrNull()

/**
 * decodes this [Asn1Primitive]'s content into an [ULong]. [assertTag] defaults to [Asn1Element.Tag.INT], but can be
 * overridden (for implicitly tagged unsigned longs, for example)
 * @throws [Asn1Exception] on invalid input
 */
@Throws(Asn1Exception::class)
fun Asn1Primitive.decodeToULong(assertTag: Asn1Element.Tag = Asn1Element.Tag.INT) =
    runRethrowing { decode(assertTag) { ULong.decodeFromAsn1ContentBytes(it) } }

/** Exception-free version of [decodeToULong] */
inline fun Asn1Primitive.decodeToULongOrNull(assertTag: Asn1Element.Tag = Asn1Element.Tag.INT) =
    catching { decodeToULong(assertTag) }.getOrNull()

/** Decode the [Asn1Primitive] as a [Asn1Integer]
 * @throws [Asn1Exception] on invalid input */
@Throws(Asn1Exception::class)
fun Asn1Primitive.decodeToAsn1Integer(assertTag: Asn1Element.Tag = Asn1Element.Tag.INT) =
    runRethrowing { decode(assertTag) { Asn1Integer.decodeFromAsn1ContentBytes(it) } }

/** Exception-free version of [decodeToAsn1Integer] */
inline fun Asn1Primitive.decodeToAsn1IntegerOrNull(assertTag: Asn1Element.Tag = Asn1Element.Tag.INT) =
    catching { decodeToAsn1Integer() }.getOrNull()

/**
 * Decodes a [Asn1Integer] from [bytes] assuming the same encoding as the [Asn1Primitive.content] property of an [Asn1Primitive] containing an ASN.1 INTEGER
 */
@Throws(Asn1Exception::class)
fun Asn1Integer.Companion.decodeFromAsn1ContentBytes(bytes: ByteArray): Asn1Integer =
    runRethrowing { fromTwosComplement(bytes) }

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
fun Asn1Primitive.decodeToString() = runRethrowing { asAsn1String().value }

/** Exception-free version of [decodeToString] */
fun Asn1Primitive.decodeToStringOrNull() = catching { decodeToString() }.getOrNull()

/**
 * decodes this [Asn1Primitive]'s content into an [Instant] if it is encoded as UTC TIME or GENERALIZED TIME
 *
 * @throws Asn1Exception on invalid input
 */
@Throws(Asn1Exception::class)
fun Asn1Primitive.decodeToInstant() =
    when (tag) {
        Asn1Element.Tag.TIME_UTC -> decode(
            Asn1Element.Tag.TIME_UTC,
            Instant.Companion::decodeUtcTimeFromAsn1ContentBytes
        )

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
 * Generic decoding function. Verifies that this [Asn1Primitive]'s tag matches [assertTag]
 * and transforms its content as per [transform]
 * @throws Asn1Exception all sorts of exceptions on invalid input
 */
@Throws(Asn1Exception::class)
inline fun <reified T> Asn1Primitive.decode(assertTag: ULong, transform: (content: ByteArray) -> T): T =
    decode(Asn1Element.Tag(assertTag, constructed = false), transform)

/**
 * Generic decoding function. Verifies that this [Asn1Primitive]'s tag matches [assertTag]
 * and transforms its content as per [transform]
 * @throws Asn1Exception all sorts of exceptions on invalid input
 */
@Throws(Asn1Exception::class)
inline fun <reified T> Asn1Primitive.decode(assertTag: Asn1Element.Tag, transform: (content: ByteArray) -> T) =
    runRethrowing {
        if (assertTag.isConstructed) throw IllegalArgumentException("A primitive cannot have a CONSTRUCTED tag")
        if (assertTag != this.tag) throw Asn1TagMismatchException(assertTag, this.tag)
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

/**
 * [Asn1Element.Tag] to the decoded length
 */
private typealias TagAndLength = Pair<Asn1Element.Tag, Long>

private val TagAndLength.tag: Asn1Element.Tag get() = first
private val TagAndLength.length: Long get() = second

/**
 * Reads [TagAndLength] and the number of consumed bytes from the source
 */
private fun Source.readTagAndLength(): Pair<TagAndLength, Int> = runRethrowing {
    if (exhausted()) throw IllegalArgumentException("Can't read TLV, input empty")

    val tag = readAsn1Tag()
    val length = decodeLength()
    require(length.first >= 0L) { "Illegal length: $length" }
    return Pair((tag to length.first), (length.second + tag.encodedTagLength))
}

/**
 * Decodes the `length` of an ASN.1 element (which is preceded by its tag) from the source.
 * @return the decoded length and the number of bytes consumed
 */
@Throws(IllegalArgumentException::class)
private fun Source.decodeLength(): Pair<Long, Int> =
    readByte().let { firstByte ->
        if (firstByte.isBerShortForm()) {
            Pair(firstByte.toUByte().toLong(), 1)
        } else { // its BER long form!
            val numberOfLengthOctets = (firstByte byteMask 0x7F).toInt()
            (0 until numberOfLengthOctets).fold(0L) { acc, index ->
                require(!exhausted()) { "Can't decode length" }
                acc + (readUByte().toLong() shl Byte.SIZE_BITS * (numberOfLengthOctets - index - 1))
            }.let { Pair(it, 1 + numberOfLengthOctets) }
        }
    }

private fun Byte.isBerShortForm() = this byteMask 0x80 == 0x00.toUByte()

internal infix fun Byte.byteMask(mask: Int) = (this and mask.toUInt().toByte()).toUByte()

fun Source.readAsn1Tag(): Asn1Element.Tag =
    readByte().let { firstByte ->
        (firstByte byteMask 0x1F).let { tagNumber ->
            if (tagNumber <= 30U) Asn1Element.Tag(tagNumber.toULong(), byteArrayOf(firstByte))
            else decodeAsn1VarULong().let { (l, b) ->
                Asn1Element.Tag(l, byteArrayOf(firstByte, *b))
            }
        }
    }
