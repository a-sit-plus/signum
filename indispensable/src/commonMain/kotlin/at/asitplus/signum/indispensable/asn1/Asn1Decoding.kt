package at.asitplus.signum.indispensable.asn1

import at.asitplus.catching
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
import kotlin.math.ceil


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
            else if (tlv.isSet()) result.add(Asn1Set.fromPresorted(Asn1Reader(tlv.content).doParse()))
            else if (tlv.isExplicitlyTagged()) result.add(
                Asn1Tagged(
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

        }
        return result
    }

    private fun TLV.isSet() = tag == Asn1Element.Tag.SET
    private fun TLV.isSequence() = (tag == Asn1Element.Tag.ASN1_SEQUENCE)
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
fun Asn1Primitive.readInt() = runRethrowing { decode(Asn1Element.Tag.INT) { Int.decodeFromDerValue(it) } }

/**
 * decodes this [Asn1Primitive]'s content into an [Boolean]
 *
 * @throws [Throwable] all sorts of exceptions on invalid input
 */
@Throws(Asn1Exception::class)
fun Asn1Primitive.readBool() = runRethrowing {
    decode(Asn1Element.Tag.BOOL) {
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
    decode(Asn1Element.Tag.INT) { BigInteger.fromTwosComplementByteArray(it) }

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
fun Asn1Primitive.readLong() = runRethrowing { decode(Asn1Element.Tag.INT) { Long.decodeFromDerValue(it) } }

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
    when (tag.tagValue) {
        UTF8_STRING.toULong() -> Asn1String.UTF8(content.decodeToString())
        UNIVERSAL_STRING.toULong() -> Asn1String.Universal(content.decodeToString())
        IA5_STRING.toULong() -> Asn1String.IA5(content.decodeToString())
        BMP_STRING.toULong() -> Asn1String.BMP(content.decodeToString())
        T61_STRING.toULong() -> Asn1String.Teletex(content.decodeToString())
        PRINTABLE_STRING.toULong() -> Asn1String.Printable(content.decodeToString())
        NUMERIC_STRING.toULong() -> Asn1String.Numeric(content.decodeToString())
        VISIBLE_STRING.toULong() -> Asn1String.Visible(content.decodeToString())
        else -> TODO("Support other string tag $tag")
    }
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
    when (tag) {
        Asn1Element.Tag.TIME_UTC -> decode(Asn1Element.Tag.TIME_UTC, Instant.Companion::decodeUtcTimeFromDer)
        Asn1Element.Tag.TIME_GENERALIZED -> decode(
            Asn1Element.Tag.TIME_GENERALIZED,
            Instant.Companion::decodeGeneralizedTimeFromDer
        )

        else -> TODO("Support time tag $tag")
    }

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
fun Asn1Primitive.readNull() = decode(Asn1Element.Tag.NULL) {}

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
fun Asn1Tagged.verifyTag(tag: ULong): List<Asn1Element> {
    val explicitTag = Asn1Element.Tag(tag, constructed = true, TagClass.CONTEXT_SPECIFIC)
    if (this.tag != explicitTag) throw Asn1TagMismatchException(explicitTag, this.tag)
    return this.children
}

/**
 * Exception-free version of [verifyTag]
 */
fun Asn1Tagged.verifyTagOrNull(tag: ULong) = catching { verifyTag(tag) }.getOrNull()


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
fun Int.Companion.decodeFromDerValue(input: ByteArray): Int = runRethrowing {
    if (input.size > 5) throw IllegalArgumentException("Absolute value too large!")
    return Long.decodeFromDerValue(input).toInt()
}

/**
 * @throws IllegalArgumentException if the byte array is too long to be parsed to a long (note that only rudimentary checking happens)
 */
@Throws(Asn1Exception::class)
fun Long.Companion.decodeFromDerValue(bytes: ByteArray): Long = runRethrowing {
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


@Throws(Asn1Exception::class)
private fun ByteArray.readTlv(): TLV = runRethrowing {
    if (this.isEmpty()) throw IllegalArgumentException("Can't read TLV, input empty")
    if (this.size == 1) return TLV(Asn1Element.Tag(byteArrayOf(this[0])), byteArrayOf())

    val iterator = iterator()
    val decodedTag = iterator.decodeTag()
    val tagLength = decodedTag.second.size
    val tagBytes = decodedTag.second
    val value = drop(tagLength).decodeValue()
    return TLV(Asn1Element.Tag(tagBytes), value.toByteArray())
}

@Throws(IllegalArgumentException::class)
private fun List<Byte>.decodeValue() =
    if (this[0].isBerShortForm()) {
        val length = getInt(0)
        require(size >= 1 + length) { "Out of bytes" }
        drop(1).take(length)
    } else { // its BER long form!
        val numberOfLengthOctets = (this[0] byteMask 0x7F).toInt()
        require(size >= numberOfLengthOctets + 1) { "Can't decode length" }
        val length = (numberOfLengthOctets downTo 1).fold(0) { acc, index ->
            acc + (getInt(index) shl Byte.SIZE_BITS * (numberOfLengthOctets - index))
        }
        drop(1 + numberOfLengthOctets).take(length)
    }

private fun Byte.isBerShortForm() = this byteMask 0x80 == 0x00.toUByte()

private fun List<Byte>.getInt(i: Int) = this[i].toUByte().toInt()

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


/**
 * Decodes an ULong from bytes using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come. Trailing bytes are ignored.
 *
 * @return the decoded ULong and the underlying varint-encoded bytes as `ByteArray`
 * @throws IllegalArgumentException if the number is larger than [ULong.MAX_VALUE]
 */
inline fun Iterable<Byte>.decodeAsn1VarULong(): Pair<ULong, ByteArray> = iterator().decodeAsn1VarULong()

/**
 * Decodes an ULong from bytes using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come. Trailing bytes are ignored.
 *
 * @return the decoded ULong and the underlying varint-encoded bytes as `ByteArray`
 * @throws IllegalArgumentException if the number is larger than [ULong.MAX_VALUE]
 */
inline fun ByteArray.decodeAsn1VarULong(): Pair<ULong, ByteArray> = iterator().decodeAsn1VarULong()

/**
 * Decodes an ULong from bytes using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come. Trailing bytes are ignored.
 *
 * @return the decoded ULong and the underlying varint-encoded bytes as `ByteArray`
 * @throws IllegalArgumentException if the number is larger than [ULong.MAX_VALUE]
 */
fun Iterator<Byte>.decodeAsn1VarULong(): Pair<ULong, ByteArray> {
    var offset = 0
    var result = 0uL
    val accumulator = mutableListOf<Byte>()
    while (hasNext()) {
        val current = next().toUByte()
        accumulator += current.toByte()
        if (offset == 0) result = (current and 0x7F.toUByte()).toULong()
        else if (current >= 0x80.toUByte()) {
            result = (current and 0x7F.toUByte()).toULong() or (result shl 7)
        } else {
            result = (current and 0x7F.toUByte()).toULong() or (result shl 7)
            break
        }
        if (++offset > ceil(ULong.SIZE_BYTES.toFloat() * 8f / 7f)) throw IllegalArgumentException("Tag number too Large do decode into ULong!")
    }

    return result to accumulator.toByteArray()
}


//TOOD: how to not duplicate all this???
/**
 * Decodes an UInt from bytes using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come. Trailing bytes are ignored.
 *
 * @return the decoded UInt and the underlying varint-encoded bytes as `ByteArray`
 * @throws IllegalArgumentException if the number is larger than [UInt.MAX_VALUE]
 */
inline fun Iterable<Byte>.decodeAsn1VarUInt(): Pair<UInt, ByteArray> = iterator().decodeAsn1VarUInt()

/**
 * Decodes an UInt from bytes using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come. Trailing bytes are ignored.
 *
 * @return the decoded UInt and the underlying varint-encoded bytes as `ByteArray`
 * @throws IllegalArgumentException if the number is larger than [UInt.MAX_VALUE]
 */
inline fun ByteArray.decodeAsn1VarUInt(): Pair<UInt, ByteArray> = iterator().decodeAsn1VarUInt()

/**
 * Decodes an UInt from bytes using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come. Trailing bytes are ignored.
 *
 * @return the decoded UInt and the underlying varint-encoded bytes as `ByteArray`
 * @throws IllegalArgumentException if the number is larger than [UInt.MAX_VALUE]
 */
fun Iterator<Byte>.decodeAsn1VarUInt(): Pair<UInt, ByteArray> {
    var offset = 0
    var result = 0u
    val accumulator = mutableListOf<Byte>()
    while (hasNext()) {
        val current = next().toUByte()
        accumulator += current.toByte()
        if (offset == 0) result = (current and 0x7F.toUByte()).toUInt()
        else if (current >= 0x80.toUByte()) {
            result = (current and 0x7F.toUByte()).toUInt() or (result shl 7)
        } else {
            result = (current and 0x7F.toUByte()).toUInt() or (result shl 7)
            break
        }
        if (++offset > ceil(UInt.SIZE_BYTES.toFloat() * 8f / 7f)) throw IllegalArgumentException("Tag number too Large do decode into UInt!")
    }

    return result to accumulator.toByteArray()
}
