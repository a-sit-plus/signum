package at.asitplus.signum.indispensable.asn1

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.io.BitSet
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.util.toTwosComplementByteArray
import kotlinx.datetime.Instant
import kotlin.experimental.or

/**
 * Class Providing a DSL for creating arbitrary ASN.1 structures. You will almost certainly never use it directly, but rather use it as follows:
 * ```kotlin
 * Sequence {
 *   +ExplicitlyTagged(1uL) {
 *     +Asn1Primitive(Asn1Element.Tag.BOOL, byteArrayOf(0x00)) //or +Asn1.Bool(false)
 *   }
 *   +Asn1.Set {
 *     +Asn1.Sequence {
 *       +Asn1.SetOf {
 *         +PrintableString("World")
 *         +PrintableString("Hello")
 *       }
 *       +Asn1.Set {
 *         +PrintableString("World")
 *         +PrintableString("Hello")
 *         +Utf8String("!!!")
 *       }
 *
 *     }
 *   }
 *   +Asn1.Null()
 *
 *   +ObjectIdentifier("1.2.603.624.97")
 *
 *   +(Utf8String("Foo") withImplicitTag (0xCAFEuL withClass TagClass.PRIVATE))
 *   +PrintableString("Bar")
 *
 *   //fake Primitive
 *   +(Asn1.Sequence { +Asn1.Int(42) } withImplicitTag (0x5EUL without CONSTRUCTED))
 *
 *   +Asn1.Set {
 *     +Asn1.Int(3)
 *     +Asn1.Int(-65789876543L)
 *     +Asn1.Bool(false)
 *     +Asn1.Bool(true)
 *   }
 *   +Asn1.Sequence {
 *     +Asn1.Null()
 *     +Asn1String.Numeric("12345")
 *     +UtcTime(Clock.System.now())
 *   }
 * } withImplicitTag (1337uL withClass TagClass.APPLICATION)
 * ```
 */
class Asn1TreeBuilder {
    internal val elements = mutableListOf<Asn1Element>()

    /**
     * appends a single [Asn1Element] to this ASN.1 structure
     */
    operator fun Asn1Element.unaryPlus() {
        elements += this
    }

    /**
     * appends a single [Asn1Encodable] to this ASN.1 structure
     * @throws Asn1Exception in case encoding constraints of children are violated
     */
    @Throws(Asn1Exception::class)
    operator fun Asn1Encodable<*>.unaryPlus() {
        +encodeToTlv()
    }
}

/**
 * Namespace object for ASN.1 builder DSL functions and utility functions for creating ASN.1 primitives
 */
object Asn1 {
    /**
     * Creates a new SEQUENCE as [Asn1Sequence].
     * Use as follows:
     *
     * ```kotlin
     * Sequence {
     *   +Null()
     *   +PrintableString("World")
     *   +PrintableString("Hello")
     *   +Utf8String("!!!")
     * }
     *  ```
     */
    fun Sequence(root: Asn1TreeBuilder.() -> Unit): Asn1Sequence {
        val seq = Asn1TreeBuilder()
        seq.root()
        return Asn1Sequence(seq.elements)
    }


    /**
     * Exception-free version of [Sequence]
     */
    fun SequenceOrNull(root: Asn1TreeBuilder.() -> Unit) =
        catching { Sequence(root) }.getOrNull()


    /**
     * Safe version of [Sequence], wrapping the result into a [KmmResult]
     */
    fun SequenceSafe(root: Asn1TreeBuilder.() -> Unit) = catching { Sequence(root) }


    /**
     * Creates a new  SET as [Asn1Set]. Elements are sorted by tag.
     * Use as follows:
     *
     * ```kotlin
     * Set {
     *   +Null()
     *   +PrintableString("World")
     *   +PrintableString("Hello")
     *   +Utf8String("!!!")
     * }
     *  ```
     */
    fun Set(root: Asn1TreeBuilder.() -> Unit): Asn1Set {
        val seq = Asn1TreeBuilder()
        seq.root()
        return Asn1Set(seq.elements)
    }

    /**
     * Exception-free version of [Set]
     */
    fun SetOrNull(root: Asn1TreeBuilder.() -> Unit) = catching { Set(root) }.getOrNull()


    /**
     * Safe version of [Set], wrapping the result into a [KmmResult]
     */
    fun SetSafe(root: Asn1TreeBuilder.() -> Unit) = catching { Set(root) }


    /**
     * Creates a new SET OF as [Asn1Set]. Tags of all added elements need to be the same. Elements are sorted by encoded value
     * Use as follows:
     *
     * ```kotlin
     * SetOf {
     *   +PrintableString("World")
     *   +PrintableString("!!!")
     *   +PrintableString("Hello")
     * }
     *  ```
     *
     *  @throws Asn1Exception if children of different tags are added
     */
    @Throws(Asn1Exception::class)
    fun SetOf(root: Asn1TreeBuilder.() -> Unit): Asn1Set {
        val seq = Asn1TreeBuilder()
        seq.root()
        return Asn1SetOf(seq.elements)
    }

    /**
     * Exception-free version of [SetOf]
     */
    fun SetOfOrNull(root: Asn1TreeBuilder.() -> Unit) = catching { SetOf(root) }.getOrNull()


    /**
     * Safe version of [SetOf], wrapping the result into a [KmmResult]
     */
    fun SetOfSafe(root: Asn1TreeBuilder.() -> Unit) = catching { SetOf(root) }


    /**
     * Creates a new EXPLICITLY TAGGED ASN.1 structure as [Asn1ExplicitlyTagged] using [tag].
     *
     * Use as follows:
     *
     * ```kotlin
     * ExplicitlyTagged(2uL) {
     *   +PrintableString("World World")
     *   +Null()
     *   +Int(1337)
     * }
     *  ```
     */
    fun ExplicitlyTagged(tag: ULong, root: Asn1TreeBuilder.() -> Unit): Asn1ExplicitlyTagged {
        val seq = Asn1TreeBuilder()
        seq.root()
        return Asn1ExplicitlyTagged(tag, seq.elements)
    }

    /**
     * Exception-free version of [ExplicitlyTagged]
     */
    fun ExplicitlyTaggedOrNull(tag: ULong, root: Asn1TreeBuilder.() -> Unit) =
        catching { ExplicitlyTagged(tag, root) }.getOrNull()

    /**
     * Safe version on [ExplicitlyTagged], wrapping the result into a [KmmResult]
     */
    fun ExplicitlyTaggedSafe(tag: ULong, root: Asn1TreeBuilder.() -> Unit) =
        catching { ExplicitlyTagged(tag, root) }


    /**
     * Adds a BOOL [Asn1Primitive] to this ASN.1 structure
     */
    fun Bool(value: Boolean) = value.encodeToTlv()


    /** Adds an INTEGER [Asn1Primitive] to this ASN.1 structure */
    fun Int(value: Int) = value.encodeToTlv()

    /** Adds an INTEGER [Asn1Primitive] to this ASN.1 structure */
    fun Int(value: Long) = value.encodeToTlv()

    /** Adds an INTEGER [Asn1Primitive] to this ASN.1 structure */
    fun Int(value: UInt) = value.encodeToTlv()

    /** Adds an INTEGER [Asn1Primitive] to this ASN.1 structure */
    fun Int(value: ULong) = value.encodeToTlv()

    /** Adds an INTEGER [Asn1Primitive] to this ASN.1 structure */
    fun Int(value: BigInteger) = value.encodeToTlv()


    /**
     * Adds the passed bytes as OCTET STRING [Asn1Element] to this ASN.1 structure
     */
    fun OctetString(bytes: ByteArray) = bytes.encodeToTlvOctetString()


    /**
     * Adds the passed bytes as BIT STRING [Asn1Primitive] to this ASN.1 structure
     */
    fun BitString(bytes: ByteArray) = bytes.encodeToTlvBitString()


    /**
     * Transforms the passed BitSet as BIT STRING [Asn1Primitive] to this ASN.1 structure.
     * **Left-Aligned and right-padded (see [Asn1BitString])**
     */
    fun BitString(bitSet: BitSet) = Asn1BitString(bitSet).encodeToTlv()

    /**
     * Adds the passed string as UTF8 STRING [Asn1Primitive] to this ASN.1 structure
     */
    fun Utf8String(value: String) = Asn1String.UTF8(value).encodeToTlv()


    /**
     * Adds the passed string as PRINTABLE STRING [Asn1Primitive] to this ASN.1 structure
     *
     * @throws Asn1Exception if illegal characters are to be encoded into a printable string
     */
    @Throws(Asn1Exception::class)
    fun PrintableString(value: String) = Asn1String.Printable(value).encodeToTlv()


    /**
     * Adds a NULL [Asn1Primitive] to this ASN.1 structure
     */
    fun Null() = Asn1Primitive(Asn1Element.Tag.NULL, byteArrayOf())


    /**
     * Adds the passed instant as UTC TIME [Asn1Primitive] to this ASN.1 structure
     */
    fun UtcTime(value: Instant) = value.encodeToAsn1UtcTime()


    /**
     * Adds the passed instant as GENERALIZED TIME [Asn1Primitive] to this ASN.1 structure
     */
    fun GeneralizedTime(value: Instant) = value.encodeToAsn1GeneralizedTime()


    /**
     * OCTET STRING builder. The result of [init] is encapsulated into an ASN.1 OCTET STRING and then added to this ASN.1 structure
     * ```kotlin
     *   OctetStringEncapsulating {
     *       +PrintableString("Hello")
     *       +PrintableString("World")
     *       +Sequence {
     *         +PrintableString("World")
     *         +PrintableString("Hello")
     *         +Utf8String("!!!")
     *       }
     *     }
     *  ```
     */
    fun OctetStringEncapsulating(init: Asn1TreeBuilder.() -> Unit): Asn1EncapsulatingOctetString {
        val seq = Asn1TreeBuilder()
        seq.init()
        return Asn1EncapsulatingOctetString(seq.elements)
    }

    /**
     * Convenience helper to easily construct implicitly tagged elements.
     * Shorthand for `Tag(tagValue, constructed=false, tagClass=TagClass.CONTEXT_SPECIFIC)
     */
    fun ImplicitTag(tagNum: ULong, tagClass: TagClass = TagClass.CONTEXT_SPECIFIC) =
        Asn1Element.Tag(tagNum, constructed = false, tagClass = tagClass)

    /**
     * Convenience helper to easily construct implicitly tagged elements.
     * Shorthand for `Tag(tagValue, constructed=true, tagClass=TagClass.CONTEXT_SPECIFIC)
     */
    fun ExplicitTag(tagNum: ULong) =
        Asn1Element.Tag(tagNum, constructed = true, tagClass = TagClass.CONTEXT_SPECIFIC)

}

/**
 * Produces a BOOLEAN as [Asn1Primitive]
 */
fun Boolean.encodeToTlv() = Asn1Primitive(Asn1Element.Tag.BOOL, byteArrayOf(if (this) 0xff.toByte() else 0))

/** Produces an INTEGER as [Asn1Primitive] */
fun Int.encodeToTlv() = Asn1Primitive(Asn1Element.Tag.INT, encodeToDer())

/** Produces an INTEGER as [Asn1Primitive] */
fun Long.encodeToTlv() = Asn1Primitive(Asn1Element.Tag.INT, encodeToDer())

/** Produces an INTEGER as [Asn1Primitive] */
fun UInt.encodeToTlv() = Asn1Primitive(Asn1Element.Tag.INT, encodeToDer())

/** Produces an INTEGER as [Asn1Primitive] */
fun ULong.encodeToTlv() = Asn1Primitive(Asn1Element.Tag.INT, encodeToDer())

/** Produces an INTEGER as [Asn1Primitive] */
fun BigInteger.encodeToTlv() = Asn1Primitive(Asn1Element.Tag.INT, encodeToDer())

/**
 * Produces an OCTET STRING as [Asn1Primitive]
 */
fun ByteArray.encodeToTlvOctetString() = Asn1PrimitiveOctetString(this)

/**
 * Produces a BIT STRING as [Asn1Primitive]
 */
fun ByteArray.encodeToTlvBitString() = Asn1Primitive(Asn1Element.Tag.BIT_STRING, encodeToBitString())

/**
 * Prepends 0x00 to this ByteArray for encoding it into a BIT STRING. Useful for implicit tagging
 */
fun ByteArray.encodeToBitString() = byteArrayOf(0x00) + this

private fun Int.encodeToDer() = toTwosComplementByteArray()
private fun Long.encodeToDer() = toTwosComplementByteArray()
private fun UInt.encodeToDer() = toTwosComplementByteArray()
private fun ULong.encodeToDer() = toTwosComplementByteArray()
private fun BigInteger.encodeToDer() = toTwosComplementByteArray()

/**
 * Produces a UTC TIME as [Asn1Primitive]
 */
fun Instant.encodeToAsn1UtcTime() =
    Asn1Primitive(Asn1Element.Tag.TIME_UTC, encodeToAsn1Time().drop(2).encodeToByteArray())

/**
 * Produces a GENERALIZED TIME as [Asn1Primitive]
 */
fun Instant.encodeToAsn1GeneralizedTime() =
    Asn1Primitive(Asn1Element.Tag.TIME_GENERALIZED, encodeToAsn1Time().encodeToByteArray())

private fun Instant.encodeToAsn1Time(): String {
    val value = this.toString()
    if (value.isEmpty())
        throw IllegalArgumentException("Instant serialization failed: no value")
    val matchResult = Regex("([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})")
        .matchAt(value, 0)
        ?: throw IllegalArgumentException("Instant serialization failed: $value")
    val year = matchResult.groups[1]?.value
        ?: throw IllegalArgumentException("Instant serialization year failed: $value")
    val month = matchResult.groups[2]?.value
        ?: throw IllegalArgumentException("Instant serialization month failed: $value")
    val day = matchResult.groups[3]?.value
        ?: throw IllegalArgumentException("Instant serialization day failed: $value")
    val hour = matchResult.groups[4]?.value
        ?: throw IllegalArgumentException("Instant serialization hour failed: $value")
    val minute = matchResult.groups[5]?.value
        ?: throw IllegalArgumentException("Instant serialization minute failed: $value")
    val seconds = matchResult.groups[6]?.value
        ?: throw IllegalArgumentException("Instant serialization seconds failed: $value")
    return "$year$month$day$hour$minute$seconds" + "Z"
}

/**
 * Encode as a four-byte array
 */
fun Int.encodeTo4Bytes(): ByteArray = byteArrayOf(
    (this ushr 24).toByte(),
    (this ushr 16).toByte(),
    (this ushr 8).toByte(),
    (this).toByte()
)

/**
 * Encode as an eight-byte array
 */
fun Long.encodeTo8Bytes(): ByteArray = byteArrayOf(
    (this ushr 56).toByte(),
    (this ushr 48).toByte(),
    (this ushr 40).toByte(),
    (this ushr 32).toByte(),
    (this ushr 24).toByte(),
    (this ushr 16).toByte(),
    (this ushr 8).toByte(),
    (this).toByte()
)

/** Encodes an unsigned Long to a minimum-size twos-complement byte array */
fun ULong.toTwosComplementByteArray() = when {
    this >= 0x8000000000000000UL ->
        byteArrayOf(
            0x00,
            (this shr 56).toByte(),
            (this shr 48).toByte(),
            (this shr 40).toByte(),
            (this shr 32).toByte(),
            (this shr 24).toByte(),
            (this shr 16).toByte(),
            (this shr 8).toByte(),
            this.toByte()
        )

    else -> this.toLong().toTwosComplementByteArray()
}

/** Encodes an unsigned Int to a minimum-size twos-complement byte array */
fun UInt.toTwosComplementByteArray() = toLong().toTwosComplementByteArray()

/** Encodes a signed Long to a minimum-size twos-complement byte array */
fun Long.toTwosComplementByteArray() = when {
    (this >= -0x80L && this <= 0x7FL) ->
        byteArrayOf(
            this.toByte()
        )

    (this >= -0x8000L && this <= 0x7FFFL) ->
        byteArrayOf(
            (this ushr 8).toByte(),
            this.toByte()
        )

    (this >= -0x800000L && this <= 0x7FFFFFL) ->
        byteArrayOf(
            (this ushr 16).toByte(),
            (this ushr 8).toByte(),
            this.toByte()
        )

    (this >= -0x80000000L && this <= 0x7FFFFFFFL) ->
        byteArrayOf(
            (this ushr 24).toByte(),
            (this ushr 16).toByte(),
            (this ushr 8).toByte(),
            this.toByte()
        )

    (this >= -0x8000000000L && this <= 0x7FFFFFFFFFL) ->
        byteArrayOf(
            (this ushr 32).toByte(),
            (this ushr 24).toByte(),
            (this ushr 16).toByte(),
            (this ushr 8).toByte(),
            this.toByte()
        )

    (this >= -0x800000000000L && this <= 0x7FFFFFFFFFFFL) ->
        byteArrayOf(
            (this ushr 40).toByte(),
            (this ushr 32).toByte(),
            (this ushr 24).toByte(),
            (this ushr 16).toByte(),
            (this ushr 8).toByte(),
            this.toByte()
        )

    (this >= -0x80000000000000L && this <= 0x7FFFFFFFFFFFFFL) ->
        byteArrayOf(
            (this ushr 48).toByte(),
            (this ushr 40).toByte(),
            (this ushr 32).toByte(),
            (this ushr 24).toByte(),
            (this ushr 16).toByte(),
            (this ushr 8).toByte(),
            this.toByte()
        )

    else ->
        byteArrayOf(
            (this ushr 56).toByte(),
            (this ushr 48).toByte(),
            (this ushr 40).toByte(),
            (this ushr 32).toByte(),
            (this ushr 24).toByte(),
            (this ushr 16).toByte(),
            (this ushr 8).toByte(),
            this.toByte()
        )
}

/** Encodes a signed Int to a minimum-size twos-complement byte array */
fun Int.toTwosComplementByteArray() = toLong().toTwosComplementByteArray()

fun Int.Companion.fromTwosComplementByteArray(it: ByteArray) = when (it.size) {
    4 -> (it[0].toInt() shl 24) or (it[1].toUByte().toInt() shl 16) or (it[2].toUByte()
        .toInt() shl 8) or (it[3].toUByte().toInt())

    3 -> (it[0].toInt() shl 16) or (it[1].toUByte().toInt() shl 8) or (it[2].toUByte().toInt())
    2 -> (it[0].toInt() shl 8) or (it[1].toUByte().toInt() shl 0)
    1 -> (it[0].toInt())
    else -> throw IllegalArgumentException("Input with size $it is out of bounds for Int")
}

fun UInt.Companion.fromTwosComplementByteArray(it: ByteArray) =
    Long.fromTwosComplementByteArray(it).let {
        require((0 <= it) && (it <= 0xFFFFFFFFL)) { "Value $it is out of bounds for UInt" }
        it.toUInt()
    }

fun Long.Companion.fromTwosComplementByteArray(it: ByteArray) = when (it.size) {
    8 -> (it[0].toLong() shl 56) or (it[1].toUByte().toLong() shl 48) or (it[2].toUByte().toLong() shl 40) or
            (it[3].toUByte().toLong() shl 32) or (it[4].toUByte().toLong() shl 24) or
            (it[5].toUByte().toLong() shl 16) or (it[6].toUByte().toLong() shl 8) or (it[7].toUByte().toLong())

    7 -> (it[0].toLong() shl 48) or (it[1].toUByte().toLong() shl 40) or (it[2].toUByte().toLong() shl 32) or
            (it[3].toUByte().toLong() shl 24) or (it[4].toUByte().toLong() shl 16) or
            (it[5].toUByte().toLong() shl 8) or (it[6].toUByte().toLong())

    6 -> (it[0].toLong() shl 40) or (it[1].toUByte().toLong() shl 32) or (it[2].toUByte().toLong() shl 24) or
            (it[3].toUByte().toLong() shl 16) or (it[4].toUByte().toLong() shl 8) or (it[5].toUByte().toLong())

    5 -> (it[0].toLong() shl 32) or (it[1].toUByte().toLong() shl 24) or (it[2].toUByte().toLong() shl 16) or
            (it[3].toUByte().toLong() shl 8) or (it[4].toUByte().toLong())

    4 -> (it[0].toLong() shl 24) or (it[1].toUByte().toLong() shl 16) or (it[2].toUByte().toLong() shl 8) or
            (it[3].toUByte().toLong())

    3 -> (it[0].toLong() shl 16) or (it[1].toUByte().toLong() shl 8) or (it[2].toUByte().toLong())
    2 -> (it[0].toLong() shl 8) or (it[1].toUByte().toLong() shl 0)
    1 -> (it[0].toLong())
    else -> throw IllegalArgumentException("Input with size $it is out of bounds for Long")
}

fun ULong.Companion.fromTwosComplementByteArray(it: ByteArray) = when {
    ((it.size == 9) && (it[0] == 0.toByte())) ->
        (it[1].toUByte().toULong() shl 56) or (it[2].toUByte().toULong() shl 48) or (it[3].toUByte()
            .toULong() shl 40) or
                (it[4].toUByte().toULong() shl 32) or (it[5].toUByte().toULong() shl 24) or
                (it[6].toUByte().toULong() shl 16) or (it[7].toUByte().toULong() shl 8) or
                (it[8].toUByte().toULong())

    else -> Long.fromTwosComplementByteArray(it).let {
        require(it >= 0) { "Value $it is out of bounds for ULong" }
        it.toULong()
    }
}

/** Encodes an unsigned Long to a minimum-size unsigned byte array */
fun Long.toUnsignedByteArray(): ByteArray {
    require(this >= 0)
    return this.toTwosComplementByteArray().let {
        if (it[0] == 0.toByte()) it.copyOfRange(1, it.size)
        else it
    }
}

/** Encodes an unsigned Int to a minimum-size unsigned byte array */
fun Int.toUnsignedByteArray() = toLong().toUnsignedByteArray()

/**
 * Drops bytes at the start, or adds zero bytes at the start, until the [size] is reached
 */
fun ByteArray.ensureSize(size: Int): ByteArray = (this.size - size).let { toDrop ->
    when {
        toDrop > 0 -> this.copyOfRange(toDrop, this.size)
        toDrop < 0 -> ByteArray(-toDrop) + this
        else -> this
    }
}

@Suppress("NOTHING_TO_INLINE")
inline fun ByteArray.ensureSize(size: UInt) = ensureSize(size.toInt())

/**
 * Encodes this number using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come
 */
fun ULong.toAsn1VarInt(): ByteArray {
    if (this < 128u) return byteArrayOf(this.toByte()) //Fast case
    var offset = 0
    var result = mutableListOf<Byte>()

    var b0 = (this shr offset and 0x7FuL).toByte()
    while ((this shr offset > 0uL) || offset == 0) {
        result += b0
        offset += 7
        if (offset > (ULong.SIZE_BITS - 1)) break //End of Fahnenstange
        b0 = (this shr offset and 0x7FuL).toByte()
    }

    return with(result) {
        ByteArray(size) { fromBack(it) or asn1VarIntByteMask(it) }
    }
}

//TODO: how to not duplicate this withut wasting bytes?
/**
 * Encodes this number using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come
 */
fun UInt.toAsn1VarInt(): ByteArray {
    if (this < 128u) return byteArrayOf(this.toByte()) //Fast case
    var offset = 0
    var result = mutableListOf<Byte>()

    var b0 = (this shr offset and 0x7Fu).toByte()
    while ((this shr offset > 0u) || offset == 0) {
        result += b0
        offset += 7
        if (offset > (UInt.SIZE_BITS - 1)) break //End of Fahnenstange
        b0 = (this shr offset and 0x7Fu).toByte()
    }

    return with(result) {
        ByteArray(size) { fromBack(it) or asn1VarIntByteMask(it) }
    }
}

private fun MutableList<Byte>.asn1VarIntByteMask(it: Int) = (if (isLastIndex(it)) 0x00 else 0x80).toByte()

private fun MutableList<Byte>.isLastIndex(it: Int) = it == size - 1

private fun MutableList<Byte>.fromBack(it: Int) = this[size - 1 - it]
