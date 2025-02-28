package at.asitplus.signum.indispensable.asn1.encoding

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.encoding.Asn1.ExplicitlyTagged
import at.asitplus.signum.indispensable.asn1.encoding.Asn1.Sequence
import at.asitplus.signum.indispensable.asn1.encoding.Asn1.Set
import at.asitplus.signum.indispensable.asn1.encoding.Asn1.SetOf
import kotlinx.datetime.Instant

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
        catchingUnwrapped { Sequence(root) }.getOrNull()


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
    fun SetOrNull(root: Asn1TreeBuilder.() -> Unit) = catchingUnwrapped { Set(root) }.getOrNull()


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
    fun SetOfOrNull(root: Asn1TreeBuilder.() -> Unit) = catchingUnwrapped { SetOf(root) }.getOrNull()


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
        catchingUnwrapped { ExplicitlyTagged(tag, root) }.getOrNull()

    /**
     * Safe version on [ExplicitlyTagged], wrapping the result into a [KmmResult]
     */
    fun ExplicitlyTaggedSafe(tag: ULong, root: Asn1TreeBuilder.() -> Unit) =
        catching { ExplicitlyTagged(tag, root) }

    /** Creates an ENUMERATED [Asn1Primitive] from [ordinal]*/
    fun Enumerated(ordinal: Long) = Asn1Primitive(Asn1Element.Tag.ENUM, ordinal.encodeToAsn1ContentBytes())

    /** Creates an ENUMERATED [Asn1Primitive] from [ordinal]*/
    fun Enumerated(ordinal: Int) = Asn1Primitive(Asn1Element.Tag.ENUM, ordinal.encodeToAsn1ContentBytes())

    /** Creates an ENUMERATED [Asn1Primitive] from [enum] by encoding its ordinal*/
    fun Enumerated(enum: Enum<*>) = enum.encodeToAsn1Primitive()

    /**
     * Adds a BOOL [Asn1Primitive] to this ASN.1 structure
     */
    fun Bool(value: Boolean) = value.encodeToAsn1Primitive()

    /** Creates an INTEGER [Asn1Primitive] from [value] */
    fun Int(value: Int) = value.encodeToAsn1Primitive()

    /** Creates an INTEGER [Asn1Primitive] from [value] */
    fun Int(value: Long) = value.encodeToAsn1Primitive()

    /** Creates an INTEGER [Asn1Primitive] from [value] */
    fun Int(value: UInt) = value.encodeToAsn1Primitive()

    /** Creates an INTEGER [Asn1Primitive] from [value] */
    fun Int(value: ULong) = value.encodeToAsn1Primitive()

    /** Creates an INTEGER [Asn1Primitive] from [value] */
    fun Int(value: Asn1Integer) = value.encodeToAsn1Primitive()


    /** Creates an OCTET STRING [Asn1Element] from [bytes] */
    fun OctetString(bytes: ByteArray) = bytes.encodeToAsn1OctetStringPrimitive()


    /** Creates an BIT STRING [Asn1Primitive] from [bytes] */
    fun BitString(bytes: ByteArray) = bytes.encodeToAsn1BitStringPrimitive()


    /**
     * Creates an BIT STRING [Asn1Primitive] from [bitSet].
     * **Left-Aligned and right-padded (see [Asn1BitString])**
     */
    fun BitString(bitSet: BitSet) = Asn1BitString(bitSet).encodeToTlv()

    /** Creates an UTF8 STRING [Asn1Primitive] from [value] */
    fun Utf8String(value: String) = Asn1String.UTF8(value).encodeToTlv()


    /**
     * Creates a PRINTABLE STRING [Asn1Primitive] from [value].
     * @throws Asn1Exception if illegal characters are to be encoded into a printable string
     */
    @Throws(Asn1Exception::class)
    fun PrintableString(value: String) = Asn1String.Printable(value).encodeToTlv()


    /**
     * Create a NULL [Asn1Primitive]
     */
    fun Null() = Asn1Primitive(Asn1Element.Tag.NULL, byteArrayOf())


    /** Creates a UTC TIME [Asn1Primitive] from [value] */
    fun UtcTime(value: Instant) = value.encodeToAsn1UtcTimePrimitive()


    /** Creates a GENERALIZED TIME [Asn1Primitive] from [value]*/
    fun GeneralizedTime(value: Instant) = value.encodeToAsn1GeneralizedTimePrimitive()


    /**
     * OCTET STRING builder. The result of [init] is encapsulated into an ASN.1 OCTET STRING [Asn1Structure]
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
     * Shorthand for `Tag(tagValue, constructed=false, tagClass=TagClass.CONTEXT_SPECIFIC)`
     */
    fun ImplicitTag(tagNum: ULong, tagClass: TagClass = TagClass.CONTEXT_SPECIFIC) =
        Asn1Element.Tag(tagNum, constructed = false, tagClass = tagClass)

    /**
     * Convenience helper to easily construct explicitly tagged elements.
     * Shorthand for `Tag(tagValue, constructed=true, tagClass=TagClass.CONTEXT_SPECIFIC)`
     */
    fun ExplicitTag(tagNum: ULong) =
        Asn1Element.Tag(tagNum, constructed = true, tagClass = TagClass.CONTEXT_SPECIFIC)

}

/**
 * Produces a BOOLEAN as [Asn1Primitive]
 */
fun Boolean.encodeToAsn1Primitive() = Asn1Primitive(Asn1Element.Tag.BOOL, encodeToAsn1ContentBytes())

/** Produces an INTEGER as [Asn1Primitive] */
fun Int.encodeToAsn1Primitive() = Asn1Primitive(Asn1Element.Tag.INT, encodeToAsn1ContentBytes())

/** Produces an INTEGER as [Asn1Primitive] */
fun Long.encodeToAsn1Primitive() = Asn1Primitive(Asn1Element.Tag.INT, encodeToAsn1ContentBytes())

/** Produces an INTEGER as [Asn1Primitive] */
fun UInt.encodeToAsn1Primitive() = Asn1Primitive(Asn1Element.Tag.INT, encodeToAsn1ContentBytes())

/** Produces an INTEGER as [Asn1Primitive] */
fun ULong.encodeToAsn1Primitive() = Asn1Primitive(Asn1Element.Tag.INT, encodeToAsn1ContentBytes())

/** Encodes an ENUMERATED containing this Enum's ordinal as [Asn1Primitive] */
fun Enum<*>.encodeToAsn1Primitive() = Asn1Primitive(Asn1Element.Tag.ENUM, ordinal.encodeToAsn1ContentBytes())

/** Produces an INTEGER as [Asn1Primitive] */
fun Asn1Integer.encodeToAsn1Primitive() = Asn1Primitive(Asn1Element.Tag.INT, encodeToAsn1ContentBytes())

/** Produces a REAL as [Asn1Primitive] */
fun Asn1Real.encodeToAsn1Primitive() = Asn1Primitive(Asn1Element.Tag.REAL, encodeToAsn1ContentBytes())

/** Produces a REAL as [Asn1Primitive]
 * @throws Asn1Exception when passing [Double.NaN]
 * */
@Throws(Asn1Exception::class)
fun Double.encodeToAsn1Primitive() = Asn1Primitive(Asn1Element.Tag.REAL, Asn1Real(this).encodeToAsn1ContentBytes())

/** Exception-free version of [encodeToAsn1Primitive]*/
@Throws(Asn1Exception::class)
fun Double.encodeToAsn1PrimitiveOrNull() = catchingUnwrapped { encodeToAsn1Primitive() }.getOrNull()


/** Produces a REAL as [Asn1Primitive]
 * @throws Asn1Exception when passing [Float.NaN]
 * */
@Throws(Asn1Exception::class)
fun Float.encodeToAsn1Primitive() = Asn1Primitive(Asn1Element.Tag.REAL, Asn1Real(this.toDouble()).encodeToAsn1ContentBytes())

/** Exception-free version of [encodeToAsn1Primitive]*/
@Throws(Asn1Exception::class)
fun Float.encodeToAsn1PrimitiveOrNull() = catchingUnwrapped { encodeToAsn1Primitive() }.getOrNull()


/** Produces an ASN.1 UTF8 STRING as [Asn1Primitive] */
fun String.encodeToAsn1Primitive() = Asn1String.UTF8(this).encodeToTlv()

/**
 * Produces an OCTET STRING as [Asn1Primitive]
 */
fun ByteArray.encodeToAsn1OctetStringPrimitive() = Asn1PrimitiveOctetString(this)

/**
 * Produces a BIT STRING as [Asn1Primitive]
 */
fun ByteArray.encodeToAsn1BitStringPrimitive() =
    Asn1Primitive(Asn1Element.Tag.BIT_STRING, encodeToAsn1BitStringContentBytes())

/**
 * Prepends 0x00 to this ByteArray for encoding it into a BIT STRING. No inverse function is implemented, since `.drop(1)` does the job.
 */
fun ByteArray.encodeToAsn1BitStringContentBytes() = byteArrayOf(0x00) + this


/** Encodes this boolean into a [ByteArray] using the same encoding as the [Asn1Primitive.content] property of an [Asn1Primitive] containing an ASN.1 BOOLEAN */
fun Boolean.encodeToAsn1ContentBytes() = byteArrayOf(if (this) 0xff.toByte() else 0)

/** Encodes this number into a [ByteArray] using the same encoding as the [Asn1Primitive.content] property of an [Asn1Primitive] containing an ASN.1 INTEGER */
fun Int.encodeToAsn1ContentBytes() = toTwosComplementByteArray()

/** Encodes this number into a [ByteArray] using the same encoding as the [Asn1Primitive.content] property of an [Asn1Primitive] containing an ASN.1 INTEGER */
fun Long.encodeToAsn1ContentBytes() = toTwosComplementByteArray()

/** Encodes this number into a [ByteArray] using the same encoding as the [Asn1Primitive.content] property of an [Asn1Primitive] containing an ASN.1 INTEGER */
fun UInt.encodeToAsn1ContentBytes() = toTwosComplementByteArray()

/** Encodes this number into a [ByteArray] using the same encoding as the [Asn1Primitive.content] property of an [Asn1Primitive] containing an ASN.1 INTEGER */
fun ULong.encodeToAsn1ContentBytes() = toTwosComplementByteArray()

/** Encodes this Enum's ordinal into a [ByteArray] using the same encoding as the [Asn1Primitive.content] property of an [Asn1Primitive] containing an ASN.1 ENUMERATED */
fun Enum<*>.encodeToAsn1ContentBytes() = ordinal.encodeToAsn1ContentBytes()

/** Encodes this number into a [ByteArray] using the same encoding as the [Asn1Primitive.content] property of an [Asn1Primitive] containing an ASN.1 INTEGER */
fun Asn1Integer.encodeToAsn1ContentBytes() = twosComplement()

/**
 * Produces a UTC TIME as [Asn1Primitive]
 */
fun Instant.encodeToAsn1UtcTimePrimitive() =
    Asn1Primitive(Asn1Element.Tag.TIME_UTC, encodeToAsn1Time().drop(2).encodeToByteArray())

/**
 * Produces a GENERALIZED TIME as [Asn1Primitive]
 */
fun Instant.encodeToAsn1GeneralizedTimePrimitive() =
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

