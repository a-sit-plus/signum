package at.asitplus.awesn1

import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.encoding.decode
import at.asitplus.catchingUnwrapped
import at.asitplus.awesn1.runRethrowing
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import com.ionspin.kotlin.bignum.integer.util.fromTwosComplementByteArray
import com.ionspin.kotlin.bignum.integer.util.toTwosComplementByteArray

private fun Asn1Integer.Sign.toBigIntegerSign() = when (this) {
    Asn1Integer.Sign.POSITIVE -> Sign.POSITIVE
    Asn1Integer.Sign.NEGATIVE -> Sign.NEGATIVE
}

private fun Sign.toAsn1IntegerSign() = when (this) {
    Sign.ZERO, Sign.POSITIVE -> Asn1Integer.Sign.POSITIVE
    Sign.NEGATIVE -> Asn1Integer.Sign.NEGATIVE
}

/** Converts the [Asn1Integer] to the corresponding [BigInteger]. */
fun Asn1Integer.toBigInteger(): BigInteger =
    BigInteger.fromByteArray(this.magnitude, this.sign.toBigIntegerSign())

/** Converts the [BigInteger] to the corresponding [Asn1Integer]. */
fun BigInteger.toAsn1Integer(): Asn1Integer =
    Asn1Integer.fromByteArray(this.toByteArray(), this.getSign().toAsn1IntegerSign())

/** Creates an INTEGER [Asn1Primitive] from [value] */
fun Asn1.Int(value: BigInteger) = value.encodeToAsn1Primitive()


/** Produces an INTEGER as [Asn1Primitive] */
fun BigInteger.encodeToAsn1Primitive() = Asn1Primitive(Asn1Element.Tag.INT, encodeToAsn1ContentBytes())


/** Encodes this number into a [ByteArray] using the same encoding as the [Asn1Primitive.content] property of an [Asn1Primitive] containing an ASN.1 INTEGER */
fun BigInteger.encodeToAsn1ContentBytes() = toTwosComplementByteArray()

/**
 * Decode the [Asn1Primitive] as a [BigInteger]. [assertTag] defaults to [Asn1Element.Tag.INT], but can be
 * overridden (for implicitly tagged integers, for example)
 * @throws [Asn1Exception] on invalid input
 */
@Throws(Asn1Exception::class)
fun Asn1Primitive.decodeToBigInteger(assertTag: Asn1Element.Tag = Asn1Element.Tag.INT) =
    runRethrowing { decode(assertTag) { BigInteger.decodeFromAsn1ContentBytes(it) } }

/** Exception-free version of [decodeToBigInteger] */
@Suppress("NOTHING_TO_INLINE")
inline fun Asn1Primitive.decodeToBigIntegerOrNull(assertTag: Asn1Element.Tag = Asn1Element.Tag.INT) =
    catchingUnwrapped { decodeToBigInteger(assertTag) }.getOrNull()

/**
 * Decodes a [BigInteger] from [bytes] assuming the same encoding as the [Asn1Primitive.content] property of an [Asn1Primitive] containing an ASN.1 INTEGER
 */
@Throws(Asn1Exception::class)
fun BigInteger.Companion.decodeFromAsn1ContentBytes(bytes: ByteArray): BigInteger =
    runRethrowing { fromTwosComplementByteArray(bytes) }
