package at.asitplus.signum.indispensable.asn1

import at.asitplus.signum.indispensable.asn1.encoding.*
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import de.infix.testBalloon.framework.testSuite
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.shouldBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.*
import io.kotest.property.checkAll
import kotlinx.io.Buffer
import kotlinx.io.snapshot
import kotlin.math.ceil
import kotlin.random.Random

val UVarIntTest by testSuite {

    //TODO: buffer based tests with capped number of bytes test
    "UInts with trailing bytes" - {
        "manual" {
            val src = byteArrayOf(65, 0, 0, 0)
            src.decodeAsn1VarUInt().first shouldBe 65u
            val buf = src.wrapInUnsafeSource()
            buf.decodeAsn1VarUInt().first shouldBe 65u
            repeat(3){buf.readByte() shouldBe 0.toByte()}
            buf.exhausted().shouldBeTrue()
        }
        "automated -" {
            checkAll(Arb.uInt()) { int ->
                val rnd = Random.nextBytes(8)
                val src = int.toAsn1VarInt().asList() + rnd.asList()
                src.decodeAsn1VarUInt().first shouldBe int
                val buffer = src.toByteArray().wrapInUnsafeSource()
                buffer.decodeAsn1VarUInt().first shouldBe int
                rnd.forEach { it shouldBe buffer.readByte() }
                buffer.exhausted().shouldBeTrue()
            }
        }
    }

    "ULongs with trailing bytes" - {
        "manual" {
            val src = byteArrayOf(65, 0, 0, 0)
            src.decodeAsn1VarULong().first shouldBe 65uL
            val buf = src.wrapInUnsafeSource()
            buf.decodeAsn1VarULong().first shouldBe 65uL
            repeat(3){buf.readByte() shouldBe 0.toByte()}
            buf.exhausted().shouldBeTrue()
        }
        "automated -" {
            checkAll(Arb.uLong()) { long ->
                val rnd = Random.nextBytes(8)
                val src = long.toAsn1VarInt().asList() + rnd.asList()
                src.decodeAsn1VarULong().first shouldBe long

                val buffer = src.toByteArray().wrapInUnsafeSource()
                buffer.decodeAsn1VarULong().first shouldBe long
                rnd.forEach { it shouldBe buffer.readByte() }
                buffer.exhausted().shouldBeTrue()

            }
        }
    }

    "BigInts" - {
        "long-capped" {
            checkAll(Arb.uLong()) { long ->
                val uLongVarInt = long.toAsn1VarInt()
                val bigInteger = BigInteger.fromULong(long)
                val bigIntVarInt = bigInteger.toAsn1VarInt()

                bigIntVarInt shouldBe uLongVarInt
                Buffer().apply { writeAsn1VarInt(bigInteger) }.snapshot().toByteArray() shouldBe bigIntVarInt
                Buffer().apply { writeAsn1VarInt(long) }.snapshot().toByteArray() shouldBe uLongVarInt

                val rnd = Random.nextBytes(8)
                val src = uLongVarInt.asList() + rnd.asList()
                src.decodeAsn1VarBigInt().first shouldBe bigInteger


                val buffer = src.toByteArray().wrapInUnsafeSource()
                buffer.decodeAsn1VarBigInt().first shouldBe bigInteger
                rnd.forEach { it shouldBe buffer.readByte() }
                buffer.exhausted().shouldBeTrue()

            }
        }

        "larger" {
            checkAll(Arb.byteArray(Arb.positiveInt(1024), Arb.byte())) {
                val bigInt = BigInteger.fromByteArray(it, Sign.POSITIVE)
                val bigIntVarint = bigInt.toAsn1VarInt()
                val rnd = Random.nextBytes(33)
                val src = bigIntVarint.asList() + rnd
                    .asList()
                src.decodeAsn1VarBigInt().first shouldBe bigInt

                val buf = src.toByteArray().wrapInUnsafeSource()
                buf.decodeAsn1VarBigInt().first shouldBe bigInt
                rnd.forEach { it shouldBe buf.readByte() }
                buf.exhausted().shouldBeTrue()
            }
        }
    }

}

//old code for regeressiontests

/**
 * Decodes an ULong from bytes using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come. Trailing bytes are ignored.
 *
 * @return the decoded ULong and the underlying varint-encoded bytes as `ByteArray`
 * @throws IllegalArgumentException if the number is larger than [ULong.MAX_VALUE]
 */
@Throws(IllegalArgumentException::class)
private inline fun Iterable<Byte>.decodeAsn1VarULong(): Pair<ULong, ByteArray> = iterator().decodeAsn1VarULong()


/**
 * Decodes an ULong from bytes using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come. Trailing bytes are ignored.
 *
 * @return the decoded ULong and the underlying varint-encoded bytes as `ByteArray`
 * @throws IllegalArgumentException if the number is larger than [ULong.MAX_VALUE]
 */
@Throws(IllegalArgumentException::class)
private fun Iterator<Byte>.decodeAsn1VarULong(): Pair<ULong, ByteArray> {
    var offset = 0
    var result = 0uL
    val accumulator = mutableListOf<Byte>()
    while (hasNext()) {
        val current = next().toUByte()
        accumulator += current.toByte()
        if (current >= 0x80.toUByte()) {
            result = (current and 0x7F.toUByte()).toULong() or (result shl 7)
        } else {
            result = (current and 0x7F.toUByte()).toULong() or (result shl 7)
            break
        }
        if (++offset > ceil(ULong.SIZE_BYTES.toFloat() * 8f / 7f)) throw IllegalArgumentException("Tag number too Large do decode into ULong!")
    }

    return result to accumulator.toByteArray()
}

/**
 * Decodes an unsigned BigInteger from bytes using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come. Trailing bytes are ignored.
 *
 * @return the decoded unsigned BigInteger and the underlying varint-encoded bytes as `ByteArray`
 */
internal inline fun Iterable<Byte>.decodeAsn1VarBigInt(): Pair<BigInteger, ByteArray> = iterator().decodeAsn1VarBigInt()



/**
 * Decodes a BigInteger from bytes using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come. Trailing bytes are ignored.
 *
 * @return the decoded BigInteger and the underlying varint-encoded bytes as `ByteArray`
 */
private fun Iterator<Byte>.decodeAsn1VarBigInt(): Pair<BigInteger, ByteArray> {
    var result = BigInteger.ZERO
    val mask = BigInteger.fromUByte(0x7Fu)
    val accumulator = mutableListOf<Byte>()
    while (hasNext()) {
        val curByte = next()
        val current = BigInteger(curByte.toUByte().toInt())
        accumulator += curByte
        result = (current and mask) or (result shl 7)
        if (current < 0x80.toUByte()) break
    }

    return result to accumulator.toByteArray()
}


/**
 * Decodes an UInt from bytes using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come. Trailing bytes are ignored.
 *
 * @return the decoded UInt and the underlying varint-encoded bytes as `ByteArray`
 * @throws IllegalArgumentException if the number is larger than [UInt.MAX_VALUE]
 */
@Throws(IllegalArgumentException::class)
private inline fun Iterable<Byte>.decodeAsn1VarUInt(): Pair<UInt, ByteArray> = iterator().decodeAsn1VarUInt()

/**
 * Decodes an UInt from bytes using varint encoding as used within ASN.1: groups of seven bits are encoded into a byte,
 * while the highest bit indicates if more bytes are to come. Trailing bytes are ignored.
 *
 * @return the decoded UInt and the underlying varint-encoded bytes as `ByteArray`
 * @throws IllegalArgumentException if the number is larger than [UInt.MAX_VALUE]
 */
@Throws(IllegalArgumentException::class)
private fun Iterator<Byte>.decodeAsn1VarUInt(): Pair<UInt, ByteArray> {
    var offset = 0
    var result = 0u
    val accumulator = mutableListOf<Byte>()
    while (hasNext()) {
        val current = next().toUByte()
        accumulator += current.toByte()
        if (current >= 0x80.toUByte()) {
            result = (current and 0x7F.toUByte()).toUInt() or (result shl 7)
        } else {
            result = (current and 0x7F.toUByte()).toUInt() or (result shl 7)
            break
        }
        if (++offset > ceil(UInt.SIZE_BYTES.toFloat() * 8f / 7f)) throw IllegalArgumentException("Tag number too Large do decode into UInt!")
    }

    return result to accumulator.toByteArray()
}
