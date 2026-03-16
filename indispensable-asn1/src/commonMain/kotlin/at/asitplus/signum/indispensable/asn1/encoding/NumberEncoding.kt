@file:Suppress("unused", "NOTHING_TO_INLINE")

package at.asitplus.signum.indispensable.asn1.encoding

import at.asitplus.awesn1.encoding.decodeAsn1VarBigInt as awesn1DecodeAsn1VarBigInt
import at.asitplus.awesn1.encoding.decodeAsn1VarUInt as awesn1DecodeAsn1VarUInt
import at.asitplus.awesn1.encoding.decodeAsn1VarULong as awesn1DecodeAsn1VarULong
import at.asitplus.awesn1.encoding.encodeTo4Bytes as awesn1EncodeTo4Bytes
import at.asitplus.awesn1.encoding.encodeTo8Bytes as awesn1EncodeTo8Bytes
import at.asitplus.awesn1.encoding.toAsn1VarInt as awesn1ToAsn1VarInt
import at.asitplus.awesn1.encoding.toTwosComplementByteArray as awesn1ToTwosComplementByteArray
import at.asitplus.awesn1.encoding.toUnsignedByteArray as awesn1ToUnsignedByteArray
import at.asitplus.awesn1.io.decodeAsn1VarBigInt as awesn1SourceDecodeAsn1VarBigInt
import at.asitplus.awesn1.io.decodeAsn1VarUInt as awesn1SourceDecodeAsn1VarUInt
import at.asitplus.awesn1.io.decodeAsn1VarULong as awesn1SourceDecodeAsn1VarULong
import at.asitplus.awesn1.io.readTwosComplementInt as awesn1ReadTwosComplementInt
import at.asitplus.awesn1.io.readTwosComplementLong as awesn1ReadTwosComplementLong
import at.asitplus.awesn1.io.readTwosComplementUInt as awesn1ReadTwosComplementUInt
import at.asitplus.awesn1.io.readTwosComplementULong as awesn1ReadTwosComplementULong
import at.asitplus.awesn1.io.writeAsn1VarInt as awesn1WriteAsn1VarInt
import at.asitplus.awesn1.io.writeMagnitudeLong as awesn1WriteMagnitudeLong
import at.asitplus.awesn1.io.writeTwosComplementLong as awesn1WriteTwosComplementLong
import at.asitplus.awesn1.io.writeTwosComplementUInt as awesn1WriteTwosComplementUInt
import at.asitplus.awesn1.io.writeTwosComplementULong as awesn1WriteTwosComplementULong
import at.asitplus.signum.indispensable.asn1.Asn1Integer
import at.asitplus.signum.indispensable.asn1.wrapInUnsafeSource
import kotlinx.io.Sink
import kotlinx.io.Source

internal const val UVARINT_SINGLEBYTE_MAXVALUE: Byte = 0x80.toByte()
internal const val UVARINT_MASK_UBYTE: UByte = 0x7Fu

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.encodeTo4Bytes().",
    ReplaceWith("at.asitplus.awesn1.encoding.encodeTo4Bytes(this)")
)
fun Int.encodeTo4Bytes(): ByteArray = awesn1EncodeTo4Bytes()

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.encodeTo8Bytes().",
    ReplaceWith("at.asitplus.awesn1.encoding.encodeTo8Bytes(this)")
)
fun Long.encodeTo8Bytes(): ByteArray = awesn1EncodeTo8Bytes()

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.toTwosComplementByteArray().",
    ReplaceWith("at.asitplus.awesn1.encoding.toTwosComplementByteArray(this)")
)
fun ULong.toTwosComplementByteArray(): ByteArray = awesn1ToTwosComplementByteArray()

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.toTwosComplementByteArray().",
    ReplaceWith("at.asitplus.awesn1.encoding.toTwosComplementByteArray(this)")
)
fun UInt.toTwosComplementByteArray(): ByteArray = awesn1ToTwosComplementByteArray()

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.toTwosComplementByteArray().",
    ReplaceWith("at.asitplus.awesn1.encoding.toTwosComplementByteArray(this)")
)
fun Long.toTwosComplementByteArray(): ByteArray = awesn1ToTwosComplementByteArray()

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.toTwosComplementByteArray().",
    ReplaceWith("at.asitplus.awesn1.encoding.toTwosComplementByteArray(this)")
)
fun Int.toTwosComplementByteArray(): ByteArray = awesn1ToTwosComplementByteArray()

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.fromTwosComplementByteArray().",
    ReplaceWith("Int.fromTwosComplementByteArray(it)", "at.asitplus.awesn1.encoding.fromTwosComplementByteArray")
)
fun Int.Companion.fromTwosComplementByteArray(it: ByteArray): Int =
    it.wrapInUnsafeSource().awesn1ReadTwosComplementInt(it.size)

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.fromTwosComplementByteArray().",
    ReplaceWith("UInt.fromTwosComplementByteArray(it)", "at.asitplus.awesn1.encoding.fromTwosComplementByteArray")
)
fun UInt.Companion.fromTwosComplementByteArray(it: ByteArray): UInt =
    it.wrapInUnsafeSource().awesn1ReadTwosComplementUInt(it.size)

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.fromTwosComplementByteArray().",
    ReplaceWith("Long.fromTwosComplementByteArray(it)", "at.asitplus.awesn1.encoding.fromTwosComplementByteArray")
)
fun Long.Companion.fromTwosComplementByteArray(it: ByteArray): Long =
    it.wrapInUnsafeSource().awesn1ReadTwosComplementLong(it.size)

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.fromTwosComplementByteArray().",
    ReplaceWith("ULong.fromTwosComplementByteArray(it)", "at.asitplus.awesn1.encoding.fromTwosComplementByteArray")
)
fun ULong.Companion.fromTwosComplementByteArray(it: ByteArray): ULong =
    it.wrapInUnsafeSource().awesn1ReadTwosComplementULong(it.size)

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.toUnsignedByteArray().",
    ReplaceWith("at.asitplus.awesn1.encoding.toUnsignedByteArray(this)")
)
fun Long.toUnsignedByteArray(): ByteArray = awesn1ToUnsignedByteArray()

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.toUnsignedByteArray().",
    ReplaceWith("at.asitplus.awesn1.encoding.toUnsignedByteArray(this)")
)
fun Int.toUnsignedByteArray(): ByteArray = awesn1ToUnsignedByteArray()

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.toAsn1VarInt().",
    ReplaceWith("at.asitplus.awesn1.encoding.toAsn1VarInt(this)")
)
fun ULong.toAsn1VarInt(): ByteArray = awesn1ToAsn1VarInt()

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.toAsn1VarInt().",
    ReplaceWith("at.asitplus.awesn1.encoding.toAsn1VarInt(this)")
)
fun UInt.toAsn1VarInt(): ByteArray = awesn1ToAsn1VarInt()

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.decodeAsn1VarULong().",
    ReplaceWith("at.asitplus.awesn1.encoding.decodeAsn1VarULong(this)")
)
fun ByteArray.decodeAsn1VarULong(): Pair<ULong, ByteArray> = awesn1DecodeAsn1VarULong()

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.decodeAsn1VarUInt().",
    ReplaceWith("at.asitplus.awesn1.encoding.decodeAsn1VarUInt(this)")
)
fun ByteArray.decodeAsn1VarUInt(): Pair<UInt, ByteArray> = awesn1DecodeAsn1VarUInt()

@Deprecated(
    "Moved to at.asitplus.awesn1.io.writeAsn1VarInt().",
    ReplaceWith("at.asitplus.awesn1.io.writeAsn1VarInt(this, number)")
)
fun Sink.writeAsn1VarInt(number: ULong): Int = awesn1WriteAsn1VarInt(number)

@Deprecated(
    "Moved to at.asitplus.awesn1.io.writeAsn1VarInt().",
    ReplaceWith("at.asitplus.awesn1.io.writeAsn1VarInt(this, number)")
)
fun Sink.writeAsn1VarInt(number: UInt): Int = awesn1WriteAsn1VarInt(number)

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.bitLength.",
    ReplaceWith("this.bitLength", "at.asitplus.awesn1.encoding.bitLength")
)
val ULong.bitLength: Int inline get() = ULong.SIZE_BITS - countLeadingZeroBits()

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.bitLength.",
    ReplaceWith("this.bitLength", "at.asitplus.awesn1.encoding.bitLength")
)
val Long.bitLength: Int inline get() = Long.SIZE_BITS - countLeadingZeroBits()

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.bitLength.",
    ReplaceWith("this.bitLength", "at.asitplus.awesn1.encoding.bitLength")
)
val UInt.bitLength: Int inline get() = UInt.SIZE_BITS - countLeadingZeroBits()

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.bitLength.",
    ReplaceWith("this.bitLength", "at.asitplus.awesn1.encoding.bitLength")
)
val UByte.bitLength: Int inline get() = UByte.SIZE_BITS - countLeadingZeroBits()

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.bitLength.",
    ReplaceWith("this.bitLength", "at.asitplus.awesn1.encoding.bitLength")
)
val Int.bitLength: Int inline get() = Int.SIZE_BITS - countLeadingZeroBits()

@Deprecated(
    "Moved to at.asitplus.awesn1.io.decodeAsn1VarULong().",
    ReplaceWith("at.asitplus.awesn1.io.decodeAsn1VarULong(this)")
)
fun Source.decodeAsn1VarULong(): Pair<ULong, ByteArray> = awesn1SourceDecodeAsn1VarULong()

@Deprecated(
    "Moved to at.asitplus.awesn1.io.decodeAsn1VarUInt().",
    ReplaceWith("at.asitplus.awesn1.io.decodeAsn1VarUInt(this)")
)
fun Source.decodeAsn1VarUInt(): Pair<UInt, ByteArray> = awesn1SourceDecodeAsn1VarUInt()

@Deprecated(
    "Moved to at.asitplus.awesn1.io.writeTwosComplementLong().",
    ReplaceWith("at.asitplus.awesn1.io.writeTwosComplementLong(this, number)")
)
fun Sink.writeTwosComplementLong(number: Long): Int = awesn1WriteTwosComplementLong(number)

@Deprecated(
    "Moved to at.asitplus.awesn1.io.writeTwosComplementULong().",
    ReplaceWith("at.asitplus.awesn1.io.writeTwosComplementULong(this, number)")
)
fun Sink.writeTwosComplementULong(number: ULong): Int = awesn1WriteTwosComplementULong(number)

@Deprecated(
    "Moved to at.asitplus.awesn1.io.writeTwosComplementUInt().",
    ReplaceWith("at.asitplus.awesn1.io.writeTwosComplementUInt(this, number)")
)
fun Sink.writeTwosComplementUInt(number: UInt): Int = awesn1WriteTwosComplementUInt(number)

@Deprecated(
    "Moved to at.asitplus.awesn1.io.readTwosComplementULong().",
    ReplaceWith("at.asitplus.awesn1.io.readTwosComplementULong(this, nBytes)")
)
fun Source.readTwosComplementULong(nBytes: Int): ULong = awesn1ReadTwosComplementULong(nBytes)

@Deprecated(
    "Moved to at.asitplus.awesn1.io.readTwosComplementLong().",
    ReplaceWith("at.asitplus.awesn1.io.readTwosComplementLong(this, nBytes)")
)
fun Source.readTwosComplementLong(nBytes: Int): Long = awesn1ReadTwosComplementLong(nBytes)

@Deprecated(
    "Moved to at.asitplus.awesn1.io.readTwosComplementInt().",
    ReplaceWith("at.asitplus.awesn1.io.readTwosComplementInt(this, nBytes)")
)
fun Source.readTwosComplementInt(nBytes: Int): Int = awesn1ReadTwosComplementInt(nBytes)

@Deprecated(
    "Moved to at.asitplus.awesn1.io.readTwosComplementUInt().",
    ReplaceWith("at.asitplus.awesn1.io.readTwosComplementUInt(this, nBytes)")
)
fun Source.readTwosComplementUInt(nBytes: Int): UInt = awesn1ReadTwosComplementUInt(nBytes)

@Deprecated(
    "Moved to at.asitplus.awesn1.io.writeMagnitudeLong().",
    ReplaceWith("at.asitplus.awesn1.io.writeMagnitudeLong(this, number)")
)
fun Sink.writeMagnitudeLong(number: Long): Int = awesn1WriteMagnitudeLong(number)

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.toAsn1VarInt().",
    ReplaceWith("at.asitplus.awesn1.encoding.toAsn1VarInt(this)")
)
fun Asn1Integer.toAsn1VarInt(): ByteArray = awesn1ToAsn1VarInt()

@Deprecated(
    "Use awesn1 APIs directly."
)
fun Sink.writeAsn1VarInt(number: Asn1Integer): Int {
    require(number is at.asitplus.awesn1.Asn1Integer.Positive) { "Only non-negative numbers are supported" }
    val encoded = number.awesn1ToAsn1VarInt()
    write(encoded, 0, encoded.size)
    return encoded.size
}

@Deprecated(
    "Moved to at.asitplus.awesn1.io.decodeAsn1VarBigInt().",
    ReplaceWith("at.asitplus.awesn1.io.decodeAsn1VarBigInt(this)")
)
fun Source.decodeAsn1VarBigInt(): Pair<Asn1Integer, ByteArray> = awesn1SourceDecodeAsn1VarBigInt()

@Deprecated(
    "Moved to at.asitplus.awesn1.encoding.decodeAsn1VarBigInt().",
    ReplaceWith("at.asitplus.awesn1.encoding.decodeAsn1VarBigInt(this)")
)
fun ByteArray.decodeAsn1VarBigInt(): Pair<Asn1Integer, ByteArray> = awesn1DecodeAsn1VarBigInt()
