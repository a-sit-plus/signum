@file:OptIn(ExperimentalEncodingApi::class)

package at.asitplus.crypto.datatypes.asn1

import at.asitplus.crypto.datatypes.*
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import kotlinx.datetime.Instant
import kotlin.io.encoding.ExperimentalEncodingApi

class SequenceBuilder {

    internal val elements = mutableListOf<ByteArray>()

    fun tagged(tag: Int, block: () -> ByteArray) = apply { elements += asn1Tag(tag, block()) }
    fun bool(block: () -> Boolean) = apply { elements += block().encodeToAsn1() }
    fun int(block: () -> Int) = apply { elements += block().encodeToAsn1() }
    fun long(block: () -> Long) = apply { elements += block().encodeToAsn1() }

    fun octetString(block: () -> ByteArray) = apply { elements += block().encodeToOctetString() }
    fun bitString(block: () -> ByteArray) = apply { elements += block().encodeToBitString() }

    fun oid(block: () -> String) = apply { elements += block().encodeToOid() }

    fun utf8String(block: () -> String) = apply { elements += asn1Tag(0x0c, block().encodeToByteArray()) }
    fun printableString(block: () -> String) = apply { elements += asn1Tag(0x13, block().encodeToByteArray()) }

    fun version(block: () -> Int) = apply { elements += asn1Tag(0xA0, block().encodeToAsn1()) }

    fun distinguishedName(block: () -> DistingushedName) = apply {
        val dn = block()
        oid { dn.oid }
        writeString { dn.value }

    }

    fun writeString(block: () -> Asn1String) = apply {
        val str = block()
        if (str is Asn1String.UTF8)
            utf8String { str.value }
        else printableString { str.value }
    }

    fun asn1null() = apply { elements += byteArrayOf(0x05.toByte(), 0x00.toByte()) }

    fun subjectPublicKey(block: () -> CryptoPublicKey) = apply { elements += block().encodeToAsn1() }

    fun tbsCertificate(block: () -> TbsCertificate) = apply { elements += block().encodeToDer() }

    fun sigAlg(block: () -> JwsAlgorithm) = apply { elements += block().encodeToAsn1() }

    fun utcTime(block: () -> Instant) = apply { elements += block().encodeToAsn1() }

    fun sequence(init: SequenceBuilder.() -> Unit) = apply {
        val seq = SequenceBuilder()
        seq.init()
        elements += asn1Tag(0x30, seq.elements.fold(byteArrayOf()) { acc, bytes -> acc + bytes })
    }


    fun set(init: SequenceBuilder.() -> Unit) = apply {
        val seq = SequenceBuilder()
        seq.init()
        elements += asn1Tag(0x31, seq.elements.fold(byteArrayOf()) { acc, bytes -> acc + bytes })
    }

    fun append(derEncoded: ByteArray) = apply { elements += derEncoded }
}


fun sequence(root: SequenceBuilder.() -> Unit): ByteArray {
    val seq = SequenceBuilder()
    seq.root()
    return asn1Tag(0x30, seq.elements.fold(byteArrayOf()) { acc, bytes -> acc + bytes })
}

private fun ByteArray.encodeToOctetString() = asn1Tag(0x04, this)
private fun Int.encodeToAsn1() = asn1Tag(0x02, encodeToDer())

private fun Boolean.encodeToAsn1() = asn1Tag(0x01, (if (this) 0xff else 0).encodeToDer())

private fun Int.encodeToDer() = encodeToByteArray().dropWhile { it == 0.toByte() }.toByteArray()

private fun Long.encodeToAsn1() = asn1Tag(0x02, encodeToDer())

private fun Long.encodeToDer() = encodeToByteArray().dropWhile { it == 0.toByte() }.toByteArray()

private fun ByteArray.encodeToBitString() = asn1Tag(0x03, (byteArrayOf(0x00) + this))

private fun asn1Tag(tag: Int, value: ByteArray) = byteArrayOf(tag.toByte()) + value.size.encodeLength() + value

private fun String.encodeToOid() = asn1Tag(0x06, decodeToByteArray(Base16()))

private fun Instant.encodeToAsn1(): ByteArray {
    val value = this.toString()
    if (value.isEmpty()) return asn1Tag(0x17, byteArrayOf())
    val matchResult = Regex("[0-9]{2}([0-9]{2})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})")
        .matchAt(value, 0)
        ?: throw IllegalArgumentException("instant serialization failed: $value")
    val year = matchResult.groups[1]?.value
        ?: throw IllegalArgumentException("instant serialization year failed: $value")
    val month = matchResult.groups[2]?.value
        ?: throw IllegalArgumentException("instant serialization month failed: $value")
    val day = matchResult.groups[3]?.value
        ?: throw IllegalArgumentException("instant serialization day failed: $value")
    val hour = matchResult.groups[4]?.value
        ?: throw IllegalArgumentException("instant serialization hour failed: $value")
    val minute = matchResult.groups[5]?.value
        ?: throw IllegalArgumentException("instant serialization minute failed: $value")
    val seconds = matchResult.groups[6]?.value
        ?: throw IllegalArgumentException("instant serialization seconds failed: $value")
    return asn1Tag(0x17, "$year$month$day$hour$minute${seconds}Z".encodeToByteArray())
}

fun JwsAlgorithm.Companion.decodeFromDer(input: ByteArray): JwsAlgorithm? {
    if (input.contentEquals("2A8648CE3D040303".encodeToOid()))
        return JwsAlgorithm.ES384
    else if (input.contentEquals("2A8648CE3D040302".encodeToOid()))
        return JwsAlgorithm.ES256

    return null
}

private fun JwsAlgorithm.encodeToAsn1() = when (this) {
    JwsAlgorithm.ES256 -> "2A8648CE3D040302".encodeToOid()
    JwsAlgorithm.ES384 -> "2A8648CE3D040303".encodeToOid()
    else -> throw IllegalArgumentException("sigAlg: $this")
}

fun CryptoPublicKey.encodeToAsn1() = when (this) {
    is CryptoPublicKey.Ec -> sequence {
        sequence {
            oid { "2A8648CE3D0201" }
            when (curve) {
                EcCurve.SECP_256_R_1 -> oid { "2A8648CE3D030107" }
                EcCurve.SECP_384_R_1 -> oid { "2B81040022" }
                EcCurve.SECP_521_R_1 -> oid { "2B81040023" }
            }

        }
        bitString { (byteArrayOf(0x04.toByte()) + x.ensureSize(curve.coordinateLengthBytes) + y.ensureSize(curve.coordinateLengthBytes)) }
    }

    is CryptoPublicKey.Rsa -> {
        val key = sequence {
            tagged(0x02) {
                n.ensureSize(bits.number / 8u)
                    .let { if (it.first() == 0x00.toByte()) it else byteArrayOf(0x00, *it) }
            }
            int { e.toInt() }
        }
        sequence {
            sequence {
                oid { "2A864886F70D010101" }
                asn1null()
            }
            bitString {
                key
            }

        }
    }

}

private fun Int.encodeLength(): ByteArray {
    if (this < 128) {
        return byteArrayOf(this.toByte())
    }
    if (this < 0x100) {
        return byteArrayOf(0x81.toByte(), this.toByte())
    }
    if (this < 0x8000) {
        return byteArrayOf(0x82.toByte(), (this ushr 8).toByte(), this.toByte())
    }
    throw IllegalArgumentException("length $this")
}


/**
 * Encode as a four-byte array
 */
fun Int.encodeToByteArray(): ByteArray =
    byteArrayOf((this ushr 24).toByte(), (this ushr 16).toByte(), (this ushr 8).toByte(), (this).toByte())

/**
 * Encode as a four-byte array
 */
fun Long.encodeToByteArray(): ByteArray =
    byteArrayOf(
        (this ushr 56).toByte(), (this ushr 48).toByte(), (this ushr 40).toByte(), (this ushr 32).toByte(),
        (this ushr 24).toByte(), (this ushr 16).toByte(), (this ushr 8).toByte(), (this).toByte()
    )

/**
 * Strips the leading 0x00 byte of an ASN.1-encoded Integer,
 * that will be there if the first bit of the value is set,
 * i.e. it is over 0x7F (or < 0 if it is signed)
 */
fun ByteArray.stripLeadingSignByte() =
    if (this[0] == 0.toByte() && this[1] < 0) drop(1).toByteArray() else this

/**
 * The extracted values from ASN.1 may be too short
 * to be simply concatenated as raw values,
 * so we'll need to pad them with 0x00 bytes to the expected length
 */
fun ByteArray.padWithZeros(len: Int): ByteArray =
    if (size < len) ByteArray(len - size) { 0 } + this else this

/**
 * Drops or adds zero bytes at the start until the [size] is reached
 */
fun ByteArray.ensureSize(size: UInt): ByteArray = when {
    this.size.toUInt() > size -> this.drop(1).toByteArray().ensureSize(size)
    this.size.toUInt() < size -> (byteArrayOf(0) + this).ensureSize(size)
    else -> this
}

