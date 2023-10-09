@file:OptIn(ExperimentalEncodingApi::class)

package at.asitplus.crypto.datatypes.asn1

import at.asitplus.crypto.datatypes.Asn1String
import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.EcCurve
import at.asitplus.crypto.datatypes.JwsAlgorithm
import at.asitplus.crypto.datatypes.TbsCertificate
import at.asitplus.crypto.datatypes.asn1.BERTags.BIT_STRING
import at.asitplus.crypto.datatypes.asn1.BERTags.BOOLEAN
import at.asitplus.crypto.datatypes.asn1.BERTags.GENERALIZED_TIME
import at.asitplus.crypto.datatypes.asn1.BERTags.INTEGER
import at.asitplus.crypto.datatypes.asn1.BERTags.NULL
import at.asitplus.crypto.datatypes.asn1.BERTags.OBJECT_IDENTIFIER
import at.asitplus.crypto.datatypes.asn1.BERTags.OCTET_STRING
import at.asitplus.crypto.datatypes.asn1.BERTags.UTC_TIME
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.datetime.Instant
import kotlin.io.encoding.ExperimentalEncodingApi


class Asn1TreeBuilder() {
    internal val elements = mutableListOf<Asn1Encodable>()

    fun append(child: () -> Asn1Encodable) = apply { elements += child() }
    fun tagged(tag: UByte, child: () -> Asn1Encodable) = apply { elements += Asn1Tagged(tag, child()) }
    fun bool(block: () -> Boolean) = apply { elements += block().encodeToTlv() }
    fun int(block: () -> Int) = apply { elements += block().encodeToTlv() }
    fun long(block: () -> Long) = apply { elements += block().encodeToTlv() }

    fun octetString(block: () -> ByteArray) = apply { elements += block().encodeToTlvOctetString() }
    fun octetString(child: Asn1Encodable) = apply { octetString(block = { child.derEncoded }) }

    fun bitString(block: () -> ByteArray) = apply { elements += block().encodeToTlvBitString() }
    fun bitString(child: Asn1Encodable) = apply { bitString(block = { child.derEncoded }) }

    fun hexEncoded(block: () -> String) = apply { elements += block().encodeTolvOid() }
    fun oid(block: () -> ObjectIdentifier) = apply { elements += block().encodeToTlv() }

    fun utf8String(block: () -> String) = apply { elements += Asn1String.UTF8(block()).encodeToTlv() }
    fun printableString(block: () -> String) = apply { elements += Asn1String.Printable(block()).encodeToTlv() }

    fun string(block: () -> Asn1String) = apply {
        val str = block()
        if (str is Asn1String.UTF8) utf8String { str.value }
        else printableString { str.value }
    }

    fun tbsCertificate(block: () -> TbsCertificate) = apply { elements += block().encodeToTlv() }

    fun sigAlg(block: () -> JwsAlgorithm) = apply { elements += block().encodeToTlv() }

    fun subjectPublicKey(block: () -> CryptoPublicKey) = apply { elements += block().encodeToTlv() }

    fun asn1null() = apply { elements += Asn1Primitive(NULL, byteArrayOf()) }

    fun utcTime(block: () -> Instant) = apply { elements += Asn1Primitive(UTC_TIME, block().encodeToAsn1UtcTime()) }

    fun generalizedTime(block: () -> Instant) =
        apply { elements += Asn1Primitive(GENERALIZED_TIME, block().encodeToAsn1GeneralizedTime()) }

    private fun nest(type: CollectionType, init: Asn1TreeBuilder.() -> Unit) = apply {
        val seq = Asn1TreeBuilder()
        seq.init()
        elements += if (type == CollectionType.SEQUENCE) Asn1Sequence(seq.elements) else Asn1Set(seq.elements.let {
            if (type == CollectionType.SET) it.sortedBy { it.tag }
            else {
                if (it.any { elem -> elem.tag != it.first().tag }) throw IllegalArgumentException("SET_OF must only contain elements fo the same tag")
                it.sortedBy { it.derEncoded.encodeToString(Base16) } //TODo this is inefficient
            }
        })
    }

    fun sequence(init: Asn1TreeBuilder.() -> Unit) = nest(CollectionType.SEQUENCE, init)
    fun set(init: Asn1TreeBuilder.() -> Unit) = nest(CollectionType.SET, init)
    fun setOf(init: Asn1TreeBuilder.() -> Unit) = nest(CollectionType.SET_OF, init)

}

private enum class CollectionType {
    SET,
    SEQUENCE,
    SET_OF
}


fun asn1Sequence(root: Asn1TreeBuilder.() -> Unit): Asn1Encodable {
    val seq = Asn1TreeBuilder()
    seq.root()
    return Asn1Sequence(seq.elements)
}

fun asn1Set(root: Asn1TreeBuilder.() -> Unit): Asn1Encodable {
    val seq = Asn1TreeBuilder()
    seq.root()
    return Asn1Set(seq.elements.sortedBy { it.tag })
}

fun asn1SetOf(root: Asn1TreeBuilder.() -> Unit): Asn1Encodable {
    val seq = Asn1TreeBuilder()
    seq.root()
    return Asn1Set(seq.elements)
}

fun Int.encodeToTlv() = Asn1Primitive(INTEGER, encodeToDer())

private fun Boolean.encodeToTlv() = Asn1Primitive(BOOLEAN, (if (this) 0xff else 0).encodeToDer())

private fun Long.encodeToTlv() = Asn1Primitive(INTEGER, encodeToDer())

private fun ByteArray.encodeToTlvOctetString() = Asn1Primitive(OCTET_STRING, this)

private fun ByteArray.encodeToTlvBitString() = Asn1Primitive(BIT_STRING, encodeToBitString())
fun ByteArray.encodeToBitString() = byteArrayOf(0x00) + this

private fun String.encodeTolvOid() = Asn1Primitive(OBJECT_IDENTIFIER, decodeToByteArray(Base16()))


private fun Int.encodeToDer() = encodeToByteArray().dropWhile { it == 0.toByte() }.toByteArray()


private fun Long.encodeToDer() = encodeToByteArray().dropWhile { it == 0.toByte() }.toByteArray()

private fun Instant.encodeToAsn1UtcTime(): ByteArray {
    return encodeToAsn1Time().drop(2).encodeToByteArray()
}

private fun Instant.encodeToAsn1GeneralizedTime(): ByteArray {
    return encodeToAsn1Time().encodeToByteArray()
}

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

private fun JwsAlgorithm.encodeToTlv() = when (this) {
    JwsAlgorithm.ES256 -> asn1Sequence { oid { KnownOIDs.ecdsaWithSHA256 } }
    JwsAlgorithm.ES384 -> asn1Sequence { oid { KnownOIDs.ecdsaWithSHA384 } }
    JwsAlgorithm.ES512 -> asn1Sequence { oid { KnownOIDs.ecdsaWithSHA512 } }
    JwsAlgorithm.RS256 -> asn1Sequence {
        oid { KnownOIDs.sha256WithRSAEncryption }
        asn1null()
    }

    JwsAlgorithm.RS384 -> asn1Sequence {
        oid { KnownOIDs.sha384WithRSAEncryption }
        asn1null()
    }

    JwsAlgorithm.RS512 -> asn1Sequence {
        oid { KnownOIDs.sha512WithRSAEncryption }
        asn1null()
    }

    JwsAlgorithm.UNOFFICIAL_RSA_SHA1 -> asn1Sequence {
        oid { KnownOIDs.sha1WithRSAEncryption }
        asn1null()
    }

    JwsAlgorithm.HMAC256 -> throw IllegalArgumentException("sigAlg: $this")
}

fun CryptoPublicKey.encodeToTlv() = when (this) {
    is CryptoPublicKey.Ec -> asn1Sequence {
        sequence {
            oid { KnownOIDs.ecPublicKey }
            when (curve) {
                EcCurve.SECP_256_R_1 -> oid { KnownOIDs.prime256v1 }
                EcCurve.SECP_384_R_1 -> oid { KnownOIDs.secp384r1 }
                EcCurve.SECP_521_R_1 -> oid { KnownOIDs.secp521r1 }
            }

        }
        bitString { (byteArrayOf(OCTET_STRING.toByte()) + x.ensureSize(curve.coordinateLengthBytes) + y.ensureSize(curve.coordinateLengthBytes)) }
    }

    is CryptoPublicKey.Rsa -> {
        asn1Sequence {
            sequence {
                oid { KnownOIDs.rsaEncryption }
                asn1null()
            }
            bitString(asn1Sequence {
                append {
                    Asn1Primitive(INTEGER,
                        n.ensureSize(bits.number / 8u)
                            .let { if (it.first() == 0x00.toByte()) it else byteArrayOf(0x00, *it) })
                }
                int { e.toInt() }
            })

        }
    }
}

fun Int.encodeLength(): ByteArray {
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
fun Long.encodeToByteArray(): ByteArray = byteArrayOf(
    (this ushr 56).toByte(),
    (this ushr 48).toByte(),
    (this ushr 40).toByte(),
    (this ushr 32).toByte(),
    (this ushr 24).toByte(),
    (this ushr 16).toByte(),
    (this ushr 8).toByte(),
    (this).toByte()
)

/**
 * Strips the leading 0x00 byte of an ASN.1-encoded Integer,
 * that will be there if the first bit of the value is set,
 * i.e. it is over 0x7F (or < 0 if it is signed)
 */
fun ByteArray.stripLeadingSignByte() = if (this[0] == 0.toByte() && this[1] < 0) drop(1).toByteArray() else this

/**
 * The extracted values from ASN.1 may be too short
 * to be simply concatenated as raw values,
 * so we'll need to pad them with 0x00 bytes to the expected length
 */
fun ByteArray.padWithZeros(len: Int): ByteArray = if (size < len) ByteArray(len - size) { 0 } + this else this

/**
 * Drops or adds zero bytes at the start until the [size] is reached
 */
fun ByteArray.ensureSize(size: UInt): ByteArray = when {
    this.size.toUInt() > size -> this.drop(1).toByteArray().ensureSize(size)
    this.size.toUInt() < size -> (byteArrayOf(0) + this).ensureSize(size)
    else -> this
}

