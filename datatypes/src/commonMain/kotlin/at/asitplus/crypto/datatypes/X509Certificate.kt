package at.asitplus.crypto.datatypes

import at.asitplus.crypto.datatypes.asn1.Asn1Encodable
import at.asitplus.crypto.datatypes.asn1.Asn1Primitive
import at.asitplus.crypto.datatypes.asn1.Asn1Sequence
import at.asitplus.crypto.datatypes.asn1.Asn1Set
import at.asitplus.crypto.datatypes.asn1.Asn1Tagged
import at.asitplus.crypto.datatypes.asn1.Asn1TreeBuilder
import at.asitplus.crypto.datatypes.asn1.BERTags
import at.asitplus.crypto.datatypes.asn1.DERTags.toExplicitTag
import at.asitplus.crypto.datatypes.asn1.DERTags.toImplicitTag
import at.asitplus.crypto.datatypes.asn1.DistinguishedName
import at.asitplus.crypto.datatypes.asn1.ObjectIdentifier
import at.asitplus.crypto.datatypes.asn1.asn1Sequence
import at.asitplus.crypto.datatypes.asn1.decode
import at.asitplus.crypto.datatypes.asn1.decodeBitString
import at.asitplus.crypto.datatypes.asn1.decodeFromTlv
import at.asitplus.crypto.datatypes.asn1.encodeToAsn1GeneralizedTime
import at.asitplus.crypto.datatypes.asn1.encodeToAsn1UtcTime
import at.asitplus.crypto.datatypes.asn1.encodeToBitString
import at.asitplus.crypto.datatypes.asn1.encodeToTlv
import at.asitplus.crypto.datatypes.asn1.readBitString
import at.asitplus.crypto.datatypes.asn1.readInstant
import at.asitplus.crypto.datatypes.asn1.readInt
import at.asitplus.crypto.datatypes.asn1.readOid
import at.asitplus.crypto.datatypes.asn1.verify
import at.asitplus.crypto.datatypes.io.ByteArrayBase64Serializer
import kotlinx.datetime.Instant
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/**
 * Very simple implementation of the meat of an X.509 Certificate:
 * The structure that gets signed
 */
@Serializable
data class TbsCertificate(
    val version: Int = 2,
    val serialNumber: ByteArray,
    val signatureAlgorithm: JwsAlgorithm,
    val issuerName: List<DistinguishedName>,
    val validFrom: CertificateTimeStamp,
    val validUntil: CertificateTimeStamp,
    val subjectName: List<DistinguishedName>,
    val publicKey: CryptoPublicKey,
    val issuerUniqueID: ByteArray? = null,
    val subjectUniqueID: ByteArray? = null,
    val extensions: List<X509CertificateExtension>? = null
) {


    private fun Asn1TreeBuilder.version(block: () -> Int) =
        apply { elements += Asn1Tagged(0u.toExplicitTag(), block().encodeToTlv()) }

    fun encodeToTlv() = asn1Sequence {
        version { version }
        append { Asn1Primitive(BERTags.INTEGER, serialNumber) }
        sigAlg { signatureAlgorithm }
        sequence { issuerName.forEach { append { it.encodeToTlv() } } }

        sequence {
            append { validFrom.asn1Object }
            append { validUntil.asn1Object }
        }
        sequence { subjectName.forEach { append { it.encodeToTlv() } } }

        subjectPublicKey { publicKey }

        issuerUniqueID?.let { append { Asn1Primitive(1u.toImplicitTag(), it.encodeToBitString()) } }
        subjectUniqueID?.let { append { Asn1Primitive(2u.toImplicitTag(), it.encodeToBitString()) } }

        extensions?.let {
            if (it.isNotEmpty()) {
                append {
                    Asn1Tagged(3u.toExplicitTag(),
                        asn1Sequence {
                            it.forEach { ext ->
                                append { ext.encodeToTlv() }
                            }
                        }
                    )
                }
            }
        }
    }

    companion object {
        fun decodeFromTlv(input: Asn1Sequence) = runCatching {
            //TODO make sure to always check for superfluous data
            val version = input.nextChild().let {
                ((it as Asn1Tagged).verify(0u).single() as Asn1Primitive).readInt()
            }
            val serialNumber = (input.nextChild() as Asn1Primitive).decode(BERTags.INTEGER) { it }
            val sigAlg = JwsAlgorithm.decodeFromTlv(input.nextChild() as Asn1Sequence)
            val issuerNames = (input.nextChild() as Asn1Sequence).children.map {
                DistinguishedName.decodeFromTlv(it as Asn1Set)
            }

            val timestamps = decodeTimestamps(input.nextChild() as Asn1Sequence)
                ?: throw IllegalArgumentException("error parsing Timestamps")
            val subject = (input.nextChild() as Asn1Sequence).children.map {
                DistinguishedName.decodeFromTlv(it as Asn1Set)
            }

            val cryptoPublicKey = CryptoPublicKey.decodeFromTlv(input.nextChild() as Asn1Sequence)

            val issuerUniqueID = input.peek()?.let { next ->
                if (next.tag == 1u.toImplicitTag()) {
                    (input.nextChild() as Asn1Primitive).decode(1u.toImplicitTag()) { decodeBitString(it) }
                } else null
            }

            val subjectUniqueID = input.peek()?.let { next ->
                if (next.tag == 2u.toImplicitTag()) {
                    (input.nextChild() as Asn1Primitive).decode(2u.toImplicitTag()) { decodeBitString(it) }
                } else null
            }
            val extensions = if (input.hasMoreChildren()) {
                ((input.nextChild() as Asn1Tagged).verify(3u).single() as Asn1Sequence).children.map {
                    X509CertificateExtension.decodeFromTlv(it as Asn1Sequence)
                }
            } else null

            if (input.hasMoreChildren()) throw IllegalArgumentException("Superfluous Data in Certificate Structure")

            TbsCertificate(
                version = version,
                serialNumber = serialNumber,
                signatureAlgorithm = sigAlg,
                issuerName = issuerNames,
                validFrom = timestamps.first,
                validUntil = timestamps.second,
                subjectName = subject,
                publicKey = cryptoPublicKey,
                issuerUniqueID = issuerUniqueID,
                subjectUniqueID = subjectUniqueID,
                extensions = extensions,
            )
        }.getOrElse { throw if (it is IllegalArgumentException) it else IllegalArgumentException(it) }

        private fun decodeTimestamps(input: Asn1Sequence): Pair<CertificateTimeStamp, CertificateTimeStamp> =
            runCatching {
                val firstInstant = CertificateTimeStamp(input.nextChild() as Asn1Primitive)
                val secondInstant = CertificateTimeStamp(input.nextChild() as Asn1Primitive)
                if (input.hasMoreChildren()) throw IllegalArgumentException("Superfluous content in Validity")
                return Pair(firstInstant, secondInstant)
            }.getOrElse { throw if (it is IllegalArgumentException) it else IllegalArgumentException(it) }
    }
}

@Serializable
data class X509CertificateExtension(
    val id: ObjectIdentifier, val critical: Boolean = false,
    @Serializable(with = ByteArrayBase64Serializer::class) val value: ByteArray
) {

    fun encodeToTlv() = asn1Sequence {
        oid { id }
        if (critical) bool { true }
        octetString { value }
    }

    companion object {

        fun decodeFromTlv(src: Asn1Sequence): X509CertificateExtension {

            val id = (src.children[0] as Asn1Primitive).readOid()
            val critical =
                if (src.children[1].tag == BERTags.BOOLEAN) (src.children[1] as Asn1Primitive).content[0] == 0xff.toByte() else false

            val value = (src.children.last() as Asn1Primitive).decode(BERTags.OCTET_STRING) { it }
            return X509CertificateExtension(id, critical, value)
        }

    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as X509CertificateExtension

        if (id != other.id) return false
        if (critical != other.critical) return false
        if (!value.contentEquals(other.value)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = id.hashCode()
        result = 31 * result + critical.hashCode()
        result = 31 * result + value.contentHashCode()
        return result
    }
}

/**
 * Very simple implementation of an X.509 Certificate
 */
@Serializable
data class X509Certificate(
    val tbsCertificate: TbsCertificate,
    val signatureAlgorithm: JwsAlgorithm,
    @Serializable(with = ByteArrayBase64Serializer::class)
    val signature: ByteArray
) {

    fun encodeToTlv() = asn1Sequence {
        tbsCertificate { tbsCertificate }
        sigAlg { signatureAlgorithm }
        bitString { signature }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as X509Certificate

        if (tbsCertificate != other.tbsCertificate) return false
        if (signatureAlgorithm != other.signatureAlgorithm) return false
        if (!signature.contentEquals(other.signature)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = tbsCertificate.hashCode()
        result = 31 * result + signatureAlgorithm.hashCode()
        result = 31 * result + signature.contentHashCode()
        return result
    }

    companion object {

        fun decodeFromTlv(src: Asn1Sequence): X509Certificate {
            val tbs = TbsCertificate.decodeFromTlv(src.nextChild() as Asn1Sequence)
            val sigAlg = JwsAlgorithm.decodeFromTlv(src.nextChild() as Asn1Sequence)
            val signature = (src.nextChild() as Asn1Primitive).readBitString()
            if (src.hasMoreChildren()) throw IllegalArgumentException("Superfluous structure in Certificate Structure")
            return X509Certificate(tbs, sigAlg, signature)
        }
    }
}

@Serializable(with = CertTimeStampSerializer::class)
class CertificateTimeStamp(val asn1Object: Asn1Primitive) {
    init {
        if (asn1Object.tag != BERTags.UTC_TIME && asn1Object.tag != BERTags.GENERALIZED_TIME)
            throw IllegalArgumentException("Not a timestamp!")
    }

    constructor(instant: Instant) : this(instant.wrap())

    val instant by lazy { asn1Object.readInstant() }

    companion object {
        fun Instant.wrap() = if (this > Instant.parse("2050-01-01T00:00:00Z")) { // per RFC 5280 4.1.2.5
            Asn1Primitive(BERTags.GENERALIZED_TIME, encodeToAsn1GeneralizedTime())
        } else {
            Asn1Primitive(BERTags.UTC_TIME, encodeToAsn1UtcTime())
        }

    }
}

object CertTimeStampSerializer : KSerializer<CertificateTimeStamp> {
    override val descriptor = PrimitiveSerialDescriptor("CertificateTimestamp", PrimitiveKind.STRING)

    override fun deserialize(decoder: Decoder) =
        CertificateTimeStamp(Asn1Encodable.decodeFromDerHexString(decoder.decodeString()) as Asn1Primitive)

    override fun serialize(encoder: Encoder, value: CertificateTimeStamp) {
        encoder.encodeString(value.asn1Object.toDerHexString())
    }

}
