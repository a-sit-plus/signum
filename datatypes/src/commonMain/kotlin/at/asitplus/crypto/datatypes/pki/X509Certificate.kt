package at.asitplus.crypto.datatypes.pki

import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.JwsAlgorithm
import at.asitplus.crypto.datatypes.asn1.*
import at.asitplus.crypto.datatypes.asn1.DERTags.toExplicitTag
import at.asitplus.crypto.datatypes.asn1.DERTags.toImplicitTag
import at.asitplus.crypto.datatypes.io.ByteArrayBase64Serializer
import at.asitplus.crypto.datatypes.sigAlg
import at.asitplus.crypto.datatypes.subjectPublicKey
import kotlinx.serialization.Serializable

/**
 * Very simple implementation of the meat of an X.509 Certificate:
 * The structure that gets signed
 */
@Serializable
data class TbsCertificate(
    val version: Int = 2,
    @Serializable(with = ByteArrayBase64Serializer::class) val serialNumber: ByteArray,
    val signatureAlgorithm: JwsAlgorithm,
    val issuerName: List<DistinguishedName>,
    val validFrom: CertificateTimeStamp,
    val validUntil: CertificateTimeStamp,
    val subjectName: List<DistinguishedName>,
    val publicKey: CryptoPublicKey,
    @Serializable(with = ByteArrayBase64Serializer::class) val issuerUniqueID: ByteArray? = null,
    @Serializable(with = ByteArrayBase64Serializer::class) val subjectUniqueID: ByteArray? = null,
    val extensions: List<X509CertificateExtension>? = null
) : Asn1Encodable<Asn1Sequence> {


    private fun Asn1TreeBuilder.version(block: () -> Int) =
        apply { elements += Asn1Tagged(0u.toExplicitTag(), block().encodeToTlv()) }

    override fun encodeToTlv() = asn1Sequence {
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

    companion object : Asn1Decodable<Asn1Sequence, TbsCertificate> {
        override fun decodeFromTlv(src: Asn1Sequence) = runCatching {
            //TODO make sure to always check for superfluous data
            val version = src.nextChild().let {
                ((it as Asn1Tagged).verify(0u).single() as Asn1Primitive).readInt()
            }
            val serialNumber = (src.nextChild() as Asn1Primitive).decode(BERTags.INTEGER) { it }
            val sigAlg = JwsAlgorithm.decodeFromTlv(src.nextChild() as Asn1Sequence)
            val issuerNames = (src.nextChild() as Asn1Sequence).children.map {
                DistinguishedName.decodeFromTlv(it as Asn1Set)
            }

            val timestamps = decodeTimestamps(src.nextChild() as Asn1Sequence)
            val subject = (src.nextChild() as Asn1Sequence).children.map {
                DistinguishedName.decodeFromTlv(it as Asn1Set)
            }

            val cryptoPublicKey = CryptoPublicKey.decodeFromTlv(src.nextChild() as Asn1Sequence)

            val issuerUniqueID = src.peek()?.let { next ->
                if (next.tag == 1u.toImplicitTag()) {
                    (src.nextChild() as Asn1Primitive).decode(1u.toImplicitTag()) { decodeBitString(it) }
                } else null
            }

            val subjectUniqueID = src.peek()?.let { next ->
                if (next.tag == 2u.toImplicitTag()) {
                    (src.nextChild() as Asn1Primitive).decode(2u.toImplicitTag()) { decodeBitString(it) }
                } else null
            }
            val extensions = if (src.hasMoreChildren()) {
                ((src.nextChild() as Asn1Tagged).verify(3u).single() as Asn1Sequence).children.map {
                    X509CertificateExtension.decodeFromTlv(it as Asn1Sequence)
                }
            } else null

            if (src.hasMoreChildren()) throw IllegalArgumentException("Superfluous Data in Certificate Structure")

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

fun Asn1TreeBuilder.tbsCertificate(block: () -> TbsCertificate) = apply { elements += block().encodeToTlv() }

/**
 * Very simple implementation of an X.509 Certificate
 */
@Serializable
data class X509Certificate(
    val tbsCertificate: TbsCertificate,
    val signatureAlgorithm: JwsAlgorithm,
    @Serializable(with = ByteArrayBase64Serializer::class)
    val signature: ByteArray
) : Asn1Encodable<Asn1Sequence> {

    override fun encodeToTlv() = asn1Sequence {
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

    val publicKey: CryptoPublicKey get() = tbsCertificate.publicKey

    companion object : Asn1Decodable<Asn1Sequence, X509Certificate> {

        override fun decodeFromTlv(src: Asn1Sequence): X509Certificate {
            val tbs = TbsCertificate.decodeFromTlv(src.nextChild() as Asn1Sequence)
            val sigAlg = JwsAlgorithm.decodeFromTlv(src.nextChild() as Asn1Sequence)
            val signature = (src.nextChild() as Asn1Primitive).readBitString()
            if (src.hasMoreChildren()) throw IllegalArgumentException("Superfluous structure in Certificate Structure")
            return X509Certificate(tbs, sigAlg, signature)
        }

    }
}