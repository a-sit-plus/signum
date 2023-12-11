package at.asitplus.crypto.datatypes.pki

import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.CryptoSignature
import at.asitplus.crypto.datatypes.CryptoAlgorithm
import at.asitplus.crypto.datatypes.asn1.*
import at.asitplus.crypto.datatypes.asn1.DERTags.toImplicitTag
import at.asitplus.crypto.datatypes.io.BitSet
import at.asitplus.crypto.datatypes.io.ByteArrayBase64Serializer
import kotlinx.serialization.Serializable

/**
 * Very simple implementation of the meat of a X.509 Certificate:
 * The structure that gets signed
 */
@Serializable
data class TbsCertificate(
    val version: Int = 2,
    @Serializable(with = ByteArrayBase64Serializer::class) val serialNumber: ByteArray,
    val signatureAlgorithm: CryptoAlgorithm,
    val issuerName: List<DistinguishedName>,
    val validFrom: Asn1Time,
    val validUntil: Asn1Time,
    val subjectName: List<DistinguishedName>,
    val publicKey: CryptoPublicKey,
    val issuerUniqueID: BitSet? = null,
    val subjectUniqueID: BitSet? = null,
    val extensions: List<X509CertificateExtension>? = null
) : Asn1Encodable<Asn1Sequence> {


    private fun Asn1TreeBuilder.version(value: Int) {
        tagged(0u) { int(value) }
    }

    @Throws(Asn1Exception::class)
    override fun encodeToTlv() = runRethrowing {
        asn1Sequence {
            version(version)
            append(Asn1Primitive(BERTags.INTEGER, serialNumber))
            append(signatureAlgorithm)
            sequence { issuerName.forEach { append(it) } }

            sequence {
                append(validFrom)
                append(validUntil)
            }

            sequence { subjectName.forEach { append(it) } }

            //subject public key
            append(publicKey)

            issuerUniqueID?.let {
                append(
                    Asn1Primitive(
                        1u.toImplicitTag(),
                        Asn1BitString(it).let { byteArrayOf(it.numPaddingBits, *it.rawBytes) })
                )
            }
            subjectUniqueID?.let {
                append(
                    Asn1Primitive(
                        1u.toImplicitTag(),
                        Asn1BitString(it).let { byteArrayOf(it.numPaddingBits, *it.rawBytes) })
                )
            }

            extensions?.let {
                if (it.isNotEmpty()) {
                    tagged(3u) {
                        sequence {
                            it.forEach { ext -> append(ext) }
                        }
                    }
                }
            }
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as TbsCertificate

        if (version != other.version) return false
        if (!serialNumber.contentEquals(other.serialNumber)) return false
        if (signatureAlgorithm != other.signatureAlgorithm) return false
        if (issuerName != other.issuerName) return false
        if (validFrom != other.validFrom) return false
        if (validUntil != other.validUntil) return false
        if (subjectName != other.subjectName) return false
        if (publicKey != other.publicKey) return false
        if (issuerUniqueID != other.issuerUniqueID) return false
        if (subjectUniqueID != other.subjectUniqueID) return false
        if (extensions != other.extensions) return false

        return true
    }

    override fun hashCode(): Int {
        var result = version
        result = 31 * result + serialNumber.contentHashCode()
        result = 31 * result + signatureAlgorithm.hashCode()
        result = 31 * result + issuerName.hashCode()
        result = 31 * result + validFrom.hashCode()
        result = 31 * result + validUntil.hashCode()
        result = 31 * result + subjectName.hashCode()
        result = 31 * result + publicKey.hashCode()
        result = 31 * result + (issuerUniqueID?.hashCode() ?: 0)
        result = 31 * result + (subjectUniqueID?.hashCode() ?: 0)
        result = 31 * result + (extensions?.hashCode() ?: 0)
        return result
    }

    companion object : Asn1Decodable<Asn1Sequence, TbsCertificate> {
        @Throws(Asn1Exception::class)
        override fun decodeFromTlv(src: Asn1Sequence) = runRethrowing {
            //TODO make sure to always check for superfluous data
            val version = src.nextChild().let {
                ((it as Asn1Tagged).verifyTag(0u).single() as Asn1Primitive).readInt()
            }
            val serialNumber = (src.nextChild() as Asn1Primitive).decode(BERTags.INTEGER) { it }
            val sigAlg = CryptoAlgorithm.decodeFromTlv(src.nextChild() as Asn1Sequence)
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
                    (src.nextChild() as Asn1Primitive).let { Asn1BitString.decodeFromTlv(it, 1u.toImplicitTag()) }
                } else null
            }

            val subjectUniqueID = src.peek()?.let { next ->
                if (next.tag == 2u.toImplicitTag()) {
                    (src.nextChild() as Asn1Primitive).let { Asn1BitString.decodeFromTlv(it, 2u.toImplicitTag()) }
                } else null
            }
            val extensions = if (src.hasMoreChildren()) {
                ((src.nextChild() as Asn1Tagged).verifyTag(3u).single() as Asn1Sequence).children.map {
                    X509CertificateExtension.decodeFromTlv(it as Asn1Sequence)
                }
            } else null

            if (src.hasMoreChildren()) throw Asn1StructuralException("Superfluous Data in Certificate Structure")

            TbsCertificate(
                version = version,
                serialNumber = serialNumber,
                signatureAlgorithm = sigAlg,
                issuerName = issuerNames,
                validFrom = timestamps.first,
                validUntil = timestamps.second,
                subjectName = subject,
                publicKey = cryptoPublicKey,
                issuerUniqueID = issuerUniqueID?.toBitSet(),
                subjectUniqueID = subjectUniqueID?.toBitSet(),
                extensions = extensions,
            )
        }

        private fun decodeTimestamps(input: Asn1Sequence): Pair<Asn1Time, Asn1Time> =
            runRethrowing {
                val firstInstant = Asn1Time.decodeFromTlv(input.nextChild() as Asn1Primitive)
                val secondInstant = Asn1Time.decodeFromTlv(input.nextChild() as Asn1Primitive)
                if (input.hasMoreChildren()) throw Asn1StructuralException("Superfluous content in Validity")
                return Pair(firstInstant, secondInstant)
            }
    }
}

/**
 * Very simple implementation of an X.509 Certificate
 */
@Serializable
data class X509Certificate(
    val tbsCertificate: TbsCertificate,
    val signatureAlgorithm: CryptoAlgorithm,
    val signature: CryptoSignature
) : Asn1Encodable<Asn1Sequence> {


    @Throws(Asn1Exception::class)
    override fun encodeToTlv() = asn1Sequence {
        append(tbsCertificate)
        append(signatureAlgorithm)
        append(signature.encodeToTlvBitString())
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as X509Certificate

        if (tbsCertificate != other.tbsCertificate) return false
        if (signatureAlgorithm != other.signatureAlgorithm) return false
        if (signature != other.signature) return false

        return true
    }

    override fun hashCode(): Int {
        var result = tbsCertificate.hashCode()
        result = 31 * result + signatureAlgorithm.hashCode()
        result = 31 * result + signature.hashCode()
        return result
    }

    val publicKey: CryptoPublicKey get() = tbsCertificate.publicKey

    companion object : Asn1Decodable<Asn1Sequence, X509Certificate> {

        @Throws(Asn1Exception::class)
        override fun decodeFromTlv(src: Asn1Sequence): X509Certificate = runRethrowing {
            val tbs = TbsCertificate.decodeFromTlv(src.nextChild() as Asn1Sequence)
            val sigAlg = CryptoAlgorithm.decodeFromTlv(src.nextChild() as Asn1Sequence)
            val signature = CryptoSignature.decodeFromTlv(src.nextChild())
            if (src.hasMoreChildren()) throw Asn1StructuralException("Superfluous structure in Certificate Structure")
            return X509Certificate(tbs, sigAlg, signature)
        }

    }
}
