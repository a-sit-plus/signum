package at.asitplus.crypto.datatypes

import at.asitplus.crypto.datatypes.asn1.Asn1Primitive
import at.asitplus.crypto.datatypes.asn1.Asn1Sequence
import at.asitplus.crypto.datatypes.asn1.Asn1Set
import at.asitplus.crypto.datatypes.asn1.Asn1Tagged
import at.asitplus.crypto.datatypes.asn1.DERTags.toExplicitTag
import at.asitplus.crypto.datatypes.asn1.DistinguishedName
import at.asitplus.crypto.datatypes.asn1.asn1Sequence
import at.asitplus.crypto.datatypes.asn1.decodeFromTlv
import at.asitplus.crypto.datatypes.asn1.readBitString
import at.asitplus.crypto.datatypes.asn1.readInt
import at.asitplus.crypto.datatypes.asn1.verify
import at.asitplus.crypto.datatypes.io.ByteArrayBase64Serializer
import kotlinx.serialization.Serializable

/**
 * The meat of a PKCS#10 Certification Request:
 * The structure that gets signed
 */
@Serializable
data class TbsCertificationRequest(
    val version: Int = 0,
    val subjectName: List<DistinguishedName>,
    val publicKey: CryptoPublicKey,
    val extensions: List<X509CertificateExtension>? = null
) {

    fun encodeToTlv() = asn1Sequence {
        int { version }
        sequence { subjectName.forEach { append { it.encodeToTlv() } } }
        subjectPublicKey { publicKey }
        append {
            Asn1Tagged(
                0u.toExplicitTag(),
                extensions?.let {
                    if (it.isNotEmpty()) {
                        asn1Sequence {
                            it.forEach { ext -> append { ext.encodeToTlv() } }
                        }
                    } else {
                        null
                    }
                })
        }
    }

    companion object {
        fun decodeFromTlv(input: Asn1Sequence) = runCatching {
            val version = (input.nextChild() as Asn1Primitive).readInt()
            val subject = (input.nextChild() as Asn1Sequence).children.map {
                DistinguishedName.decodeFromTlv(it as Asn1Set)
            }
            val cryptoPublicKey = CryptoPublicKey.decodeFromTlv(input.nextChild() as Asn1Sequence)
            val extensions = if (input.hasMoreChildren()) {
                when (val encodable = (input.nextChild() as Asn1Tagged).verify(0u)) {
                    is Asn1Sequence -> encodable.children.map {
                        X509CertificateExtension.decodeFromTlv(it as Asn1Sequence)
                    }

                    else -> null
                }
            } else null

            if (input.hasMoreChildren()) throw IllegalArgumentException("Superfluous Data in CSR Structure")

            TbsCertificationRequest(
                version = version,
                subjectName = subject,
                publicKey = cryptoPublicKey,
                extensions = extensions,
            )
        }.getOrElse { throw if (it is IllegalArgumentException) it else IllegalArgumentException(it) }
    }
}


/**
 * Very simple implementation of a PKCS#10 Certification Request
 */
@Serializable
data class CertificationRequest(
    val tbsCsr: TbsCertificationRequest,
    val signatureAlgorithm: JwsAlgorithm,
    @Serializable(with = ByteArrayBase64Serializer::class)
    val signature: ByteArray
) {

    fun encodeToTlv() = asn1Sequence {
        tbsCertificationRequest { tbsCsr }
        sigAlg { signatureAlgorithm }
        bitString { signature }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as CertificationRequest

        if (tbsCsr != other.tbsCsr) return false
        if (signatureAlgorithm != other.signatureAlgorithm) return false
        if (!signature.contentEquals(other.signature)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = tbsCsr.hashCode()
        result = 31 * result + signatureAlgorithm.hashCode()
        result = 31 * result + signature.contentHashCode()
        return result
    }

    companion object {

        fun decodeFromTlv(src: Asn1Sequence): CertificationRequest {
            val tbsCsr = TbsCertificationRequest.decodeFromTlv(src.nextChild() as Asn1Sequence)
            val sigAlg = JwsAlgorithm.decodeFromTlv(src.nextChild() as Asn1Sequence)
            val signature = (src.nextChild() as Asn1Primitive).readBitString()
            if (src.hasMoreChildren()) throw IllegalArgumentException("Superfluous structure in CSR Structure")
            return CertificationRequest(tbsCsr, sigAlg, signature)
        }
    }
}