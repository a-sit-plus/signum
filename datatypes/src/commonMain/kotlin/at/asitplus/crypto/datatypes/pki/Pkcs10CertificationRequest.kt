package at.asitplus.crypto.datatypes.pki

import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.JwsAlgorithm
import at.asitplus.crypto.datatypes.asn1.*
import at.asitplus.crypto.datatypes.io.ByteArrayBase64Serializer
import kotlinx.serialization.Serializable

/**
 * The meat of a PKCS#10 Certification Request:
 * The structure that gets signed
 * @param version defaults to 0
 * @param subjectName list of subject distingished names
 * @param publicKey nomen est omen
 * @param attributes nomen est omen
 */
@Serializable
data class TbsCertificationRequest(
    val version: Int = 0,
    val subjectName: List<DistinguishedName>,
    val publicKey: CryptoPublicKey,
    val attributes: List<Pkcs10CertificationRequestAttribute>? = null
) : Asn1Encodable<Asn1Sequence> {

    /**
     * Convenience constructor for adding [X509CertificateExtension]`s` to a CSR (in addition to generic attributes
     *
     * @throws IllegalArgumentException if no extensions are provided
     */
    @Throws(IllegalArgumentException::class)
    constructor(
        subjectName: List<DistinguishedName>,
        publicKey: CryptoPublicKey,
        extensions: List<X509CertificateExtension>,
        version: Int = 0,
        attributes: List<Pkcs10CertificationRequestAttribute>? = null,
    ) : this(version, subjectName, publicKey, mutableListOf<Pkcs10CertificationRequestAttribute>().also { attrs ->
        if (extensions.isEmpty()) throw IllegalArgumentException("No extensions provided!")
        attributes?.let { attrs.addAll(it) }
        attrs.add(Pkcs10CertificationRequestAttribute(KnownOIDs.extensionRequest, asn1Sequence {
            extensions.forEach { append(it) }
        }))
    })

    override fun encodeToTlv() = asn1Sequence {
        int { version }
        sequence { subjectName.forEach { append(it) } }

        //subject Public Key
        append(publicKey)
        tagged(0u) { attributes?.map { append(it) } }
    }

    companion object : Asn1Decodable<Asn1Sequence, TbsCertificationRequest> {
        override fun decodeFromTlv(src: Asn1Sequence) = runCatching {
            val version = (src.nextChild() as Asn1Primitive).readInt()
            val subject = (src.nextChild() as Asn1Sequence).children.map {
                DistinguishedName.decodeFromTlv(it as Asn1Set)
            }
            val cryptoPublicKey = CryptoPublicKey.decodeFromTlv(src.nextChild() as Asn1Sequence)
            val extensions = if (src.hasMoreChildren()) {
                (src.nextChild() as Asn1Tagged).verify(0u)
                    .map { Pkcs10CertificationRequestAttribute.decodeFromTlv(it as Asn1Sequence) }
            } else null

            if (src.hasMoreChildren()) throw IllegalArgumentException("Superfluous Data in CSR Structure")

            TbsCertificationRequest(
                version = version,
                subjectName = subject,
                publicKey = cryptoPublicKey,
                attributes = extensions,
            )
        }.getOrElse { throw if (it is IllegalArgumentException) it else IllegalArgumentException(it) }
    }
}


/**
 * Very simple implementation of a PKCS#10 Certification Request
 */
@Serializable
data class Pkcs10CertificationRequest(
    val tbsCsr: TbsCertificationRequest,
    val signatureAlgorithm: JwsAlgorithm,
    @Serializable(with = ByteArrayBase64Serializer::class)
    val signature: ByteArray
) : Asn1Encodable<Asn1Sequence> {

    override fun encodeToTlv() = asn1Sequence {
        append(tbsCsr)
        append(signatureAlgorithm)
        bitString { signature }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as Pkcs10CertificationRequest

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

    companion object : Asn1Decodable<Asn1Sequence, Pkcs10CertificationRequest> {

        override fun decodeFromTlv(src: Asn1Sequence): Pkcs10CertificationRequest {
            val tbsCsr = TbsCertificationRequest.decodeFromTlv(src.nextChild() as Asn1Sequence)
            val sigAlg = JwsAlgorithm.decodeFromTlv(src.nextChild() as Asn1Sequence)
            val signature = (src.nextChild() as Asn1Primitive).readBitString()
            if (src.hasMoreChildren()) throw IllegalArgumentException("Superfluous structure in CSR Structure")
            return Pkcs10CertificationRequest(tbsCsr, sigAlg, signature)
        }
    }
}
