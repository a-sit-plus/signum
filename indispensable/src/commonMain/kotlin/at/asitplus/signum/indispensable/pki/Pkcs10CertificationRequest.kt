package at.asitplus.signum.indispensable.pki

import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.KeyType
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.encoding.Asn1.BitString
import at.asitplus.signum.indispensable.asn1.encoding.Asn1.ExplicitlyTagged
import at.asitplus.signum.indispensable.asn1.encoding.asAsn1BitString
import at.asitplus.signum.indispensable.asn1.encoding.decodeToInt
import at.asitplus.signum.indispensable.io.ByteArrayBase64Serializer
import kotlinx.serialization.Serializable

/**
 * The meat of a PKCS#10 Certification Request:
 * The structure that gets signed
 * @param version defaults to 0
 * @param subjectName list of subject distinguished names
 * @param publicKey nomen est omen
 * @param attributes nomen est omen
 */
@Serializable
data class TbsCertificationRequest<out K: KeyType>(
    val version: Int = 0,
    val subjectName: List<RelativeDistinguishedName>,
    val publicKey: CryptoPublicKey<out K>,
    val attributes: List<Pkcs10CertificationRequestAttribute> = listOf()
) : Asn1Encodable<Asn1Sequence> {

    /**
     * Convenience constructor for adding [X509CertificateExtension]`s` to a CSR (in addition to generic attributes
     *
     * @throws IllegalArgumentException if no extensions are provided
     */
    @Throws(IllegalArgumentException::class)
    constructor(
        subjectName: List<RelativeDistinguishedName>,
        publicKey: CryptoPublicKey<out K>,
        extensions: List<X509CertificateExtension>? = null,
        version: Int = 0,
        attributes: List<Pkcs10CertificationRequestAttribute>? = null,
    ) : this(version, subjectName, publicKey, mutableListOf<Pkcs10CertificationRequestAttribute>().also { attrs ->
        attributes?.let { attrs.addAll(it) }
        extensions?.let { extn ->
            attrs.add(
                Pkcs10CertificationRequestAttribute(
                    KnownOIDs.extensionRequest,
                    Asn1.Sequence { extn.forEach { +it } })
            )
        }
    })

    override fun encodeToTlv() = Asn1.Sequence {
        +Asn1.Int(version)
        +Asn1.Sequence { subjectName.forEach { +it } }

        //subject Public Key
        +publicKey
        +ExplicitlyTagged(0u) { attributes.map { +it } }
    }


    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as TbsCertificationRequest<*>

        if (version != other.version) return false
        if (subjectName != other.subjectName) return false
        if (publicKey != other.publicKey) return false
        if (attributes != other.attributes) return false

        return true
    }

    override fun hashCode(): Int {
        var result = version
        result = 31 * result + subjectName.hashCode()
        result = 31 * result + publicKey.hashCode()
        result = 31 * result + (attributes.hashCode())
        return result
    }

    companion object : Asn1Decodable<Asn1Sequence, TbsCertificationRequest<out KeyType>> {
        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Sequence) = runRethrowing {
            val version = (src.nextChild() as Asn1Primitive).decodeToInt()
            val subject = (src.nextChild() as Asn1Sequence).children.map {
                RelativeDistinguishedName.decodeFromTlv(it as Asn1Set)
            }
            val cryptoPublicKey = CryptoPublicKey.decodeFromTlv(src.nextChild() as Asn1Sequence)
            val attributes = if (src.hasMoreChildren()) {
                (src.nextChild() as Asn1ExplicitlyTagged).verifyTag(0u)
                    .map { Pkcs10CertificationRequestAttribute.decodeFromTlv(it as Asn1Sequence) }
            } else null

            if (src.hasMoreChildren()) throw Asn1StructuralException("Superfluous Data in CSR Structure")

            TbsCertificationRequest(
                version = version,
                subjectName = subject,
                publicKey = cryptoPublicKey,
                attributes = attributes,
            )
        }
    }
}


/**
 * Very simple implementation of a PKCS#10 Certification Request
 */
@Serializable
data class Pkcs10CertificationRequest<out K: KeyType>(
    val tbsCsr: TbsCertificationRequest<K>,
    val signatureAlgorithm: X509SignatureAlgorithm,
    val signature: CryptoSignature<out K>
) : Asn1Encodable<Asn1Sequence> {


    @Throws(Asn1Exception::class)
    override fun encodeToTlv() = Asn1.Sequence {
        +tbsCsr
        +signatureAlgorithm
        +BitString(signature.encodeToDer())
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as Pkcs10CertificationRequest<*>

        if (tbsCsr != other.tbsCsr) return false
        if (signatureAlgorithm != other.signatureAlgorithm) return false
        if (signature != other.signature) return false

        return true
    }

    override fun hashCode(): Int {
        var result = tbsCsr.hashCode()
        result = 31 * result + signatureAlgorithm.hashCode()
        result = 31 * result + signature.hashCode()
        return result
    }

    companion object : Asn1Decodable<Asn1Sequence, Pkcs10CertificationRequest<out KeyType>> {

        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Sequence): Pkcs10CertificationRequest<out KeyType> = runRethrowing {
            val tbsCsr = TbsCertificationRequest.decodeFromTlv(src.nextChild() as Asn1Sequence)
            val sigAlg = X509SignatureAlgorithm.decodeFromTlv(src.nextChild() as Asn1Sequence)
            val signature = (src.nextChild() as Asn1Primitive).asAsn1BitString()
            if (src.hasMoreChildren()) throw Asn1StructuralException("Superfluous structure in CSR Structure")
            return Pkcs10CertificationRequest(tbsCsr, sigAlg, CryptoSignature.decodeFromDer(signature.rawBytes))
        }
    }
}
