package at.asitplus.signum.indispensable.pki

import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.signum.indispensable.X509SignatureAlgorithmDescription
import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.encoding.Asn1.BitString
import at.asitplus.signum.indispensable.asn1.encoding.Asn1.ExplicitlyTagged
import at.asitplus.signum.indispensable.asn1.encoding.asAsn1BitString
import at.asitplus.signum.indispensable.asn1.encoding.decodeToInt
import at.asitplus.signum.indispensable.pki.generalNames.X500Name
import at.asitplus.signum.indispensable.requireSupported

/**
 * The meat of a PKCS#10 Certification Request:
 * The structure that gets signed
 * @param version defaults to 0
 * @param subjectName list of subject distinguished names
 * @param publicKey nomen est omen
 * @param attributes nomen est omen
 */
data class TbsCertificationRequest(
    val version: Int = 0,
    val subjectName: X500Name,
    val publicKey: CryptoPublicKey,
    val attributes: List<Pkcs10CertificationRequestAttribute> = listOf()
) : Asn1Encodable<Asn1Sequence> {

    /**
     * Convenience constructor for adding [X509CertificateExtension]`s` to a CSR (in addition to generic attributes
     *
     * @throws IllegalArgumentException if no extensions are provided
     */
    @Throws(IllegalArgumentException::class)
    constructor(
        subjectName: X500Name,
        publicKey: CryptoPublicKey,
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
        +subjectName

        //subject Public Key
        +publicKey
        +ExplicitlyTagged(0u) { attributes.map { +it } }
    }

    companion object : Asn1Decodable<Asn1Sequence, TbsCertificationRequest> {
        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Sequence) = src.decodeRethrowing {
            val version = (next() as Asn1Primitive).decodeToInt()
            val subject = X500Name.decodeFromTlv(next().asSequence())
            val cryptoPublicKey = CryptoPublicKey.decodeFromTlv(next() as Asn1Sequence)
            val attributes = if (hasNext()) {
                (next() as Asn1ExplicitlyTagged).verifyTag(0u)
                    .map { Pkcs10CertificationRequestAttribute.decodeFromTlv(it as Asn1Sequence) }
            } else null
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
data class Pkcs10CertificationRequest(
    val tbsCsr: TbsCertificationRequest,
    val signatureAlgorithm: X509SignatureAlgorithmDescription,
    val rawSignature: Asn1Primitive
) : PemEncodable<Asn1Sequence> {

    constructor(
        tbsCsr: TbsCertificationRequest,
        signatureAlgorithm: X509SignatureAlgorithmDescription,
        signature: CryptoSignature
    ) : this(tbsCsr, signatureAlgorithm, signature.x509Encoded)

    val decodedSignature by lazy { catching {
        signatureAlgorithm.requireSupported()
        CryptoSignature.fromX509Encoded(signatureAlgorithm, rawSignature)
    } }

    @Deprecated("Imprecisely named and lacks support for unsupported algorithms; use rawSignature or decodedSignature",
        level = DeprecationLevel.ERROR)
    val signature get() = decodedSignature.getOrThrow()

    override val canonicalPEMBoundary: String = EB_STRINGS.DEFAULT

    @Throws(Asn1Exception::class)
    override fun encodeToTlv() = Asn1.Sequence {
        +tbsCsr
        +signatureAlgorithm
        +rawSignature
    }

    companion object : PemDecodable<Asn1Sequence, Pkcs10CertificationRequest>(
        EB_STRINGS.DEFAULT,
        EB_STRINGS.LEGACY
    ) {
        private object EB_STRINGS {
            const val DEFAULT = "CERTIFICATE REQUEST"
            const val LEGACY = "NEW CERTIFICATE REQUEST"
        }
        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Sequence): Pkcs10CertificationRequest = src.decodeRethrowing {
            val tbsCsr = TbsCertificationRequest.decodeFromTlv(next() as Asn1Sequence)
            val sigAlg = X509SignatureAlgorithmDescription.decodeFromTlv(next() as Asn1Sequence)
            val signature = next() as Asn1Primitive
            if (hasNext()) throw Asn1StructuralException("Superfluous structure in CSR Structure")
            Pkcs10CertificationRequest(tbsCsr, sigAlg, signature)
        }
    }
}
