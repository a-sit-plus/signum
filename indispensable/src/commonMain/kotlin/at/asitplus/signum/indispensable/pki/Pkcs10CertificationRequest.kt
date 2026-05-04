package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.Asn1Sequence
import at.asitplus.awesn1.crypto.pki.Attribute
import at.asitplus.awesn1.crypto.pki.Pkcs10CertificationRequestInfo
import at.asitplus.awesn1.crypto.pki.X509CertificateExtension
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.serialization.encodeToTlv
import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.X509SignatureAlgorithmDescription
import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.requireSupported
import kotlinx.serialization.Serializable

/**
 * The meat of a PKCS#10 Certification Request, backed by a raw [Pkcs10CertificationRequestInfo]
 *
 * @see Pkcs10CertificationRequestInfo
 */
@Serializable(with = TbsCertificationRequest.Companion::class)
data class TbsCertificationRequest(
    override val backing: Pkcs10CertificationRequestInfo
) : Awesn1Backed<Pkcs10CertificationRequestInfo> {

    /**
     * @param version defaults to 1 (**Note that this is the semantic version! The actually encoded version is [version]-1.**)
     * @param subjectName list of subject distinguished names
     * @param publicKey nomen est omen
     * @param attributes nomen est omen
     */
    @Throws(IllegalArgumentException::class)
    constructor(
        subjectName: List<RelativeDistinguishedName>,
        publicKey: CryptoPublicKey,
        extensions: List<X509CertificateExtension>? = null,
        attributes: List<Attribute>? = null,
        version: Int = 1,
    ) : this(Pkcs10CertificationRequestInfo(version=version, subjectName=subjectName))

    companion object : Awesn1BackedSerializer<Pkcs10CertificationRequestInfo, TbsCertificationRequest>(
        Pkcs10CertificationRequestInfo.serializer(),
        ::TbsCertificationRequest,
    ) {

    }
}
private fun List<Attribute>?.mergeWith(
    extensions: List<X509CertificateExtension>?,
): List<Attribute> {

    runRethrowing {
        this?.let {
            require(it.distinctBy { it.oid }.size == it.size) { "Multiple attributes with same OID found" }
            require(it.firstOrNull { it.oid == Attribute.EXTENSION_REQUEST_OID } == null) { "Certificate extension passed as part of regular attributes" }
        }
    }
    return mutableListOf<Attribute>().apply {
        this@mergeWith?.let { addAll(it) }
        extensions?.let { add(Attribute.CertificateExtension(it)) }
    }

}

/**
 * Very simple implementation of a PKCS#10 Certification Request
 */
@ConsistentCopyVisibility
data class Pkcs10CertificationRequest private constructor(
    val rawTbsCsr: Asn1Sequence,
    val rawSignatureAlgorithm: Asn1Sequence,
    val rawSignature: Asn1Primitive
) : PemEncodable<Asn1Sequence> {

    constructor(
        tbsCsr: TbsCertificationRequest,
        signatureAlgorithm: X509SignatureAlgorithmDescription,
        rawSignature: Asn1Primitive
    ) : this(tbsCsr.encodeToTlv(), signatureAlgorithm.encodeToTlv(), rawSignature)

    constructor(
        tbsCsr: TbsCertificationRequest,
        signatureAlgorithm: X509SignatureAlgorithmDescription,
        signature: CryptoSignature
    ) : this(tbsCsr, signatureAlgorithm, signature.x509Encoded)

    val tbsCsr: TbsCertificationRequest = TbsCertificationRequest.decodeFromTlv(rawTbsCsr)
    val signatureAlgorithm: X509SignatureAlgorithmDescription =
        X509SignatureAlgorithmDescription.decodeFromTlv(rawSignatureAlgorithm)

    val decodedSignature by lazy {
        catching {
            signatureAlgorithm.requireSupported()
            CryptoSignature.fromX509Encoded(signatureAlgorithm, rawSignature)
        }
    }

    @Deprecated(
        "Imprecisely named and lacks support for unsupported algorithms; use rawSignature or decodedSignature",
        level = DeprecationLevel.ERROR
    )
    val signature get() = decodedSignature.getOrThrow()

    override val canonicalPEMBoundary: String = EB_STRINGS.DEFAULT

    @Throws(Asn1Exception::class)
    override fun encodeToTlv() = Asn1.Sequence {
        +rawTbsCsr
        +rawSignatureAlgorithm
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
            val tbsCsr = next() as Asn1Sequence
            val sigAlg = next() as Asn1Sequence
            val signature = next() as Asn1Primitive
            if (hasNext()) throw Asn1StructuralException("Superfluous structure in CSR Structure")
            Pkcs10CertificationRequest(tbsCsr, sigAlg, signature)
        }
    }
}
