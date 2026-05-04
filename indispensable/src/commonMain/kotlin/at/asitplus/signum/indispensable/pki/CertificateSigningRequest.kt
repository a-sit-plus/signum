package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1PemEncodable
import at.asitplus.awesn1.Asn1Sequence
import at.asitplus.awesn1.crypto.SignatureValue
import at.asitplus.awesn1.crypto.pki.Attribute
import at.asitplus.awesn1.crypto.pki.Pkcs10CertificationRequest
import at.asitplus.awesn1.crypto.pki.Pkcs10CertificationRequestInfo
import at.asitplus.awesn1.crypto.pki.X509CertificateExtension
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.decodeFromTlv
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
    ) : this(
        Pkcs10CertificationRequestInfo(
            version = version,
            subjectName = subjectName.map { it.backing },
            publicKey = publicKey.toSubjectPublicKeyInfo(),
            attributes.mergeWith(extensions)
        )
    )

    @get:Throws(Asn1Exception::class)
    val subjectName: List<RelativeDistinguishedName> by lazy {
        backing.subjectName.map {
            RelativeDistinguishedName(
                backing = it,
                performValidation = false
            )
        }
    }

    @get:Throws(Asn1Exception::class)
    val publicKey: CryptoPublicKey by lazy { CryptoPublicKey.fromSubjectPublicKeyInfo(backing.publicKey) }


    /**
     * Attributes withouth certificate extensions.
     * If you want everything, use `backing.attributes`
     */
    val attributes: List<Attribute> by lazy { backing.attributes.filterNot { it.oid == Attribute.EXTENSION_REQUEST_OID } }


    @get:Throws(Asn1Exception::class)
    val extensions: List<X509CertificateExtension> by lazy {
        runRethrowing {
            backing.attributes.single { it.oid == Attribute.EXTENSION_REQUEST_OID }.let { extensionValue ->
                require(extensionValue.value.size == 1) { "Multiple extension value s found!" }
                (extensionValue.value.first() as Asn1Sequence).map {
                    DER.decodeFromTlv<X509CertificateExtension>(it)
                }
            }
        }
    }


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
data class CertificateSigningRequest(
    override val backing: Pkcs10CertificationRequest,
) : Awesn1Backed<Pkcs10CertificationRequest>, Asn1PemEncodable<Asn1Sequence> {

    override val pemLabel: String get() = Pkcs10CertificationRequest.PEM_LABEL

    constructor(
        tbsCsr: TbsCertificationRequest,
        signatureAlgorithm: X509SignatureAlgorithmDescription,
        rawSignature: SignatureValue
    ) : this(Pkcs10CertificationRequest(tbsCsr.backing, signatureAlgorithm.toIdentifier(), rawSignature))

    constructor(
        tbsCsr: TbsCertificationRequest,
        signatureAlgorithm: X509SignatureAlgorithmDescription,
        signature: CryptoSignature
    ) : this(tbsCsr, signatureAlgorithm, signature.x509Encoded)

    val tbsCsr: TbsCertificationRequest by lazy { TbsCertificationRequest(backing.certificationRequestInfo) }
    val signatureAlgorithm: X509SignatureAlgorithmDescription =
        X509SignatureAlgorithmDescription.decodeFromTlv(rawSignatureAlgorithm)

    val decodedSignature by lazy {
        catching {
            signatureAlgorithm.requireSupported()
            CryptoSignature.fromX509Encoded(signatureAlgorithm, rawSignature)
        }
    }

    val rawSignature: SignatureValue by lazy { backing.signatureValue }

    override val canonicalPEMBoundary: String = EB_STRINGS.DEFAULT



    companion object : PemDecodable<Asn1Sequence, CertificateSigningRequest>(
        EB_STRINGS.DEFAULT,
        EB_STRINGS.LEGACY
    ) {
        private object EB_STRINGS {
            const val DEFAULT = "CERTIFICATE REQUEST"
            const val LEGACY = "NEW CERTIFICATE REQUEST"
        }

        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Sequence): CertificateSigningRequest = src.decodeRethrowing {
            val tbsCsr = next() as Asn1Sequence
            val sigAlg = next() as Asn1Sequence
            val signature = next() as Asn1Primitive
            if (hasNext()) throw Asn1StructuralException("Superfluous structure in CSR Structure")
            CertificateSigningRequest(tbsCsr, sigAlg, signature)
        }
    }
}
