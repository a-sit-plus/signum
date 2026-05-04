package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1PemDecodable
import at.asitplus.awesn1.Asn1Sequence
import at.asitplus.awesn1.PemBlock
import at.asitplus.awesn1.PemDecodable
import at.asitplus.awesn1.PemEncodable
import at.asitplus.awesn1.crypto.SignatureValue
import at.asitplus.awesn1.crypto.pki.Attribute
import at.asitplus.awesn1.crypto.pki.Pkcs10CertificationRequest
import at.asitplus.awesn1.crypto.pki.Pkcs10CertificationRequestInfo
import at.asitplus.awesn1.crypto.pki.X509CertificateExtension
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.decodeFromTlv
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.X509SignatureAlgorithmDescription
import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.requireSupported
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

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
) : Awesn1Backed<Pkcs10CertificationRequest>, PemEncodable { //TODO figure out asn1pem foo

    override fun encodeToPemBlock(): PemBlock =
        PemBlock(Pkcs10CertificationRequest.PEM_LABEL, payload = DER.encodeToByteArray(backing))

    constructor(
        tbsCsr: TbsCertificationRequest,
        signatureAlgorithm: X509SignatureAlgorithmDescription,
        rawSignature: SignatureValue
    ) : this(Pkcs10CertificationRequest(tbsCsr.backing, signatureAlgorithm.toAlgorithmIdentifier(), rawSignature))

    constructor(
        tbsCsr: TbsCertificationRequest,
        signatureAlgorithm: X509SignatureAlgorithmDescription,
        signature: CryptoSignature
    ) : this(tbsCsr, signatureAlgorithm, signature.backing)

    val tbsCsr: TbsCertificationRequest by lazy { TbsCertificationRequest(backing.certificationRequestInfo) }
    val signatureAlgorithm: X509SignatureAlgorithmDescription =
        X509SignatureAlgorithmDescription.fromAlgorithmIdentifier(backing.signatureAlgorithm)

    @get:Throws(Asn1Exception::class)
        val decodedSignature: CryptoSignature by lazy {
            runRethrowing {
                signatureAlgorithm.requireSupported()
                CryptoSignature.fromSignatureValue(rawSignature)
            }
        }

    val rawSignature: SignatureValue by lazy { backing.signatureValue }

    //TODO: figure our PEM foo
   // override val canonicalPEMBoundary: String = EB_STRINGS.DEFAULT


    companion object : PemDecodable<CertificateSigningRequest> {
        override fun decodeFromPemBlock(src: PemBlock): CertificateSigningRequest {
           require(src.label == EB_STRINGS.DEFAULT || src.label == EB_STRINGS.LEGACY) {"PEM label mismatch: ${src.label}"}
            return CertificateSigningRequest(DER.decodeFromByteArray(src.payload))
        }

        private object EB_STRINGS {
            const val DEFAULT = "CERTIFICATE REQUEST"
            const val LEGACY = "NEW CERTIFICATE REQUEST"
        }

    }
}
