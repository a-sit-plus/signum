package at.asitplus.signum.indispensable.pki

import at.asitplus.catching
import at.asitplus.awesn1.*
import at.asitplus.awesn1.encoding.asAsn1BitString
import at.asitplus.awesn1.crypto.SignatureAlgorithmIdentifier
import at.asitplus.awesn1.crypto.SubjectPublicKeyInfo as RawSubjectPublicKeyInfo
import at.asitplus.awesn1.crypto.pki.Attribute
import at.asitplus.awesn1.crypto.pki.Pkcs10CertificationRequest as RawPkcs10CertificationRequest
import at.asitplus.awesn1.crypto.pki.Pkcs10CertificationRequestInfo as RawPkcs10CertificationRequestInfo
import at.asitplus.awesn1.crypto.pki.RelativeDistinguishedName
import at.asitplus.awesn1.crypto.pki.X509CertificateExtension
import at.asitplus.signum.indispensable.Awesn1Backed
import at.asitplus.signum.indispensable.PublicKey
import at.asitplus.signum.indispensable.Signature
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.asn1.LabelPemDecodable
import at.asitplus.signum.indispensable.toSignatureAlgorithmIdentifier

@Deprecated(
    "Renamed to CertificationRequestInfo.",
    ReplaceWith("CertificationRequestInfo", "at.asitplus.signum.indispensable.pki.CertificationRequestInfo")
)
typealias TbsCertificationRequest = CertificationRequestInfo
/**
 * The meat of a PKCS#10 Certification Request:
 * The structure that gets signed
 * @param version defaults to 0
 * @param subjectName list of subject distinguished names
 * @param publicKey nomen est omen
 * @param attributes nomen est omen
 */
class CertificationRequestInfo(
    override val raw: RawPkcs10CertificationRequestInfo,
) : Asn1Encodable<Asn1Sequence>, Awesn1Backed<RawPkcs10CertificationRequestInfo> {

    @Throws(Asn1Exception::class)
    constructor(
        version: Int = 0,
        subjectName: List<RelativeDistinguishedName>,
        publicKey: PublicKey,
        attributes: List<Attribute> = listOf()
    ) : this(
        raw = RawPkcs10CertificationRequestInfo(
            version = version,
            subjectName = subjectName,
            publicKey = publicKey.raw,
            attributes = attributes
        )
    )
    val version: Int get() = raw.version
    val subjectName: List<RelativeDistinguishedName> get() = raw.subjectName
    val publicKey: PublicKey get() = PublicKey.fromRaw(raw.publicKey)
    val attributes: List<Attribute> get() = raw.attributes

    /**
     * Convenience constructor for adding [X509CertificateExtension]`s` to a CSR (in addition to generic attributes
     *
     * @throws IllegalArgumentException if no extensions are provided
     */
    @Throws(IllegalArgumentException::class)
    constructor(
        subjectName: List<RelativeDistinguishedName>,
        publicKey: PublicKey,
        extensions: List<X509CertificateExtension>? = null,
        version: Int = 0,
        attributes: List<Attribute>? = null,
    ) : this(version, subjectName, publicKey, mutableListOf<Attribute>().also { attrs ->
        attributes?.let { attrs.addAll(it) }
        extensions?.let { extn ->
            attrs.add(Attribute.extensionRequest(extn))
        }
    })

    override fun encodeToTlv() = raw.encodeToTlv()

    override fun equals(other: Any?) = other is CertificationRequestInfo && raw == other.raw

    override fun hashCode(): Int = raw.hashCode()

    companion object : Asn1Decodable<Asn1Sequence, CertificationRequestInfo> {
        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Sequence): CertificationRequestInfo {
            val raw = RawPkcs10CertificationRequestInfo.decodeFromTlv(src)
            return CertificationRequestInfo(raw = raw)
        }
    }
}


/**
 * Very simple implementation of a PKCS#10 Certification Request
 */
@Deprecated(
    "Renamed to CertificationRequest.",
    ReplaceWith("CertificationRequest", "at.asitplus.signum.indispensable.pki.CertificationRequest")
)
typealias Pkcs10CertificationRequest = CertificationRequest

class CertificationRequest(
    override val raw: RawPkcs10CertificationRequest,
) : Asn1PemEncodable<Asn1Sequence>, Awesn1Backed<RawPkcs10CertificationRequest> {
    val tbsCsr: CertificationRequestInfo by lazy { CertificationRequestInfo(raw.certificationRequestInfo) }
    val signatureAlgorithm: SignatureAlgorithmIdentifier get() = raw.signatureAlgorithm
    val rawSignatureValue: Asn1BitString get() = raw.signatureValue

    @Deprecated(
        "Use rawSignatureValue.",
        ReplaceWith("rawSignatureValue")
    )
    val rawSignature: Asn1Primitive get() = rawSignatureValue.encodeToTlv()

    @Throws(Asn1Exception::class)
    constructor(
        tbsCsr: CertificationRequestInfo,
        signatureAlgorithm: SignatureAlgorithmIdentifier,
        rawSignatureValue: Asn1BitString
    ) : this(
        raw = RawPkcs10CertificationRequest(
            certificationRequestInfo = tbsCsr.raw,
            signatureAlgorithm = signatureAlgorithm,
            signatureValue = rawSignatureValue,
        ),
    )

    @Deprecated(
        "Pass an awesn1 Asn1BitString or a Signum Signature instead.",
        ReplaceWith(
            "CertificationRequest(tbsCsr, signatureAlgorithm, Asn1BitString.decodeFromTlv(rawSignature))",
            "at.asitplus.awesn1.Asn1BitString"
        )
    )
    constructor(
        tbsCsr: CertificationRequestInfo,
        signatureAlgorithm: SignatureAlgorithmIdentifier,
        rawSignature: Asn1Primitive
    ) : this(
        tbsCsr,
        signatureAlgorithm,
        Asn1BitString.decodeFromTlv(rawSignature)
    )

    constructor(
        tbsCsr: CertificationRequestInfo,
        signatureAlgorithm: SignatureAlgorithmIdentifier,
        signature: Signature
    ) : this(tbsCsr, signatureAlgorithm, signature.x509SignatureValue)

    @Throws(Asn1Exception::class)
    constructor(
        tbsCsr: CertificationRequestInfo,
        signatureAlgorithm: SignatureAlgorithm,
        rawSignatureValue: Asn1BitString
    ) : this(
        tbsCsr = tbsCsr,
        signatureAlgorithm = signatureAlgorithm.toSignatureAlgorithmIdentifier().getOrThrow(),
        rawSignatureValue = rawSignatureValue
    )

    @Throws(Asn1Exception::class)
    constructor(
        tbsCsr: CertificationRequestInfo,
        signatureAlgorithm: SignatureAlgorithm,
        signature: Signature
    ) : this(
        tbsCsr = tbsCsr,
        signatureAlgorithm = signatureAlgorithm.toSignatureAlgorithmIdentifier().getOrThrow(),
        signature = signature
    )

    val decodedSignature: at.asitplus.KmmResult<Signature> by lazy { catching {
        Signature.fromX509Encoded(signatureAlgorithm, rawSignatureValue)
    } }

    @Deprecated("Imprecisely named and lacks support for unsupported algorithms; use rawSignature or decodedSignature",
        level = DeprecationLevel.ERROR)
    val signature get() = decodedSignature.getOrThrow()

    override val pemLabel: String = EB_STRINGS.DEFAULT

    @Throws(Asn1Exception::class)
    override fun encodeToTlv() = raw.encodeToTlv()

    override fun equals(other: Any?) = other is CertificationRequest && raw == other.raw

    override fun hashCode(): Int = raw.hashCode()

    companion object : LabelPemDecodable<Asn1Sequence, CertificationRequest>(
        EB_STRINGS.DEFAULT,
        EB_STRINGS.LEGACY
    ) {
        private object EB_STRINGS {
            const val DEFAULT = "CERTIFICATE REQUEST"
            const val LEGACY = "NEW CERTIFICATE REQUEST"
        }
        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Sequence): CertificationRequest {
            return CertificationRequest(RawPkcs10CertificationRequest.decodeFromTlv(src))
        }
    }
}
