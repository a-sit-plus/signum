package at.asitplus.signum.indispensable.pki

import at.asitplus.catching
import at.asitplus.awesn1.*
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.encoding.Asn1.BitString
import at.asitplus.awesn1.encoding.Asn1.ExplicitlyTagged
import at.asitplus.awesn1.encoding.asAsn1BitString
import at.asitplus.awesn1.encoding.decodeToInt
import at.asitplus.awesn1.crypto.SignatureAlgorithmIdentifier as RawSignatureAlgorithmIdentifier
import at.asitplus.awesn1.crypto.SubjectPublicKeyInfo as RawSubjectPublicKeyInfo
import at.asitplus.awesn1.crypto.pki.Pkcs10CertificationRequest as RawPkcs10CertificationRequest
import at.asitplus.awesn1.crypto.pki.Pkcs10CertificationRequestInfo as RawPkcs10CertificationRequestInfo
import at.asitplus.signum.indispensable.Awesn1Backed
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.signum.indispensable.X509SignatureAlgorithmDescription
import at.asitplus.signum.indispensable.asn1.LabelPemDecodable
import at.asitplus.signum.indispensable.requireSupported

/**
 * The meat of a PKCS#10 Certification Request:
 * The structure that gets signed
 * @param version defaults to 0
 * @param subjectName list of subject distinguished names
 * @param publicKey nomen est omen
 * @param attributes nomen est omen
 */
class TbsCertificationRequest internal constructor(
    override val raw: RawPkcs10CertificationRequestInfo,
    val version: Int = 0,
    val subjectName: List<RelativeDistinguishedName>,
    val publicKey: CryptoPublicKey,
    val attributes: List<Pkcs10CertificationRequestAttribute> = listOf()
) : Asn1Encodable<Asn1Sequence>, Awesn1Backed<RawPkcs10CertificationRequestInfo> {

    @Throws(Asn1Exception::class)
    constructor(
        version: Int = 0,
        subjectName: List<RelativeDistinguishedName>,
        publicKey: CryptoPublicKey,
        attributes: List<Pkcs10CertificationRequestAttribute> = listOf()
    ) : this(
        raw = RawPkcs10CertificationRequestInfo(
            version = version,
            subjectName = subjectName,
            publicKey = RawSubjectPublicKeyInfo.decodeFromTlv(publicKey.encodeToTlv()),
            attributes = attributes
        ),
        version = version,
        subjectName = subjectName,
        publicKey = publicKey,
        attributes = attributes
    )

    /**
     * Convenience constructor for adding [X509CertificateExtension]`s` to a CSR (in addition to generic attributes
     *
     * @throws IllegalArgumentException if no extensions are provided
     */
    @Throws(IllegalArgumentException::class)
    constructor(
        subjectName: List<RelativeDistinguishedName>,
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

    override fun encodeToTlv() = raw.encodeToTlv()

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is TbsCertificationRequest) return false

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
        result = 31 * result + attributes.hashCode()
        return result
    }

    companion object : Asn1Decodable<Asn1Sequence, TbsCertificationRequest> {
        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Sequence) = src.decodeRethrowing {
            val version = (next() as Asn1Primitive).decodeToInt()
            val subject = (next() as Asn1Sequence).children.map {
                RelativeDistinguishedName.decodeFromTlv(it as Asn1Set)
            }
            val cryptoPublicKey = CryptoPublicKey.decodeFromTlv(next() as Asn1Sequence)
            val attributes = if (hasNext()) {
                (next() as Asn1ExplicitlyTagged).verifyTag(0u)
                    .map { Pkcs10CertificationRequestAttribute.decodeFromTlv(it as Asn1Sequence) }
            } else null
            TbsCertificationRequest(
                raw = RawPkcs10CertificationRequestInfo(
                    version = version,
                    subjectName = subject,
                    publicKey = RawSubjectPublicKeyInfo.decodeFromTlv(cryptoPublicKey.encodeToTlv()),
                    attributes = attributes ?: emptyList(),
                ),
                version = version,
                subjectName = subject,
                publicKey = cryptoPublicKey,
                attributes = attributes ?: emptyList(),
            )
        }
    }
}


/**
 * Very simple implementation of a PKCS#10 Certification Request
 */
class Pkcs10CertificationRequest internal constructor(
    override val raw: RawPkcs10CertificationRequest,
    val tbsCsr: TbsCertificationRequest,
    val signatureAlgorithm: X509SignatureAlgorithmDescription,
    val rawSignature: Asn1Primitive
) : Asn1PemEncodable<Asn1Sequence>, Awesn1Backed<RawPkcs10CertificationRequest> {

    @Throws(Asn1Exception::class)
    constructor(
        tbsCsr: TbsCertificationRequest,
        signatureAlgorithm: X509SignatureAlgorithmDescription,
        rawSignature: Asn1Primitive
    ) : this(
        raw = RawPkcs10CertificationRequest(
            certificationRequestInfo = tbsCsr.raw,
            signatureAlgorithm = signatureAlgorithm.toRawSignatureAlgorithmIdentifier(),
            signatureValue = Asn1BitString.decodeFromTlv(rawSignature),
        ),
        tbsCsr = tbsCsr,
        signatureAlgorithm = signatureAlgorithm,
        rawSignature = rawSignature,
    )

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

    override val pemLabel: String = EB_STRINGS.DEFAULT

    @Throws(Asn1Exception::class)
    override fun encodeToTlv() = raw.encodeToTlv()

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Pkcs10CertificationRequest) return false

        if (tbsCsr != other.tbsCsr) return false
        if (signatureAlgorithm != other.signatureAlgorithm) return false
        if (rawSignature != other.rawSignature) return false

        return true
    }

    override fun hashCode(): Int {
        var result = tbsCsr.hashCode()
        result = 31 * result + signatureAlgorithm.hashCode()
        result = 31 * result + rawSignature.hashCode()
        return result
    }

    companion object : LabelPemDecodable<Asn1Sequence, Pkcs10CertificationRequest>(
        EB_STRINGS.DEFAULT,
        EB_STRINGS.LEGACY
    ) {
        private object EB_STRINGS {
            const val DEFAULT = "CERTIFICATE REQUEST"
            const val LEGACY = "NEW CERTIFICATE REQUEST"
        }
        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Sequence): Pkcs10CertificationRequest = src.decodeRethrowing {
            val tbsSequence = next() as Asn1Sequence
            val tbsRaw = RawPkcs10CertificationRequestInfo.decodeFromTlv(tbsSequence)
            val publicKey = CryptoPublicKey.decodeFromTlv(tbsRaw.publicKey.encodeToTlv())
            val tbsCsr = TbsCertificationRequest(
                raw = tbsRaw,
                version = tbsRaw.version,
                subjectName = tbsRaw.subjectName,
                publicKey = publicKey,
                attributes = tbsRaw.attributes,
            )
            val sigAlgRaw = RawSignatureAlgorithmIdentifier.decodeFromTlv(next() as Asn1Sequence)
            val sigAlg = X509SignatureAlgorithmDescription.decodeFromTlv(sigAlgRaw.encodeToTlv())
            val signature = next() as Asn1Primitive
            if (hasNext()) throw Asn1StructuralException("Superfluous structure in CSR Structure")
            Pkcs10CertificationRequest(
                raw = RawPkcs10CertificationRequest(
                    certificationRequestInfo = tbsRaw,
                    signatureAlgorithm = sigAlgRaw,
                    signatureValue = Asn1BitString.decodeFromTlv(signature),
                ),
                tbsCsr = tbsCsr,
                signatureAlgorithm = sigAlg,
                rawSignature = signature,
            )
        }
    }
}

private fun X509SignatureAlgorithmDescription.toRawSignatureAlgorithmIdentifier() =
    RawSignatureAlgorithmIdentifier(oid, parameters)
