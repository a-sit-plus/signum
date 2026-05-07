package at.asitplus.signum.indispensable.pki

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1Primitive
import at.asitplus.awesn1.Asn1PrimitiveOctetString
import at.asitplus.awesn1.Asn1Sequence
import at.asitplus.awesn1.Asn1StructuralException
import at.asitplus.awesn1.crypto.pki.Attribute
import at.asitplus.awesn1.crypto.pki.Pkcs10CertificationRequestInfo
import at.asitplus.awesn1.crypto.pki.X509CertificateExtension as Awesn1X509CertificateExtension
import at.asitplus.awesn1.crypto.pki.Pkcs10CertificationRequest as Awesn1Pkcs10CertificationRequest
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.Der
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.DerDecodable
import at.asitplus.signum.indispensable.DerEncodable
import at.asitplus.signum.indispensable.X509Signature
import at.asitplus.signum.indispensable.X509SignatureAsn1Representation
import at.asitplus.signum.indispensable.X509SignatureAlgorithmDescription
import at.asitplus.signum.internals.orLazy
import kotlinx.serialization.KSerializer

private data class TbsCertificationRequestContent(
    val version: Int,
    val subjectName: List<RelativeDistinguishedName>,
    val publicKey: CryptoPublicKey,
    val attributes: List<CsrAttribute>,
)

private data class Pkcs10CertificationRequestContent(
    val tbsCsr: TbsCertificationRequest,
    val x509Signature: X509Signature,
)

/**
 * The meat of a Certification Request:
 * The structure that gets signed.
 *
 * @param version semantic CSR version, defaults to 1; DER encodes this as raw version 0.
 * @param subjectName list of subject distinguished names
 * @param publicKey nomen est omen
 * @param attributes nomen est omen
 */
class TbsCertificationRequest private constructor(
    providedAsn1Representation: Pkcs10CertificationRequestInfo?,
    providedContent: TbsCertificationRequestContent?,
) : DerEncodable<Pkcs10CertificationRequestInfo> {

    constructor(
        version: Int = 1,
        subjectName: List<RelativeDistinguishedName>,
        publicKey: CryptoPublicKey,
        attributes: List<CsrAttribute> = listOf(),
    ) : this(null, TbsCertificationRequestContent(version, subjectName, publicKey, attributes)) {
        validateAttributes(attributes)
    }

    /**
     * Convenience constructor for adding [X509CertificateExtension]`s` to a CSR in addition to generic attributes.
     *
     * @throws IllegalArgumentException if an empty extension list is provided
     */
    @Throws(IllegalArgumentException::class)
    constructor(
        subjectName: List<RelativeDistinguishedName>,
        publicKey: CryptoPublicKey,
        extensions: List<X509CertificateExtension>? = null,
        version: Int = 1,
        attributes: List<CsrAttribute>? = null,
    ) : this(
        version = version,
        subjectName = subjectName,
        publicKey = publicKey,
        attributes = mergeAttributesWithExtensions(attributes, extensions),
    )

    constructor(asn1Representation: Pkcs10CertificationRequestInfo) : this(asn1Representation, null)

    override val asn1Representation: Pkcs10CertificationRequestInfo by providedAsn1Representation orLazy {
        val content = requireNotNull(providedContent)
        Pkcs10CertificationRequestInfo(
            version = content.version,
            subjectName = content.subjectName.map { it.asn1Representation },
            publicKey = content.publicKey.asn1Representation,
            attributes = content.attributes.map { it.asn1Representation },
        )
    }

    val version: Int by providedContent?.version orLazy {
        asn1Representation.version
    }

    val subjectName: List<RelativeDistinguishedName> by providedContent?.subjectName orLazy {
        asn1Representation.subjectName.map {
            RelativeDistinguishedName(it, performValidation = false)
        }
    }

    val publicKey: CryptoPublicKey by providedContent?.publicKey orLazy {
        CryptoPublicKey(asn1Representation.publicKey)
    }

    val attributes: List<CsrAttribute> by providedContent?.attributes orLazy {
        asn1Representation.attributes.map(::CsrAttribute)
    }

    val extensions: List<X509CertificateExtension> by lazy {
        attributes.filter { it.oid == Attribute.EXTENSION_REQUEST_OID }.let { extensionAttributes ->
            when (extensionAttributes.size) {
                0 -> emptyList()
                1 -> extensionAttributes.single().value.single().asSequence().map {
                    DER.decodeFromTlv(Awesn1X509CertificateExtension.serializer(), it).toSignumExtension()
                }
                else -> throw Asn1StructuralException("Multiple extensionRequest attributes found")
            }
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is TbsCertificationRequest) return false
        return version == other.version &&
            subjectName == other.subjectName &&
            publicKey == other.publicKey &&
            attributes == other.attributes
    }

    override fun hashCode(): Int {
        var result = version
        result = 31 * result + subjectName.hashCode()
        result = 31 * result + publicKey.hashCode()
        result = 31 * result + attributes.hashCode()
        return result
    }

    override fun toString(): String =
        "TbsCertificationRequest(version=$version, subjectName=$subjectName, publicKey=$publicKey, attributes=$attributes)"

    companion object : DerDecodable<Pkcs10CertificationRequestInfo, TbsCertificationRequest> {
        @Throws(Asn1Exception::class)
        override fun decodeFromTlv(
            serializer: KSerializer<Pkcs10CertificationRequestInfo>,
            src: Asn1Element,
            der: Der,
        ): TbsCertificationRequest =
            TbsCertificationRequest(der.decodeFromTlv(serializer, src))
    }
}

/**
 * Very simple implementation of a PKCS#10 Certification Request.
 */
class CertificationRequest private constructor(
    providedAsn1Representation: Awesn1Pkcs10CertificationRequest?,
    providedContent: Pkcs10CertificationRequestContent?,
) : DerEncodable<Awesn1Pkcs10CertificationRequest> {

    constructor(
        tbsCsr: TbsCertificationRequest,
        signatureAlgorithm: X509SignatureAlgorithmDescription,
        rawSignature: Asn1Primitive,
    ) : this(null, Pkcs10CertificationRequestContent(tbsCsr, X509Signature(signatureAlgorithm, rawSignature)))

    constructor(
        tbsCsr: TbsCertificationRequest,
        signatureAlgorithm: X509SignatureAlgorithmDescription,
        signature: CryptoSignature,
    ) : this(null, Pkcs10CertificationRequestContent(tbsCsr, X509Signature(signatureAlgorithm, signature)))

    internal constructor(asn1Representation: Awesn1Pkcs10CertificationRequest) : this(asn1Representation, null)

    override val asn1Representation: Awesn1Pkcs10CertificationRequest by providedAsn1Representation orLazy {
        val content = requireNotNull(providedContent)
        Awesn1Pkcs10CertificationRequest(
            certificationRequestInfo = content.tbsCsr.asn1Representation,
            signatureAlgorithm = content.x509Signature.asn1Representation.algorithmIdentifier,
            signatureValue = content.x509Signature.asn1Representation.signatureValue,
        )
    }

    val tbsCsr: TbsCertificationRequest by providedContent?.tbsCsr orLazy {
        TbsCertificationRequest(asn1Representation.certificationRequestInfo)
    }

    val x509Signature: X509Signature by providedContent?.x509Signature orLazy {
        X509Signature(
            X509SignatureAsn1Representation(
                algorithmIdentifier = asn1Representation.signatureAlgorithm,
                signatureValue = asn1Representation.signatureValue,
            )
        )
    }

    val signatureAlgorithm: X509SignatureAlgorithmDescription get() = x509Signature.signatureAlgorithm

    val rawSignature: Asn1Primitive get() = x509Signature.rawSignature

    val rawTbsCsr: Asn1Sequence by (providedContent?.tbsCsr?.encodeToTlv(Pkcs10CertificationRequestInfo.serializer()) as Asn1Sequence?) orLazy {
        DER.encodeToTlv(Pkcs10CertificationRequestInfo.serializer(), asn1Representation.certificationRequestInfo) as Asn1Sequence
    }

    val rawSignatureAlgorithm: Asn1Sequence get() = x509Signature.rawSignatureAlgorithm

    val decodedSignature: KmmResult<CryptoSignature> get() = x509Signature.decodedSignature

    @Deprecated(
        "Imprecisely named and lacks support for unsupported algorithms; use rawSignature or decodedSignature",
        level = DeprecationLevel.ERROR,
    )
    val signature get() = decodedSignature.getOrThrow()

    // PEM disabled during awesn1 migration.

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CertificationRequest) return false
        return tbsCsr == other.tbsCsr &&
            x509Signature == other.x509Signature
    }

    override fun hashCode(): Int {
        var result = tbsCsr.hashCode()
        result = 31 * result + x509Signature.hashCode()
        return result
    }

    override fun toString(): String =
        "Pkcs10CertificationRequest(tbsCsr=$tbsCsr, signatureAlgorithm=$signatureAlgorithm, rawSignature=$rawSignature)"

    companion object : DerDecodable<Awesn1Pkcs10CertificationRequest, CertificationRequest> {
        private object EB_STRINGS {
            const val DEFAULT = "CERTIFICATE REQUEST"
            const val LEGACY = "NEW CERTIFICATE REQUEST"
        }

        @Throws(Asn1Exception::class)
        override fun decodeFromTlv(
            serializer: KSerializer<Awesn1Pkcs10CertificationRequest>,
            src: Asn1Element,
            der: Der,
        ): CertificationRequest =
            CertificationRequest(der.decodeFromTlv(serializer, src))
    }
}

private fun validateAttributes(attributes: List<CsrAttribute>) {
    require(attributes.distinctBy { it.oid }.size == attributes.size) { "Multiple attributes with same OID found" }
    require(attributes.none { it.oid == Attribute.EXTENSION_REQUEST_OID }) {
        "Certificate extension passed as part of regular attributes"
    }
}

private fun mergeAttributesWithExtensions(
    attributes: List<CsrAttribute>?,
    extensions: List<X509CertificateExtension>?,
): List<CsrAttribute> {
    attributes?.let(::validateAttributes)
    extensions?.let { require(it.isNotEmpty()) { "At least one extension is required" } }

    return mutableListOf<CsrAttribute>().apply {
        attributes?.let { addAll(it) }
        extensions?.let {
            add(CsrAttribute(Attribute.CertificateExtension(it.map(X509CertificateExtension::toAwesn1Extension))))
        }
    }
}

private fun X509CertificateExtension.toAwesn1Extension(): Awesn1X509CertificateExtension =
    Awesn1X509CertificateExtension(
        oid = oid,
        critical = critical.takeIf { it },
        value = value.asOctetString().content,
    )

private fun Awesn1X509CertificateExtension.toSignumExtension(): X509CertificateExtension =
    X509CertificateExtension(
        oid = oid,
        critical = critical ?: false,
        value = Asn1PrimitiveOctetString(value),
    )
