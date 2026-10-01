package at.asitplus.signum.indispensable.pki
import at.asitplus.signum.indispensable.sign.invoke
import at.asitplus.signum.indispensable.Encodable
import at.asitplus.signum.indispensable.sign.asn1Representation

import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1StructuralException
import at.asitplus.awesn1.allDistinctByOids
import at.asitplus.awesn1.crypto.pki.Pkcs10CsrAttribute
import at.asitplus.awesn1.crypto.pki.Pkcs10CertificationRequest
import at.asitplus.awesn1.crypto.pki.Pkcs10CertificationRequestInfo
import at.asitplus.awesn1.serialization.DER
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.sign.SignatureAlgorithm
import at.asitplus.signum.internals.orLazy
import at.asitplus.awesn1.crypto.pki.X509CertificateExtension as Awesn1X509CertificateExtension
/**
 * The meat of a Certification Request:
 * The structure that gets signed.
 *
 * @param subjectName list of subject distinguished names
 * @param publicKey nomen est omen
 * @param attributes nomen est omen
 */
class TbsCertificationRequest private constructor(
    providedContent: ContentContainer?, /*TODO EXTENSIBILITY private val*/
    providedAsn1Representation: Pkcs10CertificationRequestInfo?,
) : Encodable {
    init { require((providedContent != null) != (providedAsn1Representation != null)) }

    private data class ContentContainer(
        val subjectName: Name,
        val publicKey: CryptoPublicKey,
        val attributes: List<CsrAttribute>,
    ) {
        constructor(asn1Representation: Pkcs10CertificationRequestInfo) : this(
            subjectName = X500Name(asn1Representation.subjectName.map { RelativeDistinguishedName(it, performValidation = false) }, false),
            publicKey = CryptoPublicKey(asn1Representation.publicKey),
            attributes = asn1Representation.attributes.map { CsrAttribute(it) }
        )
    }

    constructor(
        subjectName: Name,
        publicKey: CryptoPublicKey,
        attributes: List<CsrAttribute> = listOf(),
    ) : this(ContentContainer(subjectName, publicKey, attributes), null) {
        validateAttributes(attributes, allowExtensions = true)
    }

    /**
     * Convenience constructor for adding [CertificateExtension]`s` to a CSR in addition to generic attributes.
     *
     * @throws IllegalArgumentException if an empty extension list is provided
     */
    @Throws(IllegalArgumentException::class)
    constructor(
        subjectName: Name,
        publicKey: CryptoPublicKey,
        extensions: List<CertificateExtension>? = null,
        attributesWithoutExtensions: List<CsrAttribute>? = null,
    ) : this(
        subjectName = subjectName,
        publicKey = publicKey,
        attributes = mergeAttributesWithExtensions(attributesWithoutExtensions, extensions),
    )

    constructor(asn1Representation: Pkcs10CertificationRequestInfo) : this(
        null/*TODO EXTENSIBILITY TbsCertificationRequestContent(asn1Representation)*/,
        asn1Representation
    )

    override val representations: Map<Encodable.Representation, Any>

        get() = mapOf(X509 to x509Model)

    internal val x509Model: Pkcs10CertificationRequestInfo by providedAsn1Representation orLazy {
        requireNotNull(providedContent)
        Pkcs10CertificationRequestInfo(
            subjectName = requireNotNull(providedContent.subjectName.asn1Representation) { "Subject has no X.509 representation" },
            publicKey = providedContent.publicKey.asn1Representation,
            attributes = providedContent.attributes.mapTo(mutableSetOf()) { requireNotNull(it.asn1Representation) { "Value has no X.509 representation" } },
        )
    }

    /*TODO EXTENSIBILITY delete, cuz replaced with private val in ctor*/
    private val providedContent: ContentContainer by providedContent orLazy {
        ContentContainer(asn1Representation)
    }

    val subjectName: Name get() = providedContent.subjectName
    val publicKey: CryptoPublicKey get() = providedContent.publicKey
    val attributes: List<CsrAttribute> get() = providedContent.attributes

    val attributesWithoutExtensions: List<CsrAttribute> by lazy { attributes.filterNot { it.oid == Pkcs10CsrAttribute.EXTENSION_REQUEST_OID } }

    val extensions: List<CertificateExtension> by lazy {
        attributes.filter { it.oid == Pkcs10CsrAttribute.EXTENSION_REQUEST_OID }.let { extensionAttributes ->
            when (extensionAttributes.size) {
                0 -> emptyList()
                1 -> requireNotNull(extensionAttributes.single().asn1Representation).value.single().asSequence().map {
                    CertificateExtension(DER.decodeFromTlv(Awesn1X509CertificateExtension.serializer(), it))
                }

                else -> throw Asn1StructuralException("Multiple extensionRequest attributes found")
            }
        }
    }

    /*TODO EXTENSIBILITY temp PFUSCH good enough for regression tests*/
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is TbsCertificationRequest) return false
        return subjectName == other.subjectName &&
                publicKey == other.publicKey &&
                attributes == other.attributes
    }

    /*TODO EXTENSIBILITY temp PFUSCH good enough for regression tests*/
    override fun hashCode(): Int {
        var result = subjectName.hashCode()
        result = 31 * result + publicKey.hashCode()
        result = 31 * result + attributes.hashCode()
        return result
    }

    override fun toString(): String =
        "TbsCertificationRequest(subjectName=$subjectName, publicKey=$publicKey, attributes=$attributes)"

    companion object : Decodable<TbsCertificationRequest> {
        @Throws(Asn1Exception::class)
        fun fromAsn1Representation(
            element: Pkcs10CertificationRequestInfo): TbsCertificationRequest =
            TbsCertificationRequest(element)
    }
}

private data class CertificationRequestContent(
    val tbsCsr: TbsCertificationRequest,
    val signatureAlgorithm: SignatureAlgorithm,
    val signature: CryptoSignature,
) {
    constructor(asn1Representation: Pkcs10CertificationRequest) : this(
        tbsCsr = TbsCertificationRequest(asn1Representation.certificationRequestInfo),
        signatureAlgorithm = SignatureAlgorithm(asn1Representation.signatureAlgorithm),
        signature = CryptoSignature(asn1Representation.signatureAlgorithm, asn1Representation.signatureValue)
    )
}

/**
 * Very simple implementation of a PKCS#10 Certification Request.
 */
class CertificationRequest private constructor(
    providedContent: CertificationRequestContent?, /*TODO EXTENSIBILITY private val */
    providedAsn1Representation: Pkcs10CertificationRequest?,
) : Encodable {
    init { require((providedContent != null) != (providedAsn1Representation != null)) }

    constructor(
        tbsCsr: TbsCertificationRequest,
        signatureAlgorithm: SignatureAlgorithm,
        signature: CryptoSignature,
    ) : this(CertificationRequestContent(tbsCsr, signatureAlgorithm, signature), null)

    constructor(asn1Representation: Pkcs10CertificationRequest) : this(
        null /*TODO EXTENSIBILITY CertificationRequestContent(asn1Representation) */,
        asn1Representation
    )

    override val representations: Map<Encodable.Representation, Any>

        get() = mapOf(X509 to x509Model)

    internal val x509Model: Pkcs10CertificationRequest by providedAsn1Representation orLazy {
        requireNotNull(providedContent)
        Pkcs10CertificationRequest(
            certificationRequestInfo = providedContent.tbsCsr.asn1Representation,
            signatureAlgorithm = providedContent.signatureAlgorithm.asn1Representation,
            signatureValue = providedContent.signature.asn1Representation,
        )
    }

    /*TODO EXTENSIBILITY delete, cuz replaced with private val in ctor*/
    private val providedContent: CertificationRequestContent by lazy {
        CertificationRequestContent(
            asn1Representation
        )
    }

    val tbsCsr: TbsCertificationRequest get() = providedContent.tbsCsr
    val signatureAlgorithm: SignatureAlgorithm get() = providedContent.signatureAlgorithm
    val signature: CryptoSignature get() = providedContent.signature

    /*TODO EXTENSIBILITY temp PFUSCH good enough for regression tests*/
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CertificationRequest) return false
        return tbsCsr == other.tbsCsr &&
                signatureAlgorithm == other.signatureAlgorithm &&
                signature == other.signature
    }

    /*TODO EXTENSIBILITY temp PFUSCH good enough for regression tests*/
    override fun hashCode(): Int {
        var result = tbsCsr.hashCode()
        result = 31 * result + signatureAlgorithm.hashCode()
        result = 31 * result + signature.hashCode()
        return result
    }

    override fun toString(): String =
        "Pkcs10CertificationRequest(tbsCsr=$tbsCsr, signatureAlgorithm=$signatureAlgorithm, signature=$signature)"

    companion object : Decodable<CertificationRequest> {

        @Throws(Asn1Exception::class)
        fun fromAsn1Representation(
            element: Pkcs10CertificationRequest): CertificationRequest =
            CertificationRequest(element)
    }
}

private fun validateAttributes(attributes: List<CsrAttribute>, allowExtensions: Boolean = false) {
    require(attributes.allDistinctByOids()) { "Multiple attributes with same OID found" }
    if (!allowExtensions) require(attributes.none { it.oid == Pkcs10CsrAttribute.EXTENSION_REQUEST_OID }) {
        "Certificate extension passed as part of regular attributes"
    }
}

private fun mergeAttributesWithExtensions(
    attributes: List<CsrAttribute>?,
    extensions: List<CertificateExtension>?,
): List<CsrAttribute> {
    attributes?.let(::validateAttributes)
    extensions?.let { require(it.isNotEmpty()) { "At least one extension is required" } }

    return mutableListOf<CsrAttribute>().apply {
        attributes?.let { addAll(it) }
        extensions?.let {
            add(CsrAttribute(Pkcs10CsrAttribute.ExtensionRequest(it.map { extension ->
                extension.asn1Representation
                    ?: throw Asn1Exception("Certificate extension ${extension.oid} has no X.509/DER representation")
            })))
        }
    }
}
