package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1PrimitiveOctetString
import at.asitplus.awesn1.Asn1StructuralException
import at.asitplus.awesn1.crypto.pki.Attribute
import at.asitplus.awesn1.crypto.pki.Pkcs10CertificationRequest
import at.asitplus.awesn1.crypto.pki.Pkcs10CertificationRequestInfo
import at.asitplus.awesn1.crypto.pki.X509CertificateExtension
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.Der
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.internals.orLazy
import kotlinx.serialization.KSerializer

private data class TbsCertificationRequestContent(
    val subjectName: List<RelativeDistinguishedName>,
    val publicKey: CryptoPublicKey,
    val attributes: List<CsrAttribute>,
) {
    constructor(asn1Representation: Pkcs10CertificationRequestInfo) : this(
        subjectName = asn1Representation.subjectName.map { RelativeDistinguishedName(it, performValidation = false) },
        publicKey = CryptoPublicKey(asn1Representation.publicKey),
        attributes = asn1Representation.attributes.map(::CsrAttribute)
    )
}

/**
 * The meat of a Certification Request:
 * The structure that gets signed.
 *
 * @param subjectName list of subject distinguished names
 * @param publicKey nomen est omen
 * @param attributes nomen est omen
 */
class TbsCertificationRequest private constructor(
    providedContent: TbsCertificationRequestContent?, /*TODO EXTENSIBILITY private val*/
    providedAsn1Representation: Pkcs10CertificationRequestInfo?,
) : DerEncodable<Pkcs10CertificationRequestInfo> {

    constructor(
        subjectName: List<RelativeDistinguishedName>,
        publicKey: CryptoPublicKey,
        attributes: List<CsrAttribute> = listOf(),
    ) : this(TbsCertificationRequestContent(subjectName, publicKey, attributes), null) {
        validateAttributes(attributes, allowExtensions = true)
    }

    /**
     * Convenience constructor for adding [CertificateExtension]`s` to a CSR in addition to generic attributes.
     *
     * @throws IllegalArgumentException if an empty extension list is provided
     */
    @Throws(IllegalArgumentException::class)
    constructor(
        subjectName: List<RelativeDistinguishedName>,
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


    override val asn1Representation: Pkcs10CertificationRequestInfo by providedAsn1Representation orLazy {
        requireNotNull(providedContent)
        Pkcs10CertificationRequestInfo(
            version = 1,
            subjectName = providedContent.subjectName.map { it.asn1Representation },
            publicKey = providedContent.publicKey.asn1Representation,
            attributes = providedContent.attributes.map { it.asn1Representation },
        )
    }

    /*TODO EXTENSIBILITY delete, cuz replaced with private val in ctor*/
    private val providedContent: TbsCertificationRequestContent by providedContent orLazy {
        TbsCertificationRequestContent(asn1Representation)
    }

    val subjectName: List<RelativeDistinguishedName> get() = providedContent.subjectName
    val publicKey: CryptoPublicKey get() = providedContent.publicKey
    val attributes: List<CsrAttribute> get() = providedContent.attributes

    val attributesWithoutExtensions: List<CsrAttribute> by lazy { attributes.filterNot { it.oid == Attribute.EXTENSION_REQUEST_OID } }

    val extensions: List<CertificateExtension> by lazy {
        attributes.filter { it.oid == Attribute.EXTENSION_REQUEST_OID }.let { extensionAttributes ->
            when (extensionAttributes.size) {
                0 -> emptyList()
                1 -> extensionAttributes.single().value.single().asSequence().map {
                    DER.decodeFromTlv(X509CertificateExtension.serializer(), it).toSignumExtension()
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


private data class CertificationRequestContent(
    val tbsCsr: TbsCertificationRequest,
    val signatureAlgorithm: SignatureAlgorithm,
    val signature: CryptoSignature,
) {
    constructor(asn1Representation: Pkcs10CertificationRequest) : this(
        tbsCsr = TbsCertificationRequest(asn1Representation.certificationRequestInfo),
        signatureAlgorithm = SignatureAlgorithm(asn1Representation.signatureAlgorithm),
        signature = CryptoSignature(asn1Representation.signatureAlgorithm.oid, asn1Representation.signatureValue)
    )
}


/**
 * Very simple implementation of a PKCS#10 Certification Request.
 */
class CertificationRequest private constructor(
    providedContent: CertificationRequestContent?, /*TODO EXTENSIBILITY private val */
    providedAsn1Representation: Pkcs10CertificationRequest?,
) : DerPemEncodable<Pkcs10CertificationRequest> {

    override val pemLabel: String get() = canonicalPemLabel

    constructor(
        tbsCsr: TbsCertificationRequest,
        signatureAlgorithm: SignatureAlgorithm,
        signature: CryptoSignature,
    ) : this(CertificationRequestContent(tbsCsr, signatureAlgorithm, signature), null)

    constructor(asn1Representation: Pkcs10CertificationRequest) : this(
        null /*TODO EXTENSIBILITY CertificationRequestContent(asn1Representation) */,
        asn1Representation
    )


    override val asn1Representation: Pkcs10CertificationRequest by providedAsn1Representation orLazy {
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

    companion object : DerPemDecodable<Pkcs10CertificationRequest, CertificationRequest> {

        override val canonicalPemLabel: String get() = Pkcs10CertificationRequest.canonicalPemLabel
        override val validPemLabels: Set<String> get() = Pkcs10CertificationRequest.validPemLabels

        @Throws(Asn1Exception::class)
        override fun decodeFromTlv(
            serializer: KSerializer<Pkcs10CertificationRequest>,
            src: Asn1Element,
            der: Der,
        ): CertificationRequest =
            CertificationRequest(der.decodeFromTlv(serializer, src))
    }
}

private fun validateAttributes(attributes: List<CsrAttribute>, allowExtensions: Boolean = false) {
    require(attributes.distinctBy { it.oid }.size == attributes.size) { "Multiple attributes with same OID found" }
    if (!allowExtensions) require(attributes.none { it.oid == Attribute.EXTENSION_REQUEST_OID }) {
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
            add(CsrAttribute(Attribute.CertificateExtension(it.map(CertificateExtension::toAwesn1Extension))))
        }
    }
}

private fun CertificateExtension.toAwesn1Extension(): X509CertificateExtension =
    X509CertificateExtension(
        oid = oid,
        critical = critical.takeIf { it },
        value = value.asOctetString().content,
    )

private fun X509CertificateExtension.toSignumExtension(): CertificateExtension =
    CertificateExtension(
        oid = oid,
        critical = critical ?: false,
        value = Asn1PrimitiveOctetString(value),
    )
