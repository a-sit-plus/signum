package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1StructuralException
import at.asitplus.awesn1.allDistinctByOids
import at.asitplus.awesn1.crypto.pki.Pkcs10CsrAttribute
import at.asitplus.awesn1.crypto.pki.Pkcs10CertificationRequest
import at.asitplus.awesn1.crypto.pki.Pkcs10CertificationRequestInfo
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.Der
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
    val subjectName: Name,
    val publicKey: CryptoPublicKey,
    val attributes: List<CsrAttribute>,
    providedAsn1Representation: Pkcs10CertificationRequestInfo?,
) : DerEncodable<Pkcs10CertificationRequestInfo> {


    constructor(
        subjectName: Name,
        publicKey: CryptoPublicKey,
        attributes: List<CsrAttribute> = listOf(),
    ) : this(subjectName, publicKey, attributes, null) {
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
        subjectName = X500Name(asn1Representation.subjectName.map { RelativeDistinguishedName(it, performValidation = false) }, false),
        publicKey = CryptoPublicKey(asn1Representation.publicKey),
        attributes = asn1Representation.attributes.map { CsrAttribute(it) },
        providedAsn1Representation = asn1Representation
    )


    override val asn1Representation: Pkcs10CertificationRequestInfo by providedAsn1Representation orLazy {
        Pkcs10CertificationRequestInfo(
            subjectName = subjectName.requireX509().asn1Representation,
            publicKey = publicKey.asn1Representation,
            attributes = attributes.mapTo(mutableSetOf()) { it.requireX509().asn1Representation },
        )
    }

    val attributesWithoutExtensions: List<CsrAttribute> by lazy { attributes.filterNot { it.oid == Pkcs10CsrAttribute.EXTENSION_REQUEST_OID } }

    val extensions: List<CertificateExtension> by lazy {
        attributes.filter { it.oid == Pkcs10CsrAttribute.EXTENSION_REQUEST_OID }.let { extensionAttributes ->
            when (extensionAttributes.size) {
                0 -> emptyList()
                1 -> extensionAttributes.single().requireX509().value.single().asSequence().map {
                    CertificateExtension(DER.decodeFromTlv(Awesn1X509CertificateExtension.serializer(), it))
                }

                else -> throw Asn1StructuralException("Multiple extensionRequest attributes found")
            }
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is TbsCertificationRequest) return false
        return subjectName == other.subjectName &&
                publicKey == other.publicKey &&
                attributes == other.attributes
    }

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
            element: Pkcs10CertificationRequestInfo,
            der: Der,
        ): TbsCertificationRequest =
            TbsCertificationRequest(element)
    }
}


/**
 * Very simple implementation of a PKCS#10 Certification Request.
 */
class CertificationRequest(
    val tbsCsr: TbsCertificationRequest,
    val signatureAlgorithm: SignatureAlgorithm,
    val signature: CryptoSignature,
    providedAsn1Representation: Pkcs10CertificationRequest? = null,
) : DerPemEncodable<Pkcs10CertificationRequest> {

    override val pemLabel: String get() = canonicalPemLabel

    constructor(asn1Representation: Pkcs10CertificationRequest) : this(
        tbsCsr = TbsCertificationRequest(asn1Representation.certificationRequestInfo),
        signatureAlgorithm = SignatureAlgorithm.decodeFromTlv(asn1Representation.signatureAlgorithm),
        signature = CryptoSignature(asn1Representation.signatureAlgorithm, asn1Representation.signatureValue),
        providedAsn1Representation = asn1Representation
    )


    override val asn1Representation: Pkcs10CertificationRequest by providedAsn1Representation orLazy {
        Pkcs10CertificationRequest(
            certificationRequestInfo = tbsCsr.asn1Representation,
            signatureAlgorithm = signatureAlgorithm.asn1Representation,
            signatureValue = signature.asn1Representation,
        )
    }


    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CertificationRequest) return false
        return tbsCsr == other.tbsCsr &&
                signatureAlgorithm == other.signatureAlgorithm &&
                signature == other.signature
    }

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
        override val alternativePemLabels: Set<String> get() = Pkcs10CertificationRequest.alternativePemLabels

        @Throws(Asn1Exception::class)
        override fun decodeFromTlv(
            element: Pkcs10CertificationRequest,
            der: Der,
        ): CertificationRequest =
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
                extension.requireX509().asn1Representation
            })))
        }
    }
}
