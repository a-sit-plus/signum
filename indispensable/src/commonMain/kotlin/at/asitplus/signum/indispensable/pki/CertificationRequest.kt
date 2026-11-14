package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.Asn1StructuralException
import at.asitplus.awesn1.allDistinctByOids
import at.asitplus.awesn1.crypto.pki.Pkcs10CsrAttribute
import at.asitplus.signum.Signum
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.sign.SignatureAlgorithm

/**
 * The meat of a Certification Request:
 * The structure that gets signed.
 *
 * @param subjectName list of subject distinguished names
 * @param publicKey nomen est omen
 * @param attributes nomen est omen
 */
class TbsCertificationRequest(
    val subjectName: Name,
    val publicKey: CryptoPublicKey,
    val attributes: List<CsrAttribute> = listOf(),
    validateAttributes: Boolean = true,
) : WithSourceRepresentation {

    override val sourceRepresentation = SourceRepresentationStorage()

    init {
        if (validateAttributes) {
            validateAttributes(attributes, allowExtensions = true)
        }
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

    val attributesWithoutExtensions: List<CsrAttribute> by lazy { attributes.filterNot { it.oid == Pkcs10CsrAttribute.EXTENSION_REQUEST_OID } }

    val extensions: List<CertificateExtension> by lazy {
        attributes.filter { it.oid == Pkcs10CsrAttribute.EXTENSION_REQUEST_OID }.let { extensionAttributes ->
            when (extensionAttributes.size) {
                0 -> emptyList()
                1 -> requireNotNull(extensionAttributes.single().asn1.toRepresentation()).value.single().asSequence().map {
                    CertificateExtension.fromAsn1(it)
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

    companion object
}

/**
 * Very simple implementation of a PKCS#10 Certification Request.
 */
class CertificationRequest(
    val tbsCsr: TbsCertificationRequest,
    val signatureAlgorithm: SignatureAlgorithm,
    val signatureValue: AbstractSignature,
) : WithSourceRepresentation {

    override val sourceRepresentation = SourceRepresentationStorage()

    val publicKey get() = tbsCsr.publicKey
    val signature get() = signatureValue.withSignatureAlgorithm(signatureAlgorithm)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CertificationRequest) return false
        return tbsCsr == other.tbsCsr &&
            CryptoSignature.signaturesEqual(signatureAlgorithm, signatureValue, other.signatureAlgorithm, other.signatureValue)
    }

    override fun hashCode(): Int {
        var result = tbsCsr.hashCode()
        result = 31 * result + signatureAlgorithm.hashCode()
        return result
    }

    override fun toString(): String =
        "Pkcs10CertificationRequest(tbsCsr=$tbsCsr, signatureAlgorithm=$signatureAlgorithm, signatureValue=$signatureValue)"

    companion object
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
            // TODO: this assumes asn1 in the abstract class
            add(CsrAttribute.fromAsn1(
                Pkcs10CsrAttribute.ExtensionRequest(it.map {
                    extension -> extension.asn1.toRepresentation()
                }, Signum.Der)
            ))
        }
    }
}
