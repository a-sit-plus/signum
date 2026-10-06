package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.crypto.pki.*
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.sign.SignatureAlgorithm
import at.asitplus.signum.indispensable.sign.asn1Representation
import at.asitplus.signum.indispensable.sign.invoke
import at.asitplus.awesn1.crypto.pki.X500Name as Asn1X500Name

val Name.asn1Representation: Asn1X500Name?
    get() = representations[X509] as? Asn1X500Name ?: (this as? X500Name)?.asn1Representation
val X500Name.asn1Representation: Asn1X500Name
    get() = representations[X509] as? Asn1X500Name ?: Asn1X500Name(relativeDistinguishedNames.map { it.asn1Representation })
val GeneralName.asn1Representation: X509GeneralName?
    get() = representations[X509] as? X509GeneralName
val GeneralName.tag: at.asitplus.awesn1.Asn1Element.Tag?
    get() = asn1Representation?.tag
val BaseX509GeneralName.asn1Representation: X509GeneralName
    get() = representations[X509] as X509GeneralName
val AlternativeNames.asn1Representation: X509GeneralNames?
    get() = representations[X509] as? X509GeneralNames ?: X509GeneralNames(generalNames.map {
        requireNotNull(it.asn1Representation) { "GeneralName has no X.509 representation" }
    })
val CsrAttribute.asn1Representation: Pkcs10CsrAttribute?
    get() = representations[X509] as? Pkcs10CsrAttribute ?: (this as? X509CsrAttribute)?.let { Pkcs10CsrAttribute(it.oid, it.value) }
val X509CsrAttribute.asn1Representation: Pkcs10CsrAttribute
    get() = representations[X509] as? Pkcs10CsrAttribute ?: Pkcs10CsrAttribute(oid, value)
val RelativeDistinguishedName.asn1Representation: X500RelativeDistinguishedName
    get() = representations[X509] as? X500RelativeDistinguishedName ?: X500RelativeDistinguishedName(attrsAndValues.map {
        requireNotNull(it.asn1Representation) { "Attribute has no X.509 representation" }
    }.toSet())
val AttributeTypeAndValue.asn1Representation: X500AttributeTypeAndValue?
    get() = representations[X509] as? X500AttributeTypeAndValue ?: (this as? BaseX509AttributeTypeAndValue)?.let { X500AttributeTypeAndValue(it.oid, it.value) }
val BaseX509AttributeTypeAndValue.asn1Representation: X500AttributeTypeAndValue
    get() = representations[X509] as? X500AttributeTypeAndValue ?: X500AttributeTypeAndValue(oid, value)
val TbsCertificationRequest.asn1Representation: Pkcs10CertificationRequestInfo
    get() = representations[X509] as? Pkcs10CertificationRequestInfo ?: Pkcs10CertificationRequestInfo(
        subjectName = requireNotNull(subjectName.asn1Representation) { "Subject has no X.509 representation" },
        publicKey = publicKey.asn1Representation,
        attributes = attributes.mapTo(mutableSetOf()) {
            requireNotNull(it.asn1Representation) { "Value has no X.509 representation" }
        },
    )
val CertificationRequest.asn1Representation: Pkcs10CertificationRequest
    get() = representations[X509] as? Pkcs10CertificationRequest ?: Pkcs10CertificationRequest(
        certificationRequestInfo = tbsCsr.asn1Representation,
        signatureAlgorithm = signatureAlgorithm.asn1Representation,
        signatureValue = signature.asn1Representation,
    )

/** Raw X.509 attribute value; fails if the attribute has no X.509 representation. */
val AttributeTypeAndValue.value: at.asitplus.awesn1.Asn1Element
    get() = requireNotNull(asn1Representation) { "Attribute has no X.509 representation" }.value
val CsrAttribute.value: Set<at.asitplus.awesn1.Asn1Element>
    get() = requireNotNull(asn1Representation) { "CSR attribute has no X.509 representation" }.value

operator fun TbsCertificationRequest.Companion.invoke(src: Pkcs10CertificationRequestInfo): TbsCertificationRequest =
    fromAsn1Representation(src)

/** Retains the original model; interpretation is deferred until semantic access. */
fun TbsCertificationRequest.Companion.fromAsn1Representation(src: Pkcs10CertificationRequestInfo): TbsCertificationRequest =
    TbsCertificationRequest(
        subjectName = X500Name(src.subjectName.map { RelativeDistinguishedName(it, performValidation = false) }, false),
        publicKeyProvider = { CryptoPublicKey(src.publicKey) },
        attributes = src.attributes.map { CsrAttribute(it) },
        representations = mapOf(X509 to src),
    )

operator fun CertificationRequest.Companion.invoke(src: Pkcs10CertificationRequest): CertificationRequest =
    fromAsn1Representation(src)

/** Retains the original model; interpretation is deferred until semantic access. */
fun CertificationRequest.Companion.fromAsn1Representation(src: Pkcs10CertificationRequest): CertificationRequest =
    CertificationRequest(
        tbsCsr = TbsCertificationRequest(src.certificationRequestInfo),
        signatureAlgorithmProvider = { SignatureAlgorithm(src.signatureAlgorithm) },
        signatureProvider = { CryptoSignature(src.signatureAlgorithm, src.signatureValue) },
        representations = mapOf(X509 to src),
    )

fun RelativeDistinguishedName.Companion.fromAsn1Representation(
    src: X500RelativeDistinguishedName,
    performValidation: Boolean = false,
): RelativeDistinguishedName = RelativeDistinguishedName(
    { src.attrsAndValues.map(AttributeTypeAndValue::fromAsn1Representation).toSet() },
    mapOf(X509 to src), performValidation,
)

operator fun RelativeDistinguishedName.Companion.invoke(
    src: X500RelativeDistinguishedName,
    performValidation: Boolean = false,
): RelativeDistinguishedName = fromAsn1Representation(src, performValidation)
