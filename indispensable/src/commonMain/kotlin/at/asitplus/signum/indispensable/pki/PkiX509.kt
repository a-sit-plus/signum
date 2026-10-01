package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.crypto.pki.*
import at.asitplus.signum.indispensable.*
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.crypto.pki.X500Name as Asn1X500Name

val Name.asn1Representation: Asn1X500Name?
    get() = representations[X509] as? Asn1X500Name
val X500Name.asn1Representation: Asn1X500Name
    get() = representations[X509] as Asn1X500Name
val GeneralName.asn1Representation: X509GeneralName?
    get() = representations[X509] as? X509GeneralName
val GeneralName.tag: at.asitplus.awesn1.Asn1Element.Tag?
    get() = asn1Representation?.tag
val BaseX509GeneralName.asn1Representation: X509GeneralName
    get() = representations[X509] as X509GeneralName
val AlternativeNames.asn1Representation: X509GeneralNames?
    get() = representations[X509] as? X509GeneralNames
val CsrAttribute.asn1Representation: Pkcs10CsrAttribute?
    get() = representations[X509] as? Pkcs10CsrAttribute
val X509CsrAttribute.asn1Representation: Pkcs10CsrAttribute
    get() = representations[X509] as Pkcs10CsrAttribute
val RelativeDistinguishedName.asn1Representation: X500RelativeDistinguishedName
    get() = representations[X509] as X500RelativeDistinguishedName
val AttributeTypeAndValue.asn1Representation: X500AttributeTypeAndValue?
    get() = representations[X509] as? X500AttributeTypeAndValue
val BaseX509AttributeTypeAndValue.asn1Representation: X500AttributeTypeAndValue
    get() = representations[X509] as X500AttributeTypeAndValue
val TbsCertificationRequest.asn1Representation: Pkcs10CertificationRequestInfo
    get() = representations[X509] as Pkcs10CertificationRequestInfo
val CertificationRequest.asn1Representation: Pkcs10CertificationRequest
    get() = representations[X509] as Pkcs10CertificationRequest

/** Raw X.509 attribute value; fails if the attribute has no X.509 representation. */
val AttributeTypeAndValue.value: at.asitplus.awesn1.Asn1Element
    get() = requireNotNull(asn1Representation) { "Attribute has no X.509 representation" }.value
val CsrAttribute.value: Set<at.asitplus.awesn1.Asn1Element>
    get() = requireNotNull(asn1Representation) { "CSR attribute has no X.509 representation" }.value
