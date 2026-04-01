package at.asitplus.signum.indispensable.pki.pkiExtensions

import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1EncapsulatingOctetString
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.decodeRethrowing
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.pki.X509CertificateExtension
import at.asitplus.signum.indispensable.pki.generalNames.GeneralName

class AuthorityInfoAccessExtension(
    oid: ObjectIdentifier,
    critical: Boolean,
    value: Asn1EncapsulatingOctetString,
    val accessDescriptions: List<AccessDescription>
): X509CertificateExtension(oid, critical, value) {

    constructor(base: X509CertificateExtension, accessDescriptions: List<AccessDescription>) : this(
        base.oid, base.critical,
        base.value as Asn1EncapsulatingOctetString, accessDescriptions
    )

    companion object : Asn1Decodable<Asn1Sequence, X509CertificateExtension> {
        override fun doDecode(src: Asn1Sequence): X509CertificateExtension = src.decodeRethrowing {
            val base = decodeBase(src)
            val accessDescriptions = base.value.asEncapsulatingOctetString().decodeRethrowing {
                buildList {
                    while (hasNext())
                        add(AccessDescription.decodeFromTlv(next().asSequence()))
                }
            }
            return AuthorityInfoAccessExtension(base, accessDescriptions)
        }
    }
}

data class AccessDescription(
    val accessMethod: ObjectIdentifier,
    val accessLocation: GeneralName
) : Asn1Encodable<Asn1Sequence> {

    override fun encodeToTlv(): Asn1Sequence = Asn1.Sequence {
        +accessMethod
        +accessLocation
    }

    companion object : Asn1Decodable<Asn1Sequence, AccessDescription> {
        override fun doDecode(src: Asn1Sequence): AccessDescription = src.decodeRethrowing {
            val method = ObjectIdentifier.decodeFromTlv(next().asPrimitive())
            val location = GeneralName.decodeFromTlv(next())
            return AccessDescription(method, location)
        }

    }

}