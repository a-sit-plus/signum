package at.asitplus.signum.indispensable.pki.pkiExtensions

import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1EncapsulatingOctetString
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.Asn1StructuralException
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.cRLDistributionPoints_2_5_29_31
import at.asitplus.signum.indispensable.asn1.certificateIssuer
import at.asitplus.signum.indispensable.asn1.decodeRethrowing
import at.asitplus.signum.indispensable.asn1.readOid
import at.asitplus.signum.indispensable.pki.X509CertificateExtension
import at.asitplus.signum.indispensable.pki.generalNames.GeneralName

class CertificateIssuerExtension(
    oid: ObjectIdentifier,
    critical: Boolean,
    value: Asn1EncapsulatingOctetString,
    val issuer: List<GeneralName>
): X509CertificateExtension(oid, critical, value) {

    constructor(
        base: X509CertificateExtension,
        issuer: List<GeneralName>
    ) : this(base.oid, base.critical, base.value.asEncapsulatingOctetString(), issuer)

    companion object : Asn1Decodable<Asn1Sequence, X509CertificateExtension> {

        override fun doDecode(src: Asn1Sequence): CertificateIssuerExtension = src.decodeRethrowing {
            val base = decodeBase(src)

            if (next().asPrimitive().readOid() != KnownOIDs.certificateIssuer) throw Asn1StructuralException(message = "Expected KeyUsage extension (OID: ${KnownOIDs.certificateIssuer}), but found OID: ${base.oid}")

            val critical =
                if (peek()?.tag == Asn1Element.Tag.BOOL) next().asPrimitive().content[0] == 0xff.toByte() else false

            val inner = next().asEncapsulatingOctetString().single().asSequence()

            val issuer : List<GeneralName> = inner.decodeRethrowing {
                buildList {
                    while (hasNext()) {
                        add(GeneralName.decodeFromTlv(next()))
                    }
                }
            }
            CertificateIssuerExtension(base, issuer)
        }
    }
}