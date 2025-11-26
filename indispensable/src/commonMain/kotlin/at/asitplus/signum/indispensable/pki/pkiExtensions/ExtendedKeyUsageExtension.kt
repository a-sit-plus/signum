package at.asitplus.signum.indispensable.pki.pkiExtensions

import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1EncapsulatingOctetString
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.Asn1StructuralException
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.decodeRethrowing
import at.asitplus.signum.indispensable.asn1.encoding.asAsn1BitString
import at.asitplus.signum.indispensable.asn1.extKeyUsage
import at.asitplus.signum.indispensable.asn1.keyUsage
import at.asitplus.signum.indispensable.asn1.readOid
import at.asitplus.signum.indispensable.asn1.serverAuth
import at.asitplus.signum.indispensable.pki.X509CertificateExtension

class ExtendedKeyUsageExtension(
    oid: ObjectIdentifier,
    critical: Boolean,
    value: Asn1EncapsulatingOctetString,
    val keyUsages: Set<ObjectIdentifier>
) : X509CertificateExtension(oid, critical, value) {

    constructor(
        base: X509CertificateExtension,
        keyUsages: Set<ObjectIdentifier>
    ) : this(base.oid, base.critical, base.value.asEncapsulatingOctetString(), keyUsages)

    companion object : Asn1Decodable<Asn1Sequence, X509CertificateExtension> {

        override fun doDecode(src: Asn1Sequence): ExtendedKeyUsageExtension = src.decodeRethrowing {
            val base = decodeBase(src)

            if (next().asPrimitive().readOid() != KnownOIDs.extKeyUsage) throw Asn1StructuralException(message = "Expected KeyUsage extension (OID: ${KnownOIDs.extKeyUsage}), but found OID: ${base.oid}")

            val inner = next().asEncapsulatingOctetString().single().asSequence()

            val keyUsages : Set<ObjectIdentifier> = inner.decodeRethrowing {
                buildSet {
                    while (hasNext()) {
                        add(next().asPrimitive().readOid())
                    }
                }
            }
            ExtendedKeyUsageExtension(base, keyUsages)
        }
    }
}