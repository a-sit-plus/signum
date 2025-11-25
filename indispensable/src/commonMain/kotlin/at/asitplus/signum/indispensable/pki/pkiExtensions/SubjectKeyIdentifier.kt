package at.asitplus.signum.indispensable.pki.pkiExtensions

import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1EncapsulatingOctetString
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.Asn1StructuralException
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.decodeRethrowing
import at.asitplus.signum.indispensable.asn1.subjectKeyIdentifier
import at.asitplus.signum.indispensable.pki.X509CertificateExtension

class SubjectKeyIdentifier(
    oid: ObjectIdentifier,
    critical: Boolean,
    value: Asn1EncapsulatingOctetString,
    val keyIdentifier: ByteArray?
) : X509CertificateExtension(oid, critical, value) {

    constructor(
        base: X509CertificateExtension,
        keyIdentifier: ByteArray?
    ) : this(base.oid, base.critical, base.value.asEncapsulatingOctetString(), keyIdentifier)

    companion object : Asn1Decodable<Asn1Sequence, X509CertificateExtension> {
        override fun doDecode(src: Asn1Sequence): X509CertificateExtension = src.decodeRethrowing {
            val base = decodeBase(src)

            if (base.oid != KnownOIDs.subjectKeyIdentifier) throw Asn1StructuralException(message = "Expected SKI extension (OID: ${KnownOIDs.subjectKeyIdentifier}), but found OID: ${base.oid}")

            val inner = base.value.asEncapsulatingOctetString().single().asSequence()

            val keyIdentifier = inner.decodeRethrowing {
                next().asPrimitive().content
            }

            SubjectKeyIdentifier(base, keyIdentifier)
        }

    }
}