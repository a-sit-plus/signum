package at.asitplus.signum.indispensable.pki.pkiExtensions

import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1EncapsulatingOctetString
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.Asn1StructuralException
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.decodeRethrowing
import at.asitplus.signum.indispensable.asn1.issuingDistributionPoint_2_5_29_28
import at.asitplus.signum.indispensable.asn1.ocspNonce
import at.asitplus.signum.indispensable.pki.X509CertificateExtension

class OCSPNonceExtension(
    oid: ObjectIdentifier,
    critical: Boolean,
    value: Asn1EncapsulatingOctetString,
    val nonce: ByteArray
): X509CertificateExtension(oid, critical, value) {

    constructor(
        base: X509CertificateExtension,
        nonce: ByteArray
    ) : this(base.oid, base.critical, base.value.asEncapsulatingOctetString(), nonce)

    companion object : Asn1Decodable<Asn1Sequence, X509CertificateExtension> {

        override fun doDecode(src: Asn1Sequence): X509CertificateExtension =  src.decodeRethrowing {
            val base = decodeBase()

            if (base.oid != KnownOIDs.ocspNonce) throw Asn1StructuralException(message = "Expected OCSPNonce extension (OID: ${KnownOIDs.ocspNonce}), but found OID: ${base.oid}")

            val nonce = base.value.asEncapsulatingOctetString().single().asOctetString().content

            return OCSPNonceExtension(base, nonce)
        }

    }
}