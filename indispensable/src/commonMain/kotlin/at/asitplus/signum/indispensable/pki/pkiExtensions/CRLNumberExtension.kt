package at.asitplus.signum.indispensable.pki.pkiExtensions

import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1EncapsulatingOctetString
import at.asitplus.signum.indispensable.asn1.Asn1Integer
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.decodeRethrowing
import at.asitplus.signum.indispensable.pki.X509CertificateExtension
import at.asitplus.signum.indispensable.pki.pkiExtensions.CRLNumberExtension

open class CRLNumberExtension (
    oid: ObjectIdentifier,
    critical: Boolean,
    value: Asn1EncapsulatingOctetString,
    open val crlNumber: Asn1Integer
) : X509CertificateExtension(oid, critical, value) {

    constructor(
        base: X509CertificateExtension,
        crlNumber: Asn1Integer
    ) : this(base.oid, base.critical, base.value.asEncapsulatingOctetString(), crlNumber)


    companion object : Asn1Decodable<Asn1Sequence, X509CertificateExtension> {

        override fun doDecode(src: Asn1Sequence): X509CertificateExtension = src.decodeRethrowing {

            val base = decodeBase(src)

            val crlNumber = base.value.asEncapsulatingOctetString().decodeRethrowing { Asn1Integer.decodeFromTlv(next().asPrimitive()) }

            return CRLNumberExtension(base, crlNumber)
        }

    }
}

class DeltaCRLIndicatorExtension(
    oid: ObjectIdentifier,
    critical: Boolean,
    value: Asn1EncapsulatingOctetString,
    override val crlNumber: Asn1Integer
) : CRLNumberExtension(oid, critical, value, crlNumber) {

    constructor(
        base: X509CertificateExtension,
        crlNumber: Asn1Integer
    ) : this(base.oid, base.critical, base.value.asEncapsulatingOctetString(), crlNumber)


    companion object : Asn1Decodable<Asn1Sequence, X509CertificateExtension> {
        override fun doDecode(src: Asn1Sequence): X509CertificateExtension = src.decodeRethrowing {

            val base = decodeBase(src)

            val crlNumber = base.value.asEncapsulatingOctetString().decodeRethrowing { Asn1Integer.decodeFromTlv(next().asPrimitive()) }

            return DeltaCRLIndicatorExtension(base, crlNumber)
        }
    }
}
