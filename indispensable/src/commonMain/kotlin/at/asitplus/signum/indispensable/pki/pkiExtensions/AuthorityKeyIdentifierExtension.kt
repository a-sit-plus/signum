package at.asitplus.signum.indispensable.pki.pkiExtensions

import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1EncapsulatingOctetString
import at.asitplus.signum.indispensable.asn1.Asn1OctetString
import at.asitplus.signum.indispensable.asn1.Asn1Primitive
import at.asitplus.signum.indispensable.asn1.Asn1PrimitiveOctetString
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.Asn1StructuralException
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.authorityKeyIdentifier_2_5_29_35
import at.asitplus.signum.indispensable.asn1.decodeRethrowing
import at.asitplus.signum.indispensable.asn1.encoding.decode
import at.asitplus.signum.indispensable.pki.X509CertificateExtension
import at.asitplus.signum.indispensable.pki.generalNames.GeneralName

class AuthorityKeyIdentifierExtension(
    oid: ObjectIdentifier,
    critical: Boolean,
    value: Asn1EncapsulatingOctetString,
    val keyIdentifier: ByteArray?,
    val authorityCertIssuer: List<GeneralName> = emptyList<GeneralName>(),
    val authorityCertSerialNumber: ByteArray?
) : X509CertificateExtension(oid, critical, value) {

    constructor(
        base: X509CertificateExtension,
        keyIdentifier: ByteArray?,
        authorityCertIssuer: List<GeneralName>,
        authorityCertSerialNumber: ByteArray?
    ) : this(base.oid, base.critical, base.value.asEncapsulatingOctetString(), keyIdentifier, authorityCertIssuer, authorityCertSerialNumber)

    companion object : Asn1Decodable<Asn1Sequence, X509CertificateExtension> {

        override fun doDecode(src: Asn1Sequence): X509CertificateExtension = src.decodeRethrowing {
            val base = decodeBase(src)

            if (base.oid != KnownOIDs.authorityKeyIdentifier_2_5_29_35) throw Asn1StructuralException(message = "Expected AKI extension (OID: ${KnownOIDs.authorityKeyIdentifier_2_5_29_35}), but found OID: ${base.oid}")

            val inner = base.value.asEncapsulatingOctetString().single().asSequence()

            val (keyIdentifier, authorityCertIssuer, pathLenConstraint) = inner.decodeRethrowing {
                val keyIdentifier = nextOrNull()?.asPrimitive()?.content
                val authorityCertIssuer: List<GeneralName> = nextOrNull()?.asSequence()?.children
                    ?.map { GeneralName.decodeFromTlv(it.asSequence()) }
                    ?: emptyList()
                val authorityCertSerialNumber  = nextOrNull()?.asPrimitive()?.decode(Asn1Element.Tag.INT) { it }
                Triple(keyIdentifier, authorityCertIssuer, authorityCertSerialNumber)
            }

            return AuthorityKeyIdentifierExtension(base, keyIdentifier, authorityCertIssuer, pathLenConstraint)
        }
    }
}