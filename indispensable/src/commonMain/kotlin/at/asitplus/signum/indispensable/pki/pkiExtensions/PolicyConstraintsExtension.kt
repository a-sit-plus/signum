package at.asitplus.signum.indispensable.pki.pkiExtensions

import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1EncapsulatingOctetString
import at.asitplus.signum.indispensable.asn1.Asn1Integer
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.Asn1StructuralException
import at.asitplus.signum.indispensable.asn1.Asn1TagMismatchException
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.encoding.decodeFromAsn1ContentBytes
import at.asitplus.signum.indispensable.pki.X509CertificateExtension

data class PolicyConstraintsExtension (
    override val oid: ObjectIdentifier,
    override val critical: Boolean,
    override val value: Asn1EncapsulatingOctetString,
    val requireExplicitPolicy: Asn1Integer,
    val inhibitPolicyMapping: Asn1Integer
) : X509CertificateExtension(oid, critical, value) {

    constructor(
        base: X509CertificateExtension,
        requireExplicitPolicy: Asn1Integer,
        inhibitPolicyMapping: Asn1Integer
    ) : this(base.oid, base.critical, base.value.asEncapsulatingOctetString(), requireExplicitPolicy, inhibitPolicyMapping)

    companion object : Asn1Decodable<Asn1Sequence, X509CertificateExtension> {

        private val REQUIRE: ULong = 0u
        private val INHIBIT: ULong = 1u

        override fun doDecode(src: Asn1Sequence): PolicyConstraintsExtension {
            val base = decodeBase(src)

            if (base.oid != KnownOIDs.policyConstraints_2_5_29_36) throw Asn1StructuralException(message = "This extension is not PolicyConstraints extension.")
            var inner = base.value.asEncapsulatingOctetString().children.firstOrNull() ?: throw Asn1StructuralException(message = "Not valid PolicyConstraints extension.")
            if (inner.tag != Asn1Element.Tag.SEQUENCE) throw Asn1TagMismatchException(Asn1Element.Tag.SEQUENCE, inner.tag)
            inner = inner.asSequence()

            var requireExplicitPolicy: Asn1Integer = Asn1Integer.fromDecimalString("-1")
            var inhibitPolicyMapping: Asn1Integer = Asn1Integer.fromDecimalString("-1")
            if (inner.hasMoreChildren()) {
                inner.children.forEach {
                    if (it.tag.tagValue == REQUIRE) requireExplicitPolicy =  Asn1Integer.decodeFromAsn1ContentBytes(it.asPrimitive().content)
                    if (it.tag.tagValue == INHIBIT) inhibitPolicyMapping =  Asn1Integer.decodeFromAsn1ContentBytes(it.asPrimitive().content)
                }
            }
            return PolicyConstraintsExtension(base, requireExplicitPolicy, inhibitPolicyMapping)
        }
    }
}