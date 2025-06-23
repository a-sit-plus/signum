package at.asitplus.signum.indispensable.pki.pkiExtensions

import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1EncapsulatingOctetString
import at.asitplus.signum.indispensable.asn1.Asn1Integer
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.Asn1StructuralException
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.encoding.decodeFromAsn1ContentBytes
import at.asitplus.signum.indispensable.pki.X509CertificateExtension

/**
 * Policy Constraints Extension
 * This extension specifies prohibition of policy mappings and requirement that each certificate in
 * the chain has an acceptable policy identifier
 * RFC 5280: 4.2.1.11.
 * */
class PolicyConstraintsExtension (
    oid: ObjectIdentifier,
    critical: Boolean,
    value: Asn1EncapsulatingOctetString,
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

            val inner = base.value.asEncapsulatingOctetString()
                .nextChildOrNull()
                ?.takeIf { it.tag == Asn1Element.Tag.SEQUENCE }
                ?.asSequence()
                ?: throw Asn1StructuralException("Invalid or missing SEQUENCE in PolicyConstraints extension.")

            if (inner.children.size > 2) throw Asn1StructuralException("Invalid PolicyConstraints extension found (>2 children): ${inner.toDerHexString()}")

            var requireExplicitPolicy: Asn1Integer = Asn1Integer.fromDecimalString("-1")
            var inhibitPolicyMapping: Asn1Integer = Asn1Integer.fromDecimalString("-1")
            while (inner.hasMoreChildren()) {
                val child = inner.nextChild()
                when (child.tag.tagValue) {
                    REQUIRE -> requireExplicitPolicy = Asn1Integer.decodeFromAsn1ContentBytes(child.asPrimitive().content)
                    INHIBIT -> inhibitPolicyMapping = Asn1Integer.decodeFromAsn1ContentBytes(child.asPrimitive().content)
                }
            }
            return PolicyConstraintsExtension(base, requireExplicitPolicy, inhibitPolicyMapping)
        }
    }
}