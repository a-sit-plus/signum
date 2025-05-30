package at.asitplus.signum.indispensable.pki.pkiExtensions

import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1Integer
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.Asn1StructuralException
import at.asitplus.signum.indispensable.asn1.Asn1TagMismatchException
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.encoding.decodeFromAsn1ContentBytes
import at.asitplus.signum.indispensable.pki.X509CertificateExtension

class PolicyConstraints (
    val requireExplicitPolicy: Asn1Integer,
    val inhibitPolicyMapping: Asn1Integer
) : Asn1Encodable<Asn1Sequence> {

    override fun encodeToTlv() = Asn1.Sequence {
        +requireExplicitPolicy
        +inhibitPolicyMapping
    }

    companion object : Asn1Decodable<Asn1Sequence, PolicyConstraints> {

        private val REQUIRE: ULong = 0u
        private val INHIBIT: ULong = 1u

        override fun doDecode(src: Asn1Sequence): PolicyConstraints {
            var requireExplicitPolicy: Asn1Integer = Asn1Integer.fromDecimalString("-1")
            var inhibitPolicyMapping: Asn1Integer = Asn1Integer.fromDecimalString("-1")
            if (src.hasMoreChildren()) {
                src.children.forEach {
                    if (it.tag.tagValue == REQUIRE) requireExplicitPolicy =  Asn1Integer.decodeFromAsn1ContentBytes(it.asPrimitive().content)
                    if (it.tag.tagValue == INHIBIT) inhibitPolicyMapping =  Asn1Integer.decodeFromAsn1ContentBytes(it.asPrimitive().content)
                }
            }
            return PolicyConstraints(requireExplicitPolicy, inhibitPolicyMapping)
        }
    }
}

fun X509CertificateExtension.decodePolicyConstraints() : PolicyConstraints {
    if (oid != KnownOIDs.policyConstraints_2_5_29_36) throw Asn1StructuralException(message = "This extension is not PolicyConstraints extension.")
    if (value.tag != Asn1Element.Tag.OCTET_STRING) throw Asn1TagMismatchException(Asn1Element.Tag.OCTET_STRING, value.tag)
    val elem = value.asEncapsulatingOctetString().children.firstOrNull() ?: throw Asn1StructuralException(message = "Not valid PolicyConstraints extension.")
    if (elem.tag != Asn1Element.Tag.SEQUENCE) throw Asn1TagMismatchException(Asn1Element.Tag.SEQUENCE, elem.tag)

    return PolicyConstraints.doDecode(elem.asSequence())
}