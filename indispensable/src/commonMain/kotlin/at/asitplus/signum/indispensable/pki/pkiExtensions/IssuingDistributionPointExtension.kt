package at.asitplus.signum.indispensable.pki.pkiExtensions

import at.asitplus.signum.indispensable.asn1.Asn1BitString
import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1EncapsulatingOctetString
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.Asn1StructuralException
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.TagClass
import at.asitplus.signum.indispensable.asn1.decodeRethrowing
import at.asitplus.signum.indispensable.asn1.encoding.decodeToBoolean
import at.asitplus.signum.indispensable.asn1.extKeyUsage
import at.asitplus.signum.indispensable.asn1.issuingDistributionPoint_2_5_29_28
import at.asitplus.signum.indispensable.pki.X509CertificateExtension

class IssuingDistributionPointExtension(
    oid: ObjectIdentifier,
    critical: Boolean,
    value: Asn1EncapsulatingOctetString,
    val distributionPointName: DistributionPointName? = null,
    val onlySomeReasons: Asn1BitString? = null,
    val onlyContainsUserCerts: Boolean = false,
    val onlyContainsCACerts: Boolean = false,
    val indirectCRL: Boolean = false,
    val onlyContainsAttributeCerts: Boolean = false
): X509CertificateExtension(oid, critical, value) {

    constructor(
        base: X509CertificateExtension,
        distributionPointName: DistributionPointName? = null,
        onlySomeReasons: Asn1BitString? = null,
        onlyContainsUserCerts: Boolean = false,
        onlyContainsCACerts: Boolean = false,
        indirectCRL: Boolean = false,
        onlyContainsAttributeCerts: Boolean = false
    ) : this(
        base.oid,
        base.critical,
        base.value.asEncapsulatingOctetString(),
        distributionPointName,
        onlySomeReasons,
        onlyContainsUserCerts,
        onlyContainsCACerts,
        indirectCRL,
        onlyContainsAttributeCerts
    )

    companion object : Asn1Decodable<Asn1Sequence, X509CertificateExtension> {
        override fun doDecode(src: Asn1Sequence): IssuingDistributionPointExtension = src.decodeRethrowing{
            val base = decodeBase()

            if (base.oid != KnownOIDs.issuingDistributionPoint_2_5_29_28) throw Asn1StructuralException(message = "Expected IssuingDistributionPoint extension (OID: ${KnownOIDs.issuingDistributionPoint_2_5_29_28}), but found OID: ${base.oid}")

            val inner = base.value.asEncapsulatingOctetString().single().asSequence()

            return inner.decodeRethrowing {

                var distributionPointName: DistributionPointName? = null
                var onlySomeReasons: Asn1BitString? = null
                var onlyContainsUserCerts = false
                var onlyContainsCACerts = false
                var indirectCRL = false
                var onlyContainsAttributeCerts = false

                while (hasNext()) {
                    val child = next()

                    when (child.tag.tagValue) {
                        0uL -> {
                            distributionPointName =
                                DistributionPointName.decodeFromTlv(child.asExplicitlyTagged())
                        }
                        1uL -> {
                            onlyContainsUserCerts = child.asPrimitive().decodeToBoolean(Asn1Element.Tag(1uL, false, tagClass = TagClass.CONTEXT_SPECIFIC))
                        }
                        2uL -> {
                            onlyContainsCACerts = child.asPrimitive().decodeToBoolean(Asn1Element.Tag(2uL, false, tagClass = TagClass.CONTEXT_SPECIFIC))
                        }
                        3uL -> {
                            onlySomeReasons = Asn1BitString.decodeFromTlv(child.asPrimitive())
                        }
                        4uL -> {
                            indirectCRL = child.asPrimitive().decodeToBoolean(Asn1Element.Tag(4uL, false, tagClass = TagClass.CONTEXT_SPECIFIC))
                        }
                        5uL -> {
                            onlyContainsAttributeCerts = child.asPrimitive().decodeToBoolean(Asn1Element.Tag(5uL, false, tagClass = TagClass.CONTEXT_SPECIFIC))
                        }
                        else -> throw IllegalArgumentException("Unexpected tag in IssuingDistributionPoint: ${child.tag}")
                    }
                }

                IssuingDistributionPointExtension(
                    base,
                    distributionPointName,
                    onlySomeReasons,
                    onlyContainsUserCerts,
                    onlyContainsCACerts,
                    indirectCRL,
                    onlyContainsAttributeCerts
                )
            }
        }

    }
}