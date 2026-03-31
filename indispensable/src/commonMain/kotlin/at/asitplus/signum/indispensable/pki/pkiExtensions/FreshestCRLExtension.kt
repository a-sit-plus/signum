package at.asitplus.signum.indispensable.pki.pkiExtensions

import at.asitplus.signum.indispensable.asn1.Asn1EncapsulatingOctetString
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier

class FreshestCRLExtension(
    oid: ObjectIdentifier,
    critical: Boolean,
    value: Asn1EncapsulatingOctetString,
    override val distributionPoints: List<DistributionPoint>
) : CRLDistributionPointsExtension(oid, critical, value, distributionPoints)