package at.asitplus.signum.indispensable.pki.pkiExtensions

import at.asitplus.signum.indispensable.asn1.Asn1BitString
import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1EncapsulatingOctetString
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1Exception
import at.asitplus.signum.indispensable.asn1.Asn1ExplicitlyTagged
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.Asn1StructuralException
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.cRLDistributionPoints_2_5_29_31
import at.asitplus.signum.indispensable.asn1.decodeRethrowing
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.readOid
import at.asitplus.signum.indispensable.pki.AttributeTypeAndValue
import at.asitplus.signum.indispensable.pki.X509CertificateExtension
import at.asitplus.signum.indispensable.pki.generalNames.GeneralName

class CRLDistributionPointsExtension(
    oid: ObjectIdentifier,
    critical: Boolean,
    value: Asn1EncapsulatingOctetString,
    val distributionPoints: List<DistributionPoint>
) : X509CertificateExtension(oid, critical, value) {

    constructor(
        base: X509CertificateExtension,
        distributionPoints: List<DistributionPoint>
    ) : this(base.oid, base.critical, base.value.asEncapsulatingOctetString(), distributionPoints)

    companion object : Asn1Decodable<Asn1Sequence, X509CertificateExtension> {

        override fun doDecode(src: Asn1Sequence): CRLDistributionPointsExtension = src.decodeRethrowing {
            val base = decodeBase(src)

            if (next().asPrimitive().readOid() != KnownOIDs.cRLDistributionPoints_2_5_29_31) throw Asn1StructuralException(message = "Expected KeyUsage extension (OID: ${KnownOIDs.cRLDistributionPoints_2_5_29_31}), but found OID: ${base.oid}")

            val critical =
                if (peek()?.tag == Asn1Element.Tag.BOOL) next().asPrimitive().content[0] == 0xff.toByte() else false

            val inner = next().asEncapsulatingOctetString().single().asSequence()

            val distributionPoints : List<DistributionPoint> = inner.decodeRethrowing {
                buildList {
                    while (hasNext()) {
                        add(DistributionPoint.decodeFromTlv(next().asSequence()))
                    }
                }
            }
            CRLDistributionPointsExtension(base, distributionPoints)
        }
    }
}


data class DistributionPoint(
    val distributionPointName: DistributionPointName?,
    val reasons: Asn1BitString?,
    val crlIssuer: List<GeneralName>?
) : Asn1Encodable<Asn1Sequence> {

    val decodedReasons: Set<ReasonFlag>? by lazy {
        reasons?.let { ReasonFlag.parseReasons(it) }
    }

    override fun encodeToTlv() = Asn1.Sequence {
        distributionPointName?.let { +it }
        reasons?.let { +it }
        crlIssuer?.let { names -> names.forEach { +it } }
    }

    companion object : Asn1Decodable<Asn1Sequence, DistributionPoint> {

        override fun doDecode(src: Asn1Sequence): DistributionPoint = src.decodeRethrowing {

            var name: DistributionPointName? = null
            var reasons: Asn1BitString? = null
            var crlIssuer: List<GeneralName>? = null

            while (hasNext()) {
                val child = next()

                when (child.tag.tagValue) {
                    0uL -> name =
                        DistributionPointName.decodeFromTlv(child.asExplicitlyTagged())
                    1uL -> reasons =
                        Asn1BitString.decodeFromTlv(child.asPrimitive())
                    2uL -> crlIssuer = child.asExplicitlyTagged().decodeRethrowing {
                        buildList {
                            while (hasNext()) {
                                add(GeneralName.decodeFromTlv(next()))
                            }
                        }
                    }
                    else -> throw Asn1Exception(
                        "Invalid DistributionPoint tag: ${child.tag.tagValue}"
                    )
                }
            }

            DistributionPoint(name, reasons, crlIssuer)
        }

    }
}

sealed class DistributionPointName : Asn1Encodable<Asn1ExplicitlyTagged> {

    data class FullName(val names: List<GeneralName>) : DistributionPointName()

    data class NameRelativeToCrlIssuer(val name: AttributeTypeAndValue) : DistributionPointName()

    @Throws(Asn1Exception::class)
    override fun encodeToTlv(): Asn1ExplicitlyTagged =
        when (this) {
            is FullName ->
                Asn1.ExplicitlyTagged(0u) {
                    names.forEach { +it }
                }
            is NameRelativeToCrlIssuer ->
                Asn1.ExplicitlyTagged(1u) {
                    +name
                }
        }

    companion object : Asn1Decodable<Asn1ExplicitlyTagged, DistributionPointName> {

        override fun doDecode(src: Asn1ExplicitlyTagged): DistributionPointName = src.decodeRethrowing {
            val child = next().asExplicitlyTagged()
            when (child.tag.tagValue) {
                0uL -> FullName(
                    child.decodeRethrowing {
                        buildList {
                            while (hasNext()) {
                                add(GeneralName.decodeFromTlv(next()))
                            }
                        }
                    }
                )

                1uL -> NameRelativeToCrlIssuer(
                    child.decodeRethrowing {
                        AttributeTypeAndValue.decodeFromTlv(next().asSequence())
                    }
                )

                else -> throw Asn1Exception("Invalid DistributionPointName tag")
            }
        }

    }
}


enum class ReasonFlag(val bitNumber: Long, val crlReason: CRLReason) {
    UNSPECIFIED(0, CRLReason.UNSPECIFIED),
    KEY_COMPROMISE(1, CRLReason.KEY_COMPROMISE),
    CA_COMPROMISE(2, CRLReason.CA_COMPROMISE),
    AFFILIATION_CHANGED(3, CRLReason.AFFILIATION_CHANGED),
    SUPERSEDED(4, CRLReason.SUPERSEDED),
    CESSATION_OF_OPERATION(5, CRLReason.CESSATION_OF_OPERATION),
    CERTIFICATE_HOLD(6, CRLReason.CERTIFICATE_HOLD),
    PRIVILEGE_WITHDRAWN(7, CRLReason.PRIVILEGE_WITHDRAWN),
    AA_COMPROMISE(8, CRLReason.AA_COMPROMISE);

    ;

    companion object {
        fun parseReasons(encodedValue: Asn1BitString): Set<ReasonFlag> {
            val booleans = encodedValue.toBitSet()
            val result = mutableSetOf<ReasonFlag>()
            for (usage in ReasonFlag.entries) {
                if (usage.bitNumber < booleans.length()) {
                    if (booleans[usage.bitNumber]) {
                        result.add(usage)
                    }
                }
            }
            return result
        }
    }
}