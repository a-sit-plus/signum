package at.asitplus.signum.indispensable.pki.pkiExtensions

import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1EncapsulatingOctetString
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1Integer
import at.asitplus.signum.indispensable.asn1.Asn1Primitive
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.Asn1StructuralException
import at.asitplus.signum.indispensable.asn1.Asn1TagMismatchException
import at.asitplus.signum.indispensable.asn1.BERTags
import at.asitplus.signum.indispensable.asn1.Identifiable
import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.encoding.asAsn1String
import at.asitplus.signum.indispensable.asn1.encoding.decodeToAsn1Integer
import at.asitplus.signum.indispensable.asn1.readOid
import at.asitplus.signum.indispensable.pki.X509CertificateExtension

/**
 * Certificate Policies Extension
 * This extension specifies the rules for issuing the certificate and how it can be used.
 * RFC 5280: 4.2.1.4.
 * */
class CertificatePoliciesExtension(
    oid: ObjectIdentifier,
    critical: Boolean,
    value: Asn1EncapsulatingOctetString,
    val certificatePolicies: List<PolicyInformation>
) : X509CertificateExtension(oid, critical, value) {

    constructor(
        base: X509CertificateExtension,
        certificatePolicies: List<PolicyInformation>
    ) : this(base.oid, base.critical, base.value.asEncapsulatingOctetString(), certificatePolicies)

    companion object : Asn1Decodable<Asn1Sequence, X509CertificateExtension> {
        override fun doDecode(src: Asn1Sequence): CertificatePoliciesExtension = src.decodeRethrowing {
            val base = decodeBase(src)

            if (base.oid != KnownOIDs.certificatePolicies_2_5_29_32) throw Asn1StructuralException(message = "Expected CertificatePolicies extension (OID: ${KnownOIDs.certificatePolicies_2_5_29_32}), but found OID: ${base.oid}")

            val inner = base.value.asEncapsulatingOctetString()
                .singleOrNull()
                ?.asSequence()
                ?: return CertificatePoliciesExtension(base, emptyList())

            val policies = inner.decodeRethrowing {
                buildList {
                    while (hasNext()) {
                        add(PolicyInformation.decodeFromTlv(next().asSequence()))
                    }
                }
            }
            return CertificatePoliciesExtension(base, policies)
        }
    }
}


data class PolicyInformation(
    override val oid: ObjectIdentifier,
    val policyQualifiers: Set<PolicyQualifierInfo>
) : Asn1Encodable<Asn1Sequence>, Identifiable {

    override fun encodeToTlv() = Asn1.Sequence {
        +oid
        if (policyQualifiers.isNotEmpty()) {
            +Asn1.Sequence {
                for (qualifier in policyQualifiers) {
                    +qualifier
                }
            }
        }
    }

    companion object : Asn1Decodable<Asn1Sequence, PolicyInformation> {
        override fun doDecode(src: Asn1Sequence) : PolicyInformation = src.decodeRethrowing{
            val id = (next().asPrimitive()).readOid()
            val policyQualifiers = if (hasNext()) {
                next().asSequence().decodeRethrowing {
                    buildSet {
                        while (hasNext()) {
                            add(PolicyQualifierInfo.decodeFromTlv(next().asSequence()))
                        }
                    }
                }
            } else emptySet()
            
            return PolicyInformation(id, policyQualifiers)
        }
    }
}

data class PolicyQualifierInfo(
    override val oid: ObjectIdentifier,
    val qualifier: Qualifier
) : Asn1Encodable<Asn1Sequence>, Identifiable {

    override fun encodeToTlv(): Asn1Sequence = Asn1.Sequence {
        +oid
        +qualifier.encodeToTlv()
    }

    companion object : Asn1Decodable<Asn1Sequence, PolicyQualifierInfo> {

        override fun doDecode(src: Asn1Sequence): PolicyQualifierInfo = src.decodeRethrowing {
            val oid = next().asPrimitive().readOid()
            val value = next()

            val qualifier: Qualifier = when (oid) {
                KnownOIDs.cps -> {
                    Qualifier.CPSUri(value.asPrimitive().asAsn1String() as Asn1String.IA5)
                }
                KnownOIDs.unotice -> {
                    Qualifier.UserNotice.decodeFromTlv(value.asSequence())
                }
                else -> throw Asn1StructuralException("Unsupported PolicyQualifierInfo OID: $oid")
            }

            return PolicyQualifierInfo(oid, qualifier)
        }
    }
}

sealed interface Qualifier : Asn1Encodable<Asn1Element>{
    data class CPSUri(val uri: Asn1String.IA5) : Qualifier {
        override fun encodeToTlv(): Asn1Primitive = uri.encodeToTlv()
    }

    data class UserNotice(val noticeRef: NoticeReference? = null, val explicitText: DisplayText? = null)
        : Qualifier {

        override fun encodeToTlv(): Asn1Sequence = Asn1.Sequence {
            noticeRef?.let { +it }
            explicitText?.let { +it }
        }

        companion object : Asn1Decodable<Asn1Element, UserNotice> {
            override fun doDecode(src: Asn1Element): UserNotice {
                src as Asn1Sequence
                val (ref, text) = src.decodeRethrowing {
                    when (src.children.size) {
                        0 -> null to null
                        1 -> {
                            when (val child = next()) {
                                is Asn1Sequence -> NoticeReference.decodeFromTlv(child) to null
                                is Asn1Primitive -> null to DisplayText.decodeFromTlv(child)
                                else -> throw Asn1StructuralException("Invalid UserNotice structure.")
                            }
                        }
                        2 -> NoticeReference.decodeFromTlv(next().asSequence()) to
                                DisplayText.decodeFromTlv(next().asPrimitive())
                        else -> throw Asn1StructuralException("Invalid number of elements in UserNotice.")
                    }
                }
                return UserNotice(ref, text)
            }
        }
    }
}

data class NoticeReference(
    val organization: DisplayText,
    val noticeNumbers: List<Asn1Integer>
) : Asn1Encodable<Asn1Sequence> {

    override fun encodeToTlv(): Asn1Sequence = Asn1.Sequence {
        +organization
        +Asn1.Sequence {
            for (num in noticeNumbers) {
                +num
            }
        }
    }

    companion object : Asn1Decodable<Asn1Sequence, NoticeReference> {
        override fun doDecode(src: Asn1Sequence): NoticeReference = src.decodeRethrowing {
            val organization = DisplayText.decodeFromTlv(next().asPrimitive())
            val numbersSeq = next().asSequence()

            val noticeNumbers = numbersSeq.children.map {
                it.asPrimitive().decodeToAsn1Integer()
            }
            return NoticeReference(organization, noticeNumbers)
        }
    }
}

data class DisplayText(val value: Asn1String) : Asn1Encodable<Asn1Primitive> {

    override fun encodeToTlv(): Asn1Primitive = value.encodeToTlv()

    companion object : Asn1Decodable<Asn1Primitive, DisplayText> {
        private val allowedTags = setOf(
            BERTags.UTF8_STRING.toULong(),
            BERTags.VISIBLE_STRING.toULong(),
            BERTags.IA5_STRING.toULong(),
            BERTags.BMP_STRING.toULong()
        )

        override fun doDecode(src: Asn1Primitive): DisplayText {
            if (!allowedTags.contains(src.tag.tagValue)) {
                throw Asn1StructuralException("Wrong DisplayText tag.")
            }
            return DisplayText(Asn1String.decodeFromTlv(src))
        }
    }
}
