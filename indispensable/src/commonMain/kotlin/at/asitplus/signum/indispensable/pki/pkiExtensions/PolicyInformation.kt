package at.asitplus.signum.indispensable.pki.pkiExtensions

import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1Integer
import at.asitplus.signum.indispensable.asn1.Asn1Primitive
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.Asn1StructuralException
import at.asitplus.signum.indispensable.asn1.Asn1TagMismatchException
import at.asitplus.signum.indispensable.asn1.BERTags
import at.asitplus.signum.indispensable.asn1.Identifiable
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.encoding.asAsn1String
import at.asitplus.signum.indispensable.asn1.encoding.decodeToAsn1Integer
import at.asitplus.signum.indispensable.asn1.readOid
import at.asitplus.signum.indispensable.pki.X509CertificateExtension

class PolicyInformation(
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
        override fun doDecode(src: Asn1Sequence) : PolicyInformation {
            val id = (src.children[0].asPrimitive()).readOid()
            val policyQualifiers = mutableSetOf<PolicyQualifierInfo>()

            if (src.children.size > 1) {
                if (src.children[1].tag != Asn1Element.Tag.SEQUENCE) throw Asn1TagMismatchException(Asn1Element.Tag.SEQUENCE, src.children[1].tag)
                val qualifiersSequence = src.children[1].asSequence()
                for (child in qualifiersSequence.children) {
                    if (child.tag != Asn1Element.Tag.SEQUENCE) throw Asn1TagMismatchException(Asn1Element.Tag.SEQUENCE, child.tag)
                    policyQualifiers += PolicyQualifierInfo.doDecode(child.asSequence())
                }
            }
            return PolicyInformation(id, policyQualifiers)
        }
    }
}

class PolicyQualifierInfo(
    override val oid: ObjectIdentifier,
    val qualifier: Qualifier
) : Asn1Encodable<Asn1Sequence>, Identifiable {

    override fun encodeToTlv(): Asn1Sequence = Asn1.Sequence {
        +oid
        +qualifier.encodeToTlv()
    }

    companion object : Asn1Decodable<Asn1Sequence, PolicyQualifierInfo> {

        override fun doDecode(src: Asn1Sequence): PolicyQualifierInfo {
            val id = src.children[0].asPrimitive().readOid()
            val value = src.children[1]

            val qualifier: Qualifier = when (id) {
                KnownOIDs.cps -> {
                    Qualifier.CPSUri(value.asPrimitive().asAsn1String() as Asn1String.IA5)
                }
                KnownOIDs.unotice -> {
                    Qualifier.UserNotice.doDecode(value.asSequence())
                }
                else -> throw Asn1StructuralException("Unsupported PolicyQualifierInfo OID: $id")
            }

            return PolicyQualifierInfo(id, qualifier)
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
                val (ref, text) = when (src.children.size) {
                    0 -> null to null
                    1 -> {
                        val c = src.children[0]
                        when {
                            c is Asn1Sequence -> NoticeReference.doDecode(c) to null
                            c is Asn1Primitive -> null to DisplayText.doDecode(c)
                            else -> throw Asn1StructuralException("Invalid UserNotice structure.")
                        }
                    }
                    2 -> NoticeReference.doDecode(src.children[0].asSequence()) to
                            DisplayText.doDecode(src.children[1].asPrimitive())
                    else -> throw Asn1StructuralException("Invalid number of elements in UserNotice.")
                }
                return UserNotice(ref, text)
            }
        }
    }
}

class NoticeReference(
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
        override fun doDecode(src: Asn1Sequence): NoticeReference {
            if (src.children.size != 2) {
                throw Asn1StructuralException("NoticeReference must have exactly 2 elements.")
            }
            val organization = DisplayText.doDecode(src.children[0].asPrimitive())
            val numbersSeq = src.children[1].asSequence()

            val noticeNumbers = numbersSeq.children.map {
                it.asPrimitive().decodeToAsn1Integer()
            }
            return NoticeReference(organization, noticeNumbers)
        }
    }
}

class DisplayText private constructor(val string: Asn1String) : Asn1Encodable<Asn1Primitive> {

    override fun encodeToTlv(): Asn1Primitive = string.encodeToTlv()

    val value: String get() = string.value

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
            val str = Asn1String.doDecode(src)
            return DisplayText(str)
        }
    }
}

fun X509CertificateExtension.decodeCertificatePolicies(): List<PolicyInformation> {
    if (oid != KnownOIDs.certificatePolicies_2_5_29_32) throw Asn1StructuralException(message = "This extension is not CertificatePolicies extension.")

    val policyInformation = mutableListOf<PolicyInformation>()
    val sequence = value.asEncapsulatingOctetString().children.firstOrNull()?.asSequence()?.children
        ?: return emptyList()
    for (child in sequence) {
        if (child.tag != Asn1Element.Tag.SEQUENCE) throw Asn1TagMismatchException(Asn1Element.Tag.SEQUENCE, child.tag)
        policyInformation += PolicyInformation.doDecode(child.asSequence())
    }
    return policyInformation
}