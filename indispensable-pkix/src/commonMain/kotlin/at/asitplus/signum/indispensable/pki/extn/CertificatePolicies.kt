@file:OptIn(at.asitplus.signum.SignumInternals::class)

package at.asitplus.signum.indispensable.pki.extn

import at.asitplus.awesn1.*
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.indispensable.SourceRepresentationStorage
import at.asitplus.signum.indispensable.pki.CertificateExtension
import com.eygraber.uri.Uri

/**
 * Certificate Policies Extension
 * This extension specifies the rules for issuing the certificate and how it can be used.
 * RFC 5280: 4.2.1.4.
 * */
data class CertificatePolicies(
    val certificatePolicies: List<PolicyInformation>,
    override val critical: Boolean = false,
) : CertificateExtension {
    @SignumInternals override val sourceRepresentation = SourceRepresentationStorage()
    override val oid get() = Companion.oid

    companion object : Identifiable {
        override val oid get() = KnownOIDs.certificatePolicies_2_5_29_32
    }
}

/** A policy and its open qualifier list. */
data class PolicyInformation(
    override val oid: ObjectIdentifier,
    val policyQualifiers: List<PolicyQualifierInfo> = emptyList(),
) : Identifiable

interface PolicyQualifierInfo : Identifiable, at.asitplus.signum.indispensable.WithSourceRepresentation

data class CpsUri(val uri: Uri) : PolicyQualifierInfo {
    constructor(uri: String) : this(Uri.parse(uri))

    override val oid get() = KnownOIDs.cps
    @SignumInternals override val sourceRepresentation = SourceRepresentationStorage()
    init { require(uri.toString().all { it.code < 128 }) { "A CPS URI must contain only ASCII characters" } }
}

data class UserNotice(
    val noticeRef: NoticeReference? = null,
    val explicitText: String? = null,
) : PolicyQualifierInfo {
    override val oid get() = KnownOIDs.unotice
    @SignumInternals override val sourceRepresentation = SourceRepresentationStorage()
}

data class NoticeReference(val organization: String, val noticeNumbers: List<com.ionspin.kotlin.bignum.integer.BigInteger>)

class OpaquePolicyQualifierInfo(
    override val oid: ObjectIdentifier,
    val decodingFailure: at.asitplus.signum.UnsupportedCryptoException? = null,
) : PolicyQualifierInfo {
    @SignumInternals override val sourceRepresentation = SourceRepresentationStorage()
    @OptIn(SignumInternals::class)
    override fun equals(other: Any?): Boolean = this === other || other is OpaquePolicyQualifierInfo &&
            oid == other.oid && (sourceRepresentation presentAndEquals other.sourceRepresentation)
    override fun hashCode(): Int = 31 * oid.hashCode() + sourceRepresentation.hashCode()
    override fun toString(): String = "OpaquePolicyQualifierInfo($oid, $sourceRepresentation)"
}
