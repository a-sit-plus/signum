@file:OptIn(at.asitplus.signum.SignumInternals::class)

package at.asitplus.signum.indispensable.pki.extn

import at.asitplus.awesn1.*
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.UnsupportedCryptoException
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

interface PolicyQualifierInfo : Identifiable, at.asitplus.signum.indispensable.WithSourceRepresentation {
    companion object {
        operator fun invoke(
            oid: ObjectIdentifier,
            decodingFailure: UnsupportedCryptoException? = null,
        ): PolicyQualifierInfo = Unknown(
            oid, decodingFailure ?: UnsupportedCryptoException("No semantic interpretation for policy qualifier $oid"),
        )

        private class Unknown(
            override val oid: ObjectIdentifier,
            lookupResult: UnsupportedCryptoException,
        ) : PolicyQualifierInfo, ServiceLoader.UnknownShim(lookupResult)

    }
}

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
