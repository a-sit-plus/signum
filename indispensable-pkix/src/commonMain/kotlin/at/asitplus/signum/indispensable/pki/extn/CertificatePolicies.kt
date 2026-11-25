package at.asitplus.signum.indispensable.pki.extn

import at.asitplus.awesn1.*
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.SourceRepresentationStorage
import at.asitplus.signum.indispensable.WithSourceRepresentation
import at.asitplus.signum.indispensable.pki.CertificateExtension
import at.asitplus.signum.indispensable.pki.Asn1PolicyQualifier
import com.eygraber.uri.Uri
import kotlinx.serialization.Serializable

/**
 * Certificate Policies Extension
 * This extension specifies the rules for issuing the certificate and how it can be used.
 * RFC 5280: 4.2.1.4.
 * */
data class CertificatePolicies(
    val certificatePolicies: List<PolicyInformation>,
    override val critical: Boolean = false,
) : CertificateExtension {
    override val sourceRepresentation = SourceRepresentationStorage()
    override val oid get() = Companion.oid

    companion object : Identifiable {
        override val oid get() = KnownOIDs.certificatePolicies_2_5_29_32
    }
}

/** A policy and its open qualifier list. */
data class PolicyInformation(
    override val oid: ObjectIdentifier,
    val policyQualifiers: List<PolicyQualifierInfo> = emptyList(),
) : Identifiable {
    /** ASN.1 schema from [RFC 5280, Section 4.2.1.4](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.4). */
    @Serializable
    internal data class Asn1Representation(
        val oid: ObjectIdentifier,
        val qualifiers: List<Asn1PolicyQualifier> = emptyList(),
    )
}

interface PolicyQualifierInfo : Identifiable, WithSourceRepresentation {
    @OptIn(SignumInternals::class)
    class Unknown internal constructor(
        source: Asn1PolicyQualifier,
        lookupResult: UnsupportedCryptoException,
    ) : PolicyQualifierInfo, ServiceLoader.UnknownShim(source, lookupResult) {
        override val oid = source.oid
    }

}

data class CpsUri(val uri: Uri) : PolicyQualifierInfo {
    constructor(uri: String) : this(Uri.parse(uri))

    override val oid get() = KnownOIDs.cps
    override val sourceRepresentation = SourceRepresentationStorage()
    init { require(uri.toString().all { it.code < 128 }) { "A CPS URI must contain only ASCII characters" } }
}

data class UserNotice(
    val noticeRef: NoticeReference? = null,
    val explicitText: String? = null,
) : PolicyQualifierInfo {
    /** ASN.1 schema from [RFC 5280, Section 4.2.1.4](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.4). */
    @Serializable
    internal data class Asn1Representation(
        val noticeRef: NoticeReference.Asn1Representation? = null,
        val explicitText: Asn1String? = null,
    )

    override val oid get() = KnownOIDs.unotice
    override val sourceRepresentation = SourceRepresentationStorage()
}

data class NoticeReference(val organization: String, val noticeNumbers: List<com.ionspin.kotlin.bignum.integer.BigInteger>) {
    /** ASN.1 schema from [RFC 5280, Section 4.2.1.4](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.4). */
    @Serializable
    internal data class Asn1Representation(val organization: Asn1String, val numbers: List<Asn1Integer>)
}
