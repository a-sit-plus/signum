package at.asitplus.signum.supreme.validate

import at.asitplus.signum.CertificateChainValidatorException
import at.asitplus.signum.CryptoOperationFailed
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.root
import at.asitplus.signum.supreme.sign.verifierFor
import at.asitplus.signum.supreme.sign.verify
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant

val uncheckedCriticalExtensionOids = setOf(
    KnownOIDs.cRLDistributionPoints_2_5_29_31,
    KnownOIDs.issuingDistributionPoint_2_5_29_28,
    KnownOIDs.deltaCRLIndicator,
)

interface CertificateValidator {
    // Every validator removes checked critical extensions
    fun check(currCert: X509Certificate, remainingCriticalExtensions: MutableSet<ObjectIdentifier>)
}

sealed interface CertValiditySource {
    data object ALWAYS_ACCEPT : CertValiditySource
}

class CertificateRevocationList : CertValiditySource {
    // TODO
}

class OSCPStaplingResponse : CertValiditySource {
    // TODO
}

class CertificateValidationContext(
//   Basic constraints should be ignored in SEAL certificate verification
    val basicConstraintCheck: Boolean = true,
    val date: Instant = Clock.System.now(),
    val explicitPolicyRequired: Boolean = false,
    val policyMappingInhibited: Boolean = false,
    val anyPolicyInhibited: Boolean = false,
    val policyQualifiersRejected: Boolean = false,
    val initialPolicies: Set<ObjectIdentifier> = emptySet(),
    val trustAnchors: Set<TrustAnchor> = emptySet()
)

class CertificateValidationResult (
    val rootPolicyNode: PolicyNode? = null
)

suspend fun CertificateChain.validate(
    context: CertificateValidationContext = CertificateValidationContext(),
    validator: suspend (x509Certificate: X509Certificate) -> CertValiditySource = { CertValiditySource.ALWAYS_ACCEPT }
) : CertificateValidationResult {

    val validators = mutableListOf<CertificateValidator>()

    val rootNode = PolicyNode(
        parent = null,
        validPolicy = KnownOIDs.anyPolicy,
        criticalityIndicator = false,
        expectedPolicySet = setOf(KnownOIDs.anyPolicy),
        generatedByPolicyMapping = false
    )
    validators.add(
        PolicyValidator(
            initialPolicies = context.initialPolicies,
            expPolicyRequired = context.explicitPolicyRequired,
            polMappingInhibited = context.policyMappingInhibited,
            anyPolicyInhibited = context.anyPolicyInhibited,
            certPathLen = this.size,
            rejectPolicyQualifiers = context.policyQualifiersRejected,
            rootNode = rootNode
        )
    )
    validators.add(NameConstraintsValidator(this.size))
    validators.add(KeyUsageValidator(this.size))
    if (context.basicConstraintCheck) validators.add(BasicConstraintsValidator(this.size))

    if (!context.trustAnchors.hasIssuerFor(this.root)) throw CertificateChainValidatorException("Untrusted root certificate.")

    val reversed = this.reversed()
    reversed.forEachIndexed { i, issuer ->
        val remainingCriticalExtensions = issuer.criticalExtensionOids
        issuer.checkValidity(context.date)
        validator(issuer)
        validators.forEach { it.check(issuer, remainingCriticalExtensions) }
        verifyCriticalExtensions(remainingCriticalExtensions)

        if (issuer != reversed.last()) {
            val childCert = reversed[i + 1]
            verifySignature(childCert, issuer, childCert == reversed.last())
            subjectAndIssuerPrincipalMatch(childCert, issuer)
            wasCertificateIssuedWithinIssuerValidityPeriod(
                childCert.tbsCertificate.validFrom.instant,
                issuer
            )
        }
    }
    return CertificateValidationResult((validators.find { it is PolicyValidator } as? PolicyValidator)?.rootNode)
}

private fun verifySignature(
    cert: X509Certificate,
    issuer: X509Certificate,
    isLeaf: Boolean,
) {
    val verifier = cert.signatureAlgorithm.verifierFor(issuer.publicKey).getOrThrow()
    if (!verifier.verify(cert.tbsCertificate.encodeToDer(), cert.signature).isSuccess) {
        throw CryptoOperationFailed("Signature verification failed in ${if (isLeaf) "leaf" else "CA"} certificate.")
    }
}

private fun subjectAndIssuerPrincipalMatch(
    cert: X509Certificate,
    issuer: X509Certificate
) {
    val issuerInChildPrincipal = cert.tbsCertificate.issuerName
    val subjectInIssuerPrincipal = issuer.tbsCertificate.subjectName
    if (issuerInChildPrincipal != subjectInIssuerPrincipal) {
        throw CertificateChainValidatorException("Subject of issuer cert and issuer of child certificate mismatch.")
    }

    if (cert.tbsCertificate.issuerUniqueID != issuer.tbsCertificate.subjectUniqueID) {
        throw CertificateChainValidatorException("UID of issuer cert and UID of issuer in child certificate mismatch.")
    }
}

private fun wasCertificateIssuedWithinIssuerValidityPeriod(
    dateOfIssuance: Instant,
    issuerCert: X509Certificate
) {
    val beginValidity = issuerCert.tbsCertificate.validFrom.instant
    val endValidity = issuerCert.tbsCertificate.validUntil.instant
    if (beginValidity > dateOfIssuance || dateOfIssuance > endValidity) {
        throw CertificateChainValidatorException("Certificate issued outside issuer validity period.")
    }
}

/**
 * Checks if there are any unhandled critical extensions remaining,
 * which would indicate that the current validators do not support them.
 */
private fun verifyCriticalExtensions(remainingCriticalExtensions: MutableSet<ObjectIdentifier>) {
    // TODO remove after adding CRL check
    remainingCriticalExtensions.removeAll(uncheckedCriticalExtensionOids)
    if (remainingCriticalExtensions.isNotEmpty())
        throw CertificateChainValidatorException("Unsupported critical extensions: $remainingCriticalExtensions")
}

private fun Set<TrustAnchor>.hasIssuerFor(cert: X509Certificate): Boolean =
    any { it.isIssuerOf(cert) }

