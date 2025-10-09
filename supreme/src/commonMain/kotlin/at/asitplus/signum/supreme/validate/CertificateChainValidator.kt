package at.asitplus.signum.supreme.validate

import at.asitplus.signum.CertificateChainValidatorException
import at.asitplus.signum.CryptoOperationFailed
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.leaf
import at.asitplus.signum.indispensable.pki.root
import at.asitplus.signum.indispensable.pki.validate.BasicConstraintsValidator
import at.asitplus.signum.indispensable.pki.validate.CertificateValidator
import at.asitplus.signum.indispensable.pki.validate.KeyUsageValidator
import at.asitplus.signum.indispensable.pki.validate.NameConstraintsValidator
import at.asitplus.signum.indispensable.pki.validate.PolicyNode
import at.asitplus.signum.indispensable.pki.validate.PolicyValidator
import at.asitplus.signum.supreme.sign.verifierFor
import at.asitplus.signum.supreme.sign.verify
import kotlin.time.Instant
import kotlin.time.Clock

class CertificateValidationContext(
    val performBasicConstraintsCheck: Boolean = true,
    val performPolicyCheck: Boolean = true,
    val performNameConstraintsCheck: Boolean = true,
    val performKeyUsageCheck: Boolean = true,
    val date: Instant = Clock.System.now(),
    val explicitPolicyRequired: Boolean = false,
    val policyMappingInhibited: Boolean = false,
    val anyPolicyInhibited: Boolean = false,
    val policyQualifiersRejected: Boolean = false,
    val initialPolicies: Set<ObjectIdentifier> = emptySet(),
    val trustAnchors: Set<TrustAnchor> = emptySet(),
    val validators: Set<CertificateValidator> = emptySet()
)

data class CertificateValidationResult (
    val rootPolicyNode: PolicyNode? = null,
    val subject: X509Certificate,
)

suspend fun CertificateChain.validate(
    context: CertificateValidationContext = CertificateValidationContext(),
) : CertificateValidationResult {

    val validators = context.validators.toMutableSet()

    when {
        context.performPolicyCheck -> validators.addIfMissing(
            PolicyValidator(
                initialPolicies = context.initialPolicies,
                expPolicyRequired = context.explicitPolicyRequired,
                polMappingInhibited = context.policyMappingInhibited,
                anyPolicyInhibited = context.anyPolicyInhibited,
                certPathLen = this.size,
                rejectPolicyQualifiers = context.policyQualifiersRejected,
                rootNode = PolicyNode(
                    parent = null,
                    validPolicy = KnownOIDs.anyPolicy,
                    criticalityIndicator = false,
                    expectedPolicySet = setOf(KnownOIDs.anyPolicy),
                    generatedByPolicyMapping = false
                )
            )
        )
        context.performNameConstraintsCheck -> validators.addIfMissing(NameConstraintsValidator(this.size))
        context.performKeyUsageCheck -> validators.addIfMissing(KeyUsageValidator(this.size))
        context.performKeyUsageCheck -> validators.addIfMissing(BasicConstraintsValidator(this.size))
    }

    if (!context.trustAnchors.haveIssuerFor(this.root)) throw CertificateChainValidatorException("Untrusted root certificate.")

    val reversed = this.reversed()
    reversed.forEachIndexed { i, issuer ->
        val remainingCriticalExtensions = issuer.criticalExtensionOids.toMutableSet()
        issuer.checkValidity(context.date)
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
    return CertificateValidationResult((validators.find { it is PolicyValidator } as? PolicyValidator)?.rootNode, this.leaf)
}

fun <T : CertificateValidator> MutableCollection<CertificateValidator>.addIfMissing(validator: T) {
    if (none { it::class == validator::class }) add(validator)
}

private fun verifySignature(
    cert: X509Certificate,
    issuer: X509Certificate,
    isLeaf: Boolean,
) {
    val verifier = (cert.signatureAlgorithm as X509SignatureAlgorithm).verifierFor(issuer.decodedPublicKey.getOrThrow()).getOrThrow()
    if (!verifier.verify(cert.tbsCertificate.encodeToDer(), cert.decodedSignature.getOrThrow()).isSuccess) {
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
    if (remainingCriticalExtensions.isNotEmpty())
        throw CertificateChainValidatorException("Unsupported critical extensions: $remainingCriticalExtensions")
}

private fun Set<TrustAnchor>.haveIssuerFor(cert: X509Certificate): Boolean =
    any { it.isIssuerOf(cert) }

