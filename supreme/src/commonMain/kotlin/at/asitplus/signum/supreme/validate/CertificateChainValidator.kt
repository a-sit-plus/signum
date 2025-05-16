package at.asitplus.signum.supreme.validate

import at.asitplus.signum.CertificateChainValidatorException
import at.asitplus.signum.CertificateValidityException
import at.asitplus.signum.CryptoOperationFailed
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.supreme.sign.verifierFor
import at.asitplus.signum.supreme.sign.verify
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant

val supportedCriticalExtensionOids = setOf(
    KnownOIDs.keyUsage,
    KnownOIDs.certificatePolicies,
    KnownOIDs.policyMappings,
    KnownOIDs.inhibitAnyPolicy,
    KnownOIDs.cRLDistributionPoints,
    KnownOIDs.issuingDistributionPoint,
    KnownOIDs.deltaCRLIndicator,
    KnownOIDs.policyConstraints,
    KnownOIDs.basicConstraints,
    KnownOIDs.subjectAltName,
    KnownOIDs.nameConstraints
)

sealed interface Validator {
    fun check(currCert: X509Certificate)
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
    val initialPolicies: Set<ObjectIdentifier> = emptySet()
)

suspend fun CertificateChain.validate(
    context: CertificateValidationContext = CertificateValidationContext(),
    validator: suspend (x509Certificate: X509Certificate) -> CertValiditySource = { CertValiditySource.ALWAYS_ACCEPT }
) {

    val validators = mutableListOf<Validator>()

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
    if (context.basicConstraintCheck) validators.add(BasicConstraintsValidator(this.size))

    onEach { currCert ->
        currCert.checkValidity(context.date)
        verifyCriticalExtensions(currCert)
        validator(currCert)
        validators.forEach { it.check(currCert) }
    }

    for (i in 0 until lastIndex) {
        val issuer = this[i]
        val cert = this[i + 1]

        verifySignature(cert, issuer)
        subjectAndIssuerPrincipalMatch(cert, issuer)
        wasCertificateIssuedWithinIssuerValidityPeriod(
            cert.tbsCertificate.validFrom.instant,
            issuer
        )
    }
}

private fun verifySignature(
    cert: X509Certificate,
    issuer: X509Certificate
) {
    val verifier = cert.signatureAlgorithm.verifierFor(issuer.publicKey).getOrThrow()
    if (!verifier.verify(cert.tbsCertificate.encodeToDer(), cert.signature).isSuccess) {
        throw CryptoOperationFailed("Signature verification failed.")
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
}

private fun wasCertificateIssuedWithinIssuerValidityPeriod(
    dateOfIssuance: Instant,
    issuerCert: X509Certificate
) {
    val beginValidity = issuerCert.tbsCertificate.validFrom.instant
    val endValidity = issuerCert.tbsCertificate.validUntil.instant
    if (beginValidity > dateOfIssuance || dateOfIssuance > endValidity) {
        throw CertificateValidityException("Certificate issued outside issuer validity period.")
    }
}

private fun verifyCriticalExtensions(cert: X509Certificate) {
    cert.tbsCertificate.extensions
        ?.filter { it.critical }
        ?.firstOrNull { it.oid !in supportedCriticalExtensionOids }
        ?.let {
            throw CertificateChainValidatorException("Unsupported critical extension: ${it.oid}")
        }
}

