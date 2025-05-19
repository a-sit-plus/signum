package at.asitplus.signum.supreme.validate

import at.asitplus.signum.CertificateChainValidatorException
import at.asitplus.signum.CryptoOperationFailed
import at.asitplus.signum.KeyUsageException
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.X509KeyUsage
import at.asitplus.signum.supreme.sign.verifierFor
import at.asitplus.signum.supreme.sign.verify
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant

val supportedCriticalExtensionOids = setOf(
    KnownOIDs.keyUsage,
    KnownOIDs.certificatePolicies_2_5_29_32,
    KnownOIDs.policyMappings,
    KnownOIDs.inhibitAnyPolicy,
    KnownOIDs.cRLDistributionPoints_2_5_29_31,
    KnownOIDs.issuingDistributionPoint_2_5_29_28,
    KnownOIDs.deltaCRLIndicator,
    KnownOIDs.policyConstraints_2_5_29_36,
    KnownOIDs.basicConstraints_2_5_29_19,
    KnownOIDs.subjectAltName_2_5_29_17,
    KnownOIDs.nameConstraints_2_5_29_30
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

    val reversed = this.reversed()
    reversed.forEach { it.checkValidity(context.date) }
    reversed.forEachIndexed { i, issuer ->
        verifyCriticalExtensions(issuer)
        validator(issuer)
        validators.forEach { it.check(issuer) }

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
}

private fun verifySignature(
    cert: X509Certificate,
    issuer: X509Certificate,
    isLeaf: Boolean
) {
    verifyIntermediateKeyUsage(issuer)
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

private fun verifyCriticalExtensions(cert: X509Certificate) {
    cert.tbsCertificate.extensions
        ?.filter { it.critical }
        ?.firstOrNull { it.oid !in supportedCriticalExtensionOids }
        ?.let {
            throw CertificateChainValidatorException("Unsupported critical extension: ${it.oid}")
        }
}

private fun verifyIntermediateKeyUsage(currCert: X509Certificate) {
    if (!currCert.tbsCertificate.keyUsage.contains(X509KeyUsage.KEY_CERT_SIGN)) {
        throw KeyUsageException("Digital signature key usage extension not present at the intermediate cert!")
    }
}

