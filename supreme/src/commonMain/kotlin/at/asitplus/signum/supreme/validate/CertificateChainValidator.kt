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
    val validatorResults: List<ValidatorResult>
)

data class ValidatorResult(
    val validatorName: String,
    val success: Boolean,
    val errorMessage: String? = null
)

suspend fun CertificateChain.validate(
    context: CertificateValidationContext = CertificateValidationContext(),
) : CertificateValidationResult {

    val validators = context.validators.toMutableList()


    validators.addIfMissing(
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
    validators.addIfMissing(NameConstraintsValidator(this.size))
    validators.addIfMissing(KeyUsageValidator(this.size))
    validators.addIfMissing(BasicConstraintsValidator(this.size))
    validators.addIfMissing(ChainValidator(this.reversed()))


    val activeValidators = validators.toMutableSet()
    val failedResults = emptyList<ValidatorResult>().toMutableList()

    try {
        val trustAnchorValidator = TrustAnchorValidator(context.trustAnchors, this)
        this.forEach {
            trustAnchorValidator.check(it, it.criticalExtensionOids.toMutableSet())
        }
    } catch (e: Throwable) {
        failedResults.add(ValidatorResult(TrustAnchorValidator::class.simpleName!!, false, e.message))
    }

    val reversed = this.reversed()
    reversed.forEach { cert ->
        val remainingCriticalExtensions = cert.criticalExtensionOids.toMutableSet()
        cert.checkValidity(context.date)
        validators.forEach {
            try {
                it.check(cert, remainingCriticalExtensions)
            } catch (e: Throwable) {
                activeValidators.remove(it)
                failedResults.add(ValidatorResult(it::class.simpleName!!, false, e.message))
            }
        }
        if (failedResults.isEmpty()) verifyCriticalExtensions(remainingCriticalExtensions)
    }
    return CertificateValidationResult((validators.find { it is PolicyValidator } as? PolicyValidator)?.rootNode, this.leaf, failedResults)
}

fun <T : CertificateValidator> MutableCollection<CertificateValidator>.addIfMissing(validator: T) {
    if (none { it::class == validator::class }) add(validator)
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

