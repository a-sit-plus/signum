package at.asitplus.signum.supreme.validate

import at.asitplus.signum.CertificateChainValidatorException
import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.leaf
import at.asitplus.signum.indispensable.pki.validate.BasicConstraintsValidator
import at.asitplus.signum.indispensable.pki.validate.CertificateValidator
import at.asitplus.signum.indispensable.pki.validate.KeyUsageValidator
import at.asitplus.signum.indispensable.pki.validate.NameConstraintsValidator
import at.asitplus.signum.indispensable.pki.validate.PolicyNode
import at.asitplus.signum.indispensable.pki.validate.PolicyValidator
import at.asitplus.signum.indispensable.pki.validate.TimeValidityValidator
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
    val validatorFailures: List<ValidatorFailure>
) {
    val isValid: Boolean
        get() = validatorFailures.isEmpty()
}

data class ValidatorFailure(
    val validatorName: String,
    val validator: CertificateValidator,
    val errorMessage: String,
    val certificateIndex: Int,
    val cause: Throwable? = null
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
    validators.addIfMissing(TimeValidityValidator(context.date))


    val activeValidators = validators.toMutableSet()
    val validatorFailures = emptyList<ValidatorFailure>().toMutableList()
    val trustAnchorValidator = TrustAnchorValidator(context.trustAnchors, this)

    try {
        this.forEach {
            trustAnchorValidator.check(it, it.criticalExtensionOids.toMutableSet())
        }
    } catch (e: Throwable) {
        validatorFailures.add(ValidatorFailure(TrustAnchorValidator::class.simpleName!!, trustAnchorValidator, e.message ?: "Trust Anchor validation failed.", -1, e))
    }

    this.reversed().forEachIndexed { i, cert ->
        val remainingCriticalExtensions = cert.criticalExtensionOids.toMutableSet()
        validators.forEach {
            try {
                it.check(cert, remainingCriticalExtensions)
            } catch (e: Throwable) {
                activeValidators.remove(it)
                validatorFailures.add(ValidatorFailure(it::class.simpleName!!, it, e.message ?: "Validation failed.", i, e))
            }
        }
        verifyCriticalExtensions(remainingCriticalExtensions)
    }
    return CertificateValidationResult((validators.find { it is PolicyValidator } as? PolicyValidator)?.rootNode, this.leaf, validatorFailures)
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

