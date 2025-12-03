package at.asitplus.signum.supreme.validate

import at.asitplus.catchingUnwrapped
import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.anyPolicy
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.leaf
import at.asitplus.signum.indispensable.pki.pkiExtensions.NameConstraintsExtension
import at.asitplus.signum.indispensable.pki.validate.BasicConstraintsValidator
import at.asitplus.signum.indispensable.pki.validate.CertValidityValidator
import at.asitplus.signum.indispensable.pki.validate.CertificateValidator
import at.asitplus.signum.indispensable.pki.validate.KeyIdentifierValidator
import at.asitplus.signum.indispensable.pki.validate.KeyUsageValidator
import at.asitplus.signum.indispensable.pki.validate.NameConstraintsValidator
import at.asitplus.signum.indispensable.pki.validate.PolicyNode
import at.asitplus.signum.indispensable.pki.validate.PolicyValidator
import at.asitplus.signum.indispensable.pki.validate.TimeValidityValidator
import kotlin.time.Clock
import kotlin.time.Instant

class CertificateValidationContext(
    val date: Instant = Clock.System.now(),
    val explicitPolicyRequired: Boolean = false,
    val policyMappingInhibited: Boolean = false,
    val anyPolicyInhibited: Boolean = false,
    val policyQualifiersRejected: Boolean = false,
    val initialPolicies: Set<ObjectIdentifier> = emptySet(),
    val trustAnchors: Set<TrustAnchor> = emptySet(),
    val validators: Set<CertificateValidator> = emptySet(),
    val expectedEku: Set<ObjectIdentifier> = emptySet()
)

/**
 * Represents the result of validating a certificate chain.
 */
data class CertificateValidationResult (
    val rootPolicyNode: PolicyNode? = null,
    val subject: X509Certificate,
    val validatorFailures: List<ValidatorFailure>
) {
    /** Indicates whether the certificate chain is fully valid (no validator failures). */
    val isValid: Boolean
        get() = validatorFailures.isEmpty()
}

/**
 * Represents a failure encountered by a specific validator during certificate chain validation.
 */
data class ValidatorFailure(
    val validatorName: String,
    val validator: CertificateValidator? = null,
    val errorMessage: String,
    val certificateIndex: Int,
    val cause: Throwable? = null
)

/**
 * Performs a full validation of this [CertificateChain] according to the provided [context].
 *
 * Executes all registered validators (either provided explicitly
 * in [CertificateValidationContext.validators] or automatically added defaults) against every certificate in the chain.
 * It collects validation results from each stage rather than throwing exceptions
 *
 * The following validators are automatically added if not already present:
 * [PolicyValidator] – for certificate policy processing
 * [NameConstraintsValidator] – for name constraint enforcement
 * [KeyUsageValidator] – for key usage and extended key usage checks
 * [BasicConstraintsValidator] – for CA and path length validation
 * [ChainValidator] – for signature chain integrity
 * [TimeValidityValidator] – for certificate validity period
 *
 * A [TrustAnchorValidator] is also executed once to ensure that the chain terminates
 * in a trusted root or intermediate authority.
 *
 * @return a [CertificateValidationResult] containing the resulting policy tree,
 * the end-entity certificate, and a list of any [ValidatorFailure] entries describing validation issues.
 */
@ExperimentalPkiApi
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
    val keyIdentifierValidator = KeyIdentifierValidator(this)
    validators.addIfMissing(keyIdentifierValidator)
    validators.addIfMissing(CertValidityValidator(context.date))
    validators.addIfMissing(NameConstraintsValidator(this.size))
    validators.addIfMissing(KeyUsageValidator(this.size, expectedEku = context.expectedEku))
    validators.addIfMissing(BasicConstraintsValidator(this.size))
    validators.addIfMissing(ChainValidator(this.reversed()))
    validators.addIfMissing(TimeValidityValidator(context.date, certificateChain = this.reversed()))


    val activeValidators = validators.toMutableSet()
    val validatorFailures = emptyList<ValidatorFailure>().toMutableList()
    val trustAnchorValidator = TrustAnchorValidator(context.trustAnchors, this, date = context.date)

    catchingUnwrapped {
        this.forEach {
            trustAnchorValidator.check(it, it.criticalExtensionOids.toMutableSet())
            if (trustAnchorValidator.foundTrusted) {
                catchingUnwrapped {
                    keyIdentifierValidator.checkTrustAnchorAndChild(trustAnchorValidator.trustAnchor, it)
                }.onFailure {
                    validatorFailures.add(
                        ValidatorFailure(KeyIdentifierValidator::class.simpleName!!, keyIdentifierValidator, it.message ?: "Key Identifier validation failed.", -1, it)
                    )
                }
            }
        }
    }.onFailure {
        validatorFailures.add(
            ValidatorFailure(TrustAnchorValidator::class.simpleName!!, trustAnchorValidator, it.message ?: "Trust Anchor validation failed.", -1, it)
        )
    }

    validators
        .filterIsInstance<NameConstraintsValidator>()
        .firstOrNull()
        ?.apply { previousNameConstraints = trustAnchorValidator.trustAnchor?.findExtension<NameConstraintsExtension>() }

    this.reversed().forEachIndexed { i, cert ->
        val remainingCriticalExtensions = cert.criticalExtensionOids.toMutableSet()

        val iterator = activeValidators.iterator()
        while (iterator.hasNext()) {
            val currValidator = iterator.next()
            try {
                currValidator.check(cert, remainingCriticalExtensions)
            } catch (e: Throwable) {
                iterator.remove()
                validatorFailures.add(ValidatorFailure(currValidator::class.simpleName!!, currValidator, e.message ?: "Validation failed.", i + 1, e))
            }
        }
        verifyCriticalExtensions(remainingCriticalExtensions, i , validatorFailures)
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
private fun verifyCriticalExtensions(
    remainingCriticalExtensions: Set<ObjectIdentifier>,
    certificateIndex: Int,
    failures: MutableList<ValidatorFailure>
) {
    if (remainingCriticalExtensions.isNotEmpty() && failures.none {it.validatorName == "CriticalCertificateExtensions"}) {
        failures.add(
            ValidatorFailure(
                validatorName = "CriticalCertificateExtensions",
                errorMessage = "Unsupported critical extensions: $remainingCriticalExtensions",
                certificateIndex = certificateIndex
            )
        )
    }
}

