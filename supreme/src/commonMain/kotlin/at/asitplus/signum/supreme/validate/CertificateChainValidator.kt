package at.asitplus.signum.supreme.validate

import at.asitplus.catchingUnwrapped
import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.anyPolicy
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.leaf
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
 * Performs a full, potentially unsafe validation of this [CertificateChain] using the provided [validators].
 *
 * This function executes all validators in [validators] against every certificate in the chain.
 * It does not automatically enforce RFC 5280 compliance — any custom validators can be provided
 */
@ExperimentalPkiApi
suspend fun CertificateChain.validate(
    validators: List<CertificateValidator> = emptyList()
) : CertificateValidationResult {

    val activeValidators = validators.toMutableSet()
    val validatorFailures = mutableListOf<ValidatorFailure>()
    val trustAnchorValidator = activeValidators.filterIsInstance<TrustAnchorValidator>().firstOrNull()
    val keyIdentifierValidator = activeValidators.filterIsInstance<KeyIdentifierValidator>().firstOrNull()
    val nameConstraintsValidator = activeValidators.filterIsInstance<NameConstraintsValidator>().firstOrNull()

    trustAnchorValidator?.let { trustAnchorValidator
        catchingUnwrapped {
            this.forEach {
                trustAnchorValidator.check(it, it.criticalExtensionOids.toMutableSet())
                if (trustAnchorValidator.foundTrusted) {
                    catchingUnwrapped {
                        keyIdentifierValidator?.checkTrustAnchorAndChild(trustAnchorValidator.trustAnchor?.cert, it)
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

        nameConstraintsValidator?.previousNameConstraints = trustAnchorValidator.trustAnchor?.nameConstraints
        activeValidators.remove(trustAnchorValidator)
    }

    this.reversed().forEachIndexed { i, cert ->
        val remainingCriticalExtensions = cert.criticalExtensionOids.toMutableSet()

        val validatorIterator = activeValidators.iterator()
        while (validatorIterator.hasNext()) {
            val currValidator = validatorIterator.next()
            try {
                currValidator.check(cert, remainingCriticalExtensions)
            } catch (e: Throwable) {
                validatorIterator.remove()
                validatorFailures.add(ValidatorFailure(currValidator::class.simpleName!!, currValidator, e.message ?: "Validation failed.", i + 1, e))
            }
        }
        verifyCriticalExtensions(remainingCriticalExtensions, i , validatorFailures)
    }
    return CertificateValidationResult((validators.find { it is PolicyValidator } as? PolicyValidator)?.rootNode, this.leaf, validatorFailures)
}

/**
 * Performs an RFC 5280-compliant validation of this [CertificateChain] using default validators.
 *
 * This function automatically adds all mandatory validators required for standard X.509
 * path validation according to RFC 5280, including:
 * [PolicyValidator] – for certificate policy processing
 * [NameConstraintsValidator] – for name constraint enforcement
 * [KeyUsageValidator] – for key usage and extended key usage checks
 * [BasicConstraintsValidator] – for CA and path length validation
 * [ChainValidator] – for signature chain integrity
 * [TimeValidityValidator] – for certificate validity period
 * [CertValidityValidator] – for checking whether the certificate is constructed correctly, since some components are decoded too leniently
 *
 * [TrustAnchorValidator] is also executed to ensure that the chain terminates
 * in a trusted root or intermediate authority.
 * [KeyIdentifierValidator] is added to validate Subject and Authority key identifiers
 *
 * Validation results are collected rather than throwing exceptions
 *
 * @return a [CertificateValidationResult] containing the resulting policy tree,
 * the end-entity certificate, and a list of any [ValidatorFailure] entries describing validation issues.
 */
@OptIn(HazardousMaterials::class)
@ExperimentalPkiApi
suspend fun CertificateChain.validate(
    context: CertificateValidationContext = CertificateValidationContext()
) : CertificateValidationResult {
    val validators = defineRFC5280Validators(context, this)
    return this.validate(validators)
}

/** Constructs list of default validator used in RFC5280 validation based on [context] */
fun defineRFC5280Validators(
    context: CertificateValidationContext,
    chain: CertificateChain
) : MutableList<CertificateValidator> {
    val validators = mutableListOf<CertificateValidator>()

    validators.add(
        PolicyValidator(
            initialPolicies = context.initialPolicies,
            expPolicyRequired = context.explicitPolicyRequired,
            polMappingInhibited = context.policyMappingInhibited,
            anyPolicyInhibited = context.anyPolicyInhibited,
            certPathLen = chain.size,
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
    validators += listOf(
        CertValidityValidator(context.date),
        NameConstraintsValidator(chain.size),
        KeyUsageValidator(chain.size, expectedEku = context.expectedEku),
        BasicConstraintsValidator(chain.size),
        ChainValidator(chain.reversed()),
        TimeValidityValidator(context.date, certificateChain = chain.reversed()),
        TrustAnchorValidator(context.trustAnchors, chain, date = context.date),
        KeyIdentifierValidator(chain)
    )
    return validators
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

