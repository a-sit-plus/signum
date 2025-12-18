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
import at.asitplus.signum.indispensable.pki.root
import at.asitplus.signum.indispensable.pki.validate.*
import kotlin.time.Clock
import kotlin.time.Instant

@OptIn(ExperimentalPkiApi::class)
class CertificateValidationContext(
    val date: Instant = Clock.System.now(),
    val explicitPolicyRequired: Boolean = false,
    val policyMappingInhibited: Boolean = false,
    val anyPolicyInhibited: Boolean = false,
    val policyQualifiersRejected: Boolean = false,
    val initialPolicies: Set<ObjectIdentifier> = emptySet(),
    val allowIncludedTrustAnchor: Boolean = true,
    val trustAnchors: Set<TrustAnchor> = SystemTrustStore,
    val expectedEku: Set<ObjectIdentifier> = emptySet()
)

/**
 * Represents the result of validating a certificate chain.
 */
data class CertificateValidationResult(
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
 * Represents a factory for creating certificate validators from a given certificate chain
 * and a validation context. A factory is needed because validation is inherently stateful and individual
 * validators carry mutable state.
 *
 * @param generate A function that takes a `CertificateChain` and a `CertificateValidationContext`,
 *                 and returns a list of `CertificateValidator` instances to be applied.
 */
fun interface ValidatorFactory {
    fun CertificateChain.generate(
        context: CertificateValidationContext
    ): MutableList<CertificateValidator>

    companion object {
        val RFC5280: ValidatorFactory =
            ValidatorFactory { context -> defineRFC5280Validators(context, this) }
    }
}


/**
 * Performs a full, potentially unsafe validation of this [CertificateChain] using the provided [validators].
 *
 * This function executes all validators in [validators] against every certificate in the chain.
 * It does not automatically enforce RFC 5280 compliance — any custom validators can be provided
 */
@ExperimentalPkiApi
suspend fun CertificateChain.validate(
    validatorFactory: ValidatorFactory = ValidatorFactory.RFC5280,
    context: CertificateValidationContext = CertificateValidationContext()
): CertificateValidationResult {

    val validators = with(validatorFactory) { this@validate.generate(context) }
    val processingChain = if (context.allowIncludedTrustAnchor && context.trustAnchors.any {
            it.matchesCertificate(this.root)
        }) this.dropLast(1) else this

    val activeValidators = validators.toMutableSet()
    val validatorFailures = mutableListOf<ValidatorFailure>()
    val trustAnchorValidator = activeValidators.filterIsInstance<TrustAnchorValidator>().firstOrNull()
    val keyIdentifierValidator = activeValidators.filterIsInstance<KeyIdentifierValidator>().firstOrNull()
    val nameConstraintsValidator = activeValidators.filterIsInstance<NameConstraintsValidator>().firstOrNull()

    trustAnchorValidator?.let { trustAnchorValidator ->
        catchingUnwrapped {
            processingChain.forEach {
                trustAnchorValidator.check(it, it.criticalExtensionOids.toMutableSet())
                if (trustAnchorValidator.foundTrusted) {
                    catchingUnwrapped {
                        keyIdentifierValidator?.checkTrustAnchorAndChild(trustAnchorValidator.trustAnchor?.cert, it)
                    }.onFailure {
                        validatorFailures.add(
                            ValidatorFailure(
                                KeyIdentifierValidator::class.simpleName!!,
                                keyIdentifierValidator,
                                it.message ?: "Key Identifier validation failed.",
                                -1,
                                it
                            )
                        )
                    }
                }
            }
        }.onFailure {
            validatorFailures.add(
                ValidatorFailure(
                    TrustAnchorValidator::class.simpleName!!,
                    trustAnchorValidator,
                    it.message ?: "Trust Anchor validation failed.",
                    -1,
                    it
                )
            )
        }

        nameConstraintsValidator?.previousNameConstraints = trustAnchorValidator.trustAnchor?.nameConstraints
        activeValidators.remove(trustAnchorValidator)
    }

    processingChain.reversed().forEachIndexed { i, cert ->
        val remainingCriticalExtensions = cert.criticalExtensionOids.toMutableSet()

        val validatorIterator = activeValidators.iterator()
        while (validatorIterator.hasNext()) {
            val currValidator = validatorIterator.next()
            try {
                currValidator.check(cert, remainingCriticalExtensions)
            } catch (e: Throwable) {
                validatorIterator.remove()
                validatorFailures.add(
                    ValidatorFailure(
                        currValidator::class.simpleName!!,
                        currValidator,
                        e.message ?: "Validation failed.",
                        i + 1,
                        e
                    )
                )
            }
        }
        verifyCriticalExtensions(remainingCriticalExtensions, i, validatorFailures)
    }
    return CertificateValidationResult((validators.find { it is PolicyValidator } as? PolicyValidator)?.rootNode,
        this.leaf,
        validatorFailures)
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
): CertificateValidationResult = validate(ValidatorFactory.RFC5280, context)

/** Constructs list of default validator used in RFC5280 validation based on [context] */
private fun defineRFC5280Validators(
    context: CertificateValidationContext,
    chain: CertificateChain
): MutableList<CertificateValidator> {
    val validators = mutableListOf<CertificateValidator>()
    val (pathLen, processingChain) =
        if (context.allowIncludedTrustAnchor && context.trustAnchors.any { it.matchesCertificate(chain.root) }) {
            chain.size - 1 to chain.dropLast(1)
        } else {
            chain.size to chain
        }

    validators.add(
        PolicyValidator(
            initialPolicies = context.initialPolicies,
            expPolicyRequired = context.explicitPolicyRequired,
            polMappingInhibited = context.policyMappingInhibited,
            anyPolicyInhibited = context.anyPolicyInhibited,
            certPathLen = pathLen,
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
        NameConstraintsValidator(pathLen),
        KeyUsageValidator(pathLen, expectedEku = context.expectedEku),
        BasicConstraintsValidator(pathLen),
        ChainValidator(processingChain.reversed()),
        TimeValidityValidator(context.date, certChain = processingChain.reversed()),
        TrustAnchorValidator(context.trustAnchors, processingChain, date = context.date),
        KeyIdentifierValidator(processingChain)
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
    if (remainingCriticalExtensions.isNotEmpty() && failures.none { it.validatorName == "CriticalCertificateExtensions" }) {
        failures.add(
            ValidatorFailure(
                validatorName = "CriticalCertificateExtensions",
                errorMessage = "Unsupported critical extensions: $remainingCriticalExtensions",
                certificateIndex = certificateIndex
            )
        )
    }
}

