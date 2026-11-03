@file:OptIn(HazardousMaterials::class)

package at.asitplus.signum.indispensable.pki.validate

import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.Certificate as X509Certificate
import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.contract


/**
 * Represents the result of validating a certificate chain.
 */
sealed class CertificateValidationResult {

    /** Indicates whether the certificate chain is fully valid (no validator failures). */
    @OptIn(ExperimentalContracts::class)
    val isValid: Boolean
        get() {
            contract {
                returns(true) implies (this@CertificateValidationResult is Success)
                returns(false) implies (this@CertificateValidationResult is Failure || this@CertificateValidationResult is BuildPathFailure)
            }
            return this is Success
        }

    companion object {
        internal operator fun invoke(
            rootPolicyNode: PolicyNode?,
            subject: X509Certificate,
            validatorFailures: List<ValidatorFailure>
        ) = if (validatorFailures.isNotEmpty()) {
            Failure(validatorFailures)
        } else Success(rootPolicyNode, subject)
    }

    data class Success(val rootPolicyNode: PolicyNode?, val subject: X509Certificate) : CertificateValidationResult() {
        override fun toString(): String {
            return "Success(" +
                    "rootPolicyNode=$rootPolicyNode, " +
                    "subject=$subject" +
                    ")"
        }

    }

    data class Failure(val validatorFailures: List<ValidatorFailure>) : CertificateValidationResult() {
        init {
            require(validatorFailures.isNotEmpty()) { "Certificate validation failure must not be empty" }
        }

        override fun toString(): String {
            return "Failure(" +
                    "validatorFailures=$validatorFailures" +
                    ")"
        }
    }

    data class BuildPathFailure(
        val chainFailures: Map<CertificateChain, Failure>
    ) : CertificateValidationResult()
}

/**
 * Represents a failure encountered by a specific validator during certificate chain validation.
 */
data class ValidatorFailure(
    val validatorName: String,
    val validator: CertificateChainValidator? = null,
    val errorMessage: String,
    val cause: Throwable? = null
) {
    override fun toString(): String {
        return "ValidatorFailure(" +
                "validatorName='$validatorName', " +
                "validator=$validator, " +
                "errorMessage='$errorMessage', " +
                "cause=$cause" +
                ")"
    }
}
