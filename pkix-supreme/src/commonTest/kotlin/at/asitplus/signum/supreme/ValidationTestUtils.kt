package at.asitplus.signum.supreme

import at.asitplus.signum.supreme.validate.CertificateValidationResult
import io.kotest.matchers.booleans.shouldBeFalse
import io.kotest.matchers.booleans.shouldBeTrue
import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.contract

@OptIn(ExperimentalContracts::class)
fun CertificateValidationResult.shouldBeValid(): Boolean {
    contract {
        returns() implies (this@shouldBeValid is CertificateValidationResult.Success)
    }
    return isValid.shouldBeTrue()
}

@OptIn(ExperimentalContracts::class)
fun CertificateValidationResult.shouldBeInvalid(): Boolean {
    contract {
        returns() implies (this@shouldBeInvalid is CertificateValidationResult.Failure)
    }
    return isValid.shouldBeFalse()
}
