package at.asitplus.signum.indispensable.agree

import at.asitplus.signum.indispensable.sign.EcdsaAlgorithm
import at.asitplus.signum.indispensable.sign.EcdsaPrivateKey
import at.asitplus.signum.indispensable.sign.signerFor
import kotlin.jvm.JvmName

/**
 * Key agreement private value. Always comes with the matching [publicValue].
 */
sealed interface KeyAgreementPrivateValue {
    val publicValue: KeyAgreementPublicValue

    interface ECDH: KeyAgreementPrivateValue {
        override val publicValue: KeyAgreementPublicValue.ECDH
        companion object
    }
}

/**
 * This interface exists for technical reasons and brings nothing to the public API
 */
interface UsableECDHPrivateValue : KeyAgreementPrivateValue.ECDH {
    suspend fun keyAgreement(publicValue: KeyAgreementPublicValue.ECDH): ByteArray
}

/**
 * Performs key agreement
 */
suspend fun KeyAgreementPrivateValue.keyAgreement(publicValue: KeyAgreementPublicValue): ByteArray {
    if (publicValue !is KeyAgreementPublicValue.ECDH)
        throw IllegalArgumentException("Expected KeyAgreementPublicValue.ECDH, got ${publicValue::class.simpleName}")
    return when (this) {
        is UsableECDHPrivateValue -> this.keyAgreement(publicValue)
        is EcdsaPrivateKey.WithPublicKey -> EcdsaAlgorithm.withSHA256.signerFor(this).keyAgreement(publicValue)

        else -> throw IllegalStateException("Type hierarchy failure? Actual type is ${this::class.simpleName ?: "<null>"}")
    }
}

@JvmName("keyAgreementEC")
suspend fun EcdsaPrivateKey.keyAgreement(publicValue: KeyAgreementPublicValue) =
    (this as KeyAgreementPrivateValue.ECDH).keyAgreement(publicValue)
