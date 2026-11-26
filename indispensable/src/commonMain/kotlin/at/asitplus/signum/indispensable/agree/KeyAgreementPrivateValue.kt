package at.asitplus.signum.indispensable.agree

import at.asitplus.signum.indispensable.sign.EcdsaAlgorithm
import at.asitplus.signum.indispensable.sign.EcdsaPrivateKey
import at.asitplus.signum.indispensable.sign.signerFor
import at.asitplus.signum.UnsupportedCryptoException
import kotlin.jvm.JvmName

/**
 * Key agreement private value. Always comes with the matching [publicValue].
 */
interface KeyAgreementPrivateValue {
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
    return when (this) {
        is UsableECDHPrivateValue -> this.keyAgreement(publicValue.requireECDHPeer())
        is EcdsaPrivateKey.WithPublicKey -> EcdsaAlgorithm.withSHA256.signerFor(this).keyAgreement(publicValue.requireECDHPeer())

        else -> throw UnsupportedCryptoException("Key agreement is not supported for ${this::class.simpleName ?: "<unknown>"}")
    }
}

private fun KeyAgreementPublicValue.requireECDHPeer(): KeyAgreementPublicValue.ECDH =
    this as? KeyAgreementPublicValue.ECDH
        ?: throw IllegalArgumentException("Expected KeyAgreementPublicValue.ECDH, got ${this::class.simpleName}")

@JvmName("keyAgreementEC")
suspend fun EcdsaPrivateKey.keyAgreement(publicValue: KeyAgreementPublicValue) =
    (this as? KeyAgreementPrivateValue.ECDH)?.keyAgreement(publicValue)
        ?: throw UnsupportedCryptoException("ECDSA private key does not support key agreement")
