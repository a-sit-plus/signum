package at.asitplus.signum.supreme.sign

import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.supreme.dsl.DSL
import at.asitplus.signum.supreme.dsl.DSLConfigureFn
import at.asitplus.signum.supreme.os.SignerConfiguration

internal expect fun makeEphemeralKey(configuration: EphemeralSigningKeyConfiguration) : EphemeralKey

expect class EphemeralSigningKeyConfiguration internal constructor(): SigningKeyConfiguration
expect class EphemeralSignerConfiguration internal constructor(): SignerConfiguration

sealed interface EphemeralKey {
    val publicKey: CryptoPublicKey
    fun signer(configure: DSLConfigureFn<EphemeralSignerConfiguration> = null): Signer
    interface EC: EphemeralKey {
        override val publicKey: CryptoPublicKey.EC
        override fun signer(configure: DSLConfigureFn<EphemeralSignerConfiguration>): Signer.ECDSA
    }
    interface RSA: EphemeralKey {
        override val publicKey: CryptoPublicKey.Rsa
        override fun signer(configure: DSLConfigureFn<EphemeralSignerConfiguration>): Signer.RSA
    }
    companion object {
        operator fun invoke(configure: DSLConfigureFn<EphemeralSigningKeyConfiguration> = null) =
            makeEphemeralKey(DSL.resolve(::EphemeralSigningKeyConfiguration, configure))
    }
}
