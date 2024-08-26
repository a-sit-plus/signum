package at.asitplus.signum.supreme.sign

import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.RSAPadding
import at.asitplus.signum.indispensable.SignatureAlgorithm
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

internal sealed class EphemeralKeyBase <PrivateKeyT>
    (protected val privateKey: PrivateKeyT): EphemeralKey {

    class EC<PrivateKeyT, SignerT: Signer.ECDSA>(
        private val signerFactory: (PrivateKeyT, CryptoPublicKey.EC, SignatureAlgorithm.ECDSA)->SignerT,
        privateKey: PrivateKeyT, override val publicKey: CryptoPublicKey.EC,
        val digests: Set<Digest?>) : EphemeralKeyBase<PrivateKeyT>(privateKey), EphemeralKey.EC {

        override fun signer(configure: DSLConfigureFn<EphemeralSignerConfiguration>): SignerT {
            val config = DSL.resolve(::EphemeralSignerConfiguration, configure).ec.v
            val digest = resolveOption("digest", digests, Digest.entries.asSequence() + sequenceOf<Digest?>(null), config.digestSpecified, config.digest) { it?.name ?: "<none>" }
            return signerFactory(privateKey, publicKey, SignatureAlgorithm.ECDSA(digest, publicKey.curve))
        }
    }

    class RSA<PrivateKeyT, SignerT: Signer.RSA>(
        private val signerFactory: (PrivateKeyT, CryptoPublicKey.Rsa, SignatureAlgorithm.RSA)->SignerT,
        privateKey: PrivateKeyT, override val publicKey: CryptoPublicKey.Rsa,
        val digests: Set<Digest>, val paddings: Set<RSAPadding>) : EphemeralKeyBase<PrivateKeyT>(privateKey), EphemeralKey.RSA {

        override fun signer(configure: DSLConfigureFn<EphemeralSignerConfiguration>): SignerT {
            val config = DSL.resolve(::EphemeralSignerConfiguration, configure).rsa.v
            val digest = resolveOption("digest", digests, Digest.entries.asSequence(), config.digestSpecified, config.digest, Digest::name)
            val padding = resolveOption("padding", paddings, RSAPadding.entries.asSequence(), config.paddingSpecified, config.padding, RSAPadding::name)
            return signerFactory(privateKey, publicKey, SignatureAlgorithm.RSA(digest, padding))
        }
    }
}
