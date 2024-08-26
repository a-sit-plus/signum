package at.asitplus.signum.supreme.sign

import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.RSAPadding
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.supreme.dsl.DSL
import at.asitplus.signum.supreme.dsl.DSLConfigureFn
import at.asitplus.signum.supreme.os.SignerConfiguration

internal expect fun makeEphemeralKey(configuration: EphemeralSigningKeyConfiguration) : EphemeralKey

class EphemeralSigningKeyConfiguration internal constructor(): SigningKeyConfiguration() {
    class ECConfiguration internal constructor(): SigningKeyConfiguration.ECConfiguration() {
        init { digests = (Digest.entries.asSequence() + sequenceOf<Digest?>(null)).toSet() }
    }
    override val ec = _algSpecific.option(::ECConfiguration)
    class RSAConfiguration internal constructor(): SigningKeyConfiguration.RSAConfiguration() {
        init { digests = Digest.entries.toSet(); paddings = RSAPadding.entries.toSet() }
    }
    override val rsa = _algSpecific.option(::RSAConfiguration)
}
typealias EphemeralSignerConfiguration = SignerConfiguration

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
            val digest = when (config.digestSpecified) {
                true -> {
                    require (digests.contains(config.digest))
                    { "Digest ${config.digest} unsupported (supported: ${digests.joinToString(",")}" }
                    config.digest
                }
                false -> when {
                    digests.contains(Digest.SHA256) -> Digest.SHA256
                    digests.contains(Digest.SHA384) -> Digest.SHA384
                    digests.contains(Digest.SHA512) -> Digest.SHA512
                    else -> digests.first()
                }
            }
            return signerFactory(privateKey, publicKey, SignatureAlgorithm.ECDSA(digest, publicKey.curve))
        }
    }

    class RSA<PrivateKeyT, SignerT: Signer.RSA>(
        private val signerFactory: (PrivateKeyT, CryptoPublicKey.Rsa, SignatureAlgorithm.RSA)->SignerT,
        privateKey: PrivateKeyT, override val publicKey: CryptoPublicKey.Rsa,
        val digests: Set<Digest>, val paddings: Set<RSAPadding>) : EphemeralKeyBase<PrivateKeyT>(privateKey), EphemeralKey.RSA {

        override fun signer(configure: DSLConfigureFn<EphemeralSignerConfiguration>): SignerT {
            val config = DSL.resolve(::EphemeralSignerConfiguration, configure).rsa.v
            val digest = when (config.digestSpecified) {
                true -> {
                    require (digests.contains(config.digest))
                    { "Digest ${config.digest} unsupported (supported: ${digests.joinToString(", ")}" }
                    config.digest
                }
                false -> when {
                    digests.contains(Digest.SHA256) -> Digest.SHA256
                    digests.contains(Digest.SHA384) -> Digest.SHA384
                    digests.contains(Digest.SHA512) -> Digest.SHA512
                    else -> digests.first()
                }
            }
            val padding = when (config.paddingSpecified) {
                true -> {
                    require (paddings.contains(config.padding))
                    { "Padding ${config.padding} unsupported (supported: ${paddings.joinToString(", ")}" }
                    config.padding
                }
                false -> when {
                    paddings.contains(RSAPadding.PSS) -> RSAPadding.PSS
                    paddings.contains(RSAPadding.PKCS1) -> RSAPadding.PKCS1
                    else -> paddings.first()
                }
            }
            return signerFactory(privateKey, publicKey, SignatureAlgorithm.RSA(digest, padding))
        }
    }
}
