@file:OptIn(HazardousMaterials::class)

package at.asitplus.signum.supreme.sign

import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.RSAPadding
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.supreme.HazardousMaterials
import at.asitplus.signum.supreme.dsl.DSL
import at.asitplus.signum.supreme.dsl.DSLConfigureFn
import at.asitplus.signum.supreme.os.SignerConfiguration

expect interface PlatformEphemeralKey
internal expect fun makeEphemeralKey(configuration: EphemeralSigningKeyConfiguration) : EphemeralKey<PlatformEphemeralKey>

open class EphemeralSigningKeyConfigurationBase internal constructor(): SigningKeyConfiguration() {
    class ECConfiguration internal constructor(): SigningKeyConfiguration.ECConfiguration() {
        init { digests = (Digest.entries.asSequence() + sequenceOf<Digest?>(null)).toSet() }
    }
    override val ec = _algSpecific.option(::ECConfiguration)
    class RSAConfiguration internal constructor(): SigningKeyConfiguration.RSAConfiguration() {
        init { digests = Digest.entries.toSet(); paddings = RSAPadding.entries.toSet() }
    }
    override val rsa = _algSpecific.option(::RSAConfiguration)
}
expect class EphemeralSigningKeyConfiguration internal constructor(): EphemeralSigningKeyConfigurationBase

typealias EphemeralSignerConfigurationBase = SignerConfiguration
expect class EphemeralSignerConfiguration internal constructor(): SignerConfiguration

sealed interface EphemeralKey <out PrivateKeyT> {
    @HazardousMaterials val privateKey: PrivateKeyT
    val publicKey: CryptoPublicKey
    fun signer(configure: DSLConfigureFn<EphemeralSignerConfiguration> = null): Signer
    interface EC<PrivateKeyT>: EphemeralKey<PrivateKeyT> {
        override val publicKey: CryptoPublicKey.EC
        override fun signer(configure: DSLConfigureFn<EphemeralSignerConfiguration>): Signer.ECDSA
    }
    interface RSA<PrivateKeyT>: EphemeralKey<PrivateKeyT> {
        override val publicKey: CryptoPublicKey.Rsa
        override fun signer(configure: DSLConfigureFn<EphemeralSignerConfiguration>): Signer.RSA
    }
    companion object {
        operator fun invoke(configure: DSLConfigureFn<EphemeralSigningKeyConfiguration> = null) =
            makeEphemeralKey(DSL.resolve(::EphemeralSigningKeyConfiguration, configure))
    }
}

internal sealed class EphemeralKeyBase <PrivateKeyT>
    (final override val privateKey: PrivateKeyT): EphemeralKey<PrivateKeyT> {

    class EC<PrivateKeyT, SignerT: Signer.ECDSA>(
        private val signerFactory: (EphemeralSignerConfiguration, PrivateKeyT, CryptoPublicKey.EC, SignatureAlgorithm.ECDSA)->SignerT,
        privateKey: PrivateKeyT, override val publicKey: CryptoPublicKey.EC,
        val digests: Set<Digest?>) : EphemeralKeyBase<PrivateKeyT>(privateKey), EphemeralKey.EC<PrivateKeyT> {

        override fun signer(configure: DSLConfigureFn<EphemeralSignerConfiguration>): SignerT {
            val config = DSL.resolve(::EphemeralSignerConfiguration, configure)
            val alg = config.ec.v
            val digest = when (alg.digestSpecified) {
                true -> {
                    require (digests.contains(alg.digest))
                    { "Digest ${alg.digest} unsupported (supported: ${digests.joinToString(",")}" }
                    alg.digest
                }
                false -> when {
                    digests.contains(Digest.SHA256) -> Digest.SHA256
                    digests.contains(Digest.SHA384) -> Digest.SHA384
                    digests.contains(Digest.SHA512) -> Digest.SHA512
                    else -> digests.first()
                }
            }
            @OptIn(HazardousMaterials::class)
            return signerFactory(config, privateKey, publicKey, SignatureAlgorithm.ECDSA(digest, publicKey.curve))
        }
    }

    class RSA<PrivateKeyT, SignerT: Signer.RSA>(
        private val signerFactory: (EphemeralSignerConfiguration, PrivateKeyT, CryptoPublicKey.Rsa, SignatureAlgorithm.RSA)->SignerT,
        privateKey: PrivateKeyT, override val publicKey: CryptoPublicKey.Rsa,
        val digests: Set<Digest>, val paddings: Set<RSAPadding>) : EphemeralKeyBase<PrivateKeyT>(privateKey), EphemeralKey.RSA<PrivateKeyT> {

        override fun signer(configure: DSLConfigureFn<EphemeralSignerConfiguration>): SignerT {
            val config = DSL.resolve(::EphemeralSignerConfiguration, configure)
            val alg = config.rsa.v
            val digest = when (alg.digestSpecified) {
                true -> {
                    require (digests.contains(alg.digest))
                    { "Digest ${alg.digest} unsupported (supported: ${digests.joinToString(", ")}" }
                    alg.digest
                }
                false -> when {
                    digests.contains(Digest.SHA256) -> Digest.SHA256
                    digests.contains(Digest.SHA384) -> Digest.SHA384
                    digests.contains(Digest.SHA512) -> Digest.SHA512
                    else -> digests.first()
                }
            }
            val padding = when (alg.paddingSpecified) {
                true -> {
                    require (paddings.contains(alg.padding))
                    { "Padding ${alg.padding} unsupported (supported: ${paddings.joinToString(", ")}" }
                    alg.padding
                }
                false -> when {
                    paddings.contains(RSAPadding.PSS) -> RSAPadding.PSS
                    paddings.contains(RSAPadding.PKCS1) -> RSAPadding.PKCS1
                    else -> paddings.first()
                }
            }
            @OptIn(HazardousMaterials::class)
            return signerFactory(config, privateKey, publicKey, SignatureAlgorithm.RSA(digest, padding))
        }
    }
}
