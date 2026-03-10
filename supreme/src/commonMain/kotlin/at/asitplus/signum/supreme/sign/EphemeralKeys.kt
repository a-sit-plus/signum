package at.asitplus.signum.supreme.sign

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.Pkcs1RsaSignaturePadding
import at.asitplus.signum.indispensable.PssRsaSignaturePadding
import at.asitplus.signum.indispensable.PrivateKey
import at.asitplus.signum.indispensable.PublicKey
import at.asitplus.signum.indispensable.RsaSignaturePadding
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.EcdsaSignatureAlgorithm
import at.asitplus.signum.indispensable.RsaSignatureAlgorithm
import at.asitplus.signum.indispensable.nativeDigest
import at.asitplus.signum.indispensable.SecretExposure
import at.asitplus.signum.supreme.dsl.DSL
import at.asitplus.signum.supreme.dsl.DSLConfigureFn
import at.asitplus.signum.supreme.os.SignerConfiguration


internal expect fun makeEphemeralKey(configuration: EphemeralSigningKeyConfiguration) : EphemeralKey
internal expect fun makePrivateKeySigner(key: PrivateKey.EC.WithPublicKey, algorithm: EcdsaSignatureAlgorithm) : Signer.ECDSA
internal expect fun makePrivateKeySigner(key: PrivateKey.RSA, algorithm: RsaSignatureAlgorithm) : Signer.RSA

open class EphemeralSigningKeyConfigurationBase internal constructor(): SigningKeyConfiguration() {
    class ECConfiguration internal constructor(): SigningKeyConfiguration.ECConfiguration() {
        init { digests = (Digest.entries.asSequence() + sequenceOf<Digest?>(null)).toSet() }
    }
    override val ec = _algSpecific.option(::ECConfiguration)
    class RSAConfiguration internal constructor(): SigningKeyConfiguration.RSAConfiguration() {
        init { digests = Digest.entries.toSet(); paddings = RsaSignaturePadding.entries.toSet() }
    }
    override val rsa = _algSpecific.option(::RSAConfiguration)
}

@Suppress("NOTHING_TO_INLINE")
expect class EphemeralSigningKeyConfiguration internal constructor(): EphemeralSigningKeyConfigurationBase

typealias EphemeralSignerConfigurationBase = SignerConfiguration
@Suppress("NOTHING_TO_INLINE")
expect class EphemeralSignerConfiguration internal constructor(): SignerConfiguration

/**
 * An ephemeral keypair, not stored in any kind of persistent storage.
 * Can be either [EC] or [RSA]. Has a [PublicKey], and you can obtain a [Signer] from it.
 *
 * To generate a key, use
 * ```
 * EphemeralKey {
 *  /* optional configuration */
 * }
 * ```
 */
sealed interface EphemeralKey {
    val publicKey: PublicKey

    @SecretExposure
    fun exportPrivateKey(): KmmResult<PrivateKey.WithPublicKey<*>>

    /** Create a signer that signs using this [EphemeralKey].
     * @see EphemeralSignerConfiguration */
    fun signer(configure: DSLConfigureFn<EphemeralSignerConfiguration> = null): KmmResult<Signer>

    /** An [EphemeralKey] suitable for ECDSA operations. */
    interface EC: EphemeralKey {
        override val publicKey: PublicKey.EC
        override fun signer(configure: DSLConfigureFn<EphemeralSignerConfiguration>): KmmResult<Signer.ECDSA>

        @SecretExposure
        override fun exportPrivateKey(): KmmResult<PrivateKey.EC.WithPublicKey>
    }
    /** An [EphemeralKey] suitable for RSA operations. */
    interface RSA: EphemeralKey {
        override val publicKey: PublicKey.RSA
        override fun signer(configure: DSLConfigureFn<EphemeralSignerConfiguration>): KmmResult<Signer.RSA>

        @SecretExposure
        override fun exportPrivateKey(): KmmResult<PrivateKey.RSA>
    }
    companion object {
        operator fun invoke(configure: DSLConfigureFn<EphemeralSigningKeyConfiguration> = null) =
            catching { makeEphemeralKey(DSL.resolve(::EphemeralSigningKeyConfiguration, configure)) }
    }
}

internal sealed class EphemeralKeyBase <PrivateKeyT>
    (internal val privateKey: PrivateKeyT): EphemeralKey {

    abstract class EC<PrivateKeyT, SignerT: Signer.ECDSA>(
        private val signerFactory: (EphemeralSignerConfiguration, PrivateKeyT, PublicKey.EC, EcdsaSignatureAlgorithm)->SignerT,
        privateKey: PrivateKeyT, override val publicKey: PublicKey.EC,
        val digests: Set<Digest?>) : EphemeralKeyBase<PrivateKeyT>(privateKey), EphemeralKey.EC {

        override fun signer(configure: DSLConfigureFn<EphemeralSignerConfiguration>): KmmResult<SignerT> = catching {
            val config = DSL.resolve(::EphemeralSignerConfiguration, configure)
            val alg = config.ec.v
            val digest = when (alg.digestSpecified) {
                true -> {
                    require (digests.contains(alg.digest))
                    { "Digest ${alg.digest} unsupported (supported: ${digests.joinToString(",")}" }
                    alg.digest
                }
                false ->
                    sequenceOf(publicKey.curve.nativeDigest, Digest.SHA256, Digest.SHA384, Digest.SHA512)
                        .firstOrNull(digests::contains) ?: digests.first()
            }
            return@catching signerFactory(config, privateKey, publicKey, SignatureAlgorithm.ECDSA(digest, publicKey.curve))
        }
    }

    abstract class RSA<PrivateKeyT, SignerT: Signer.RSA>(
        private val signerFactory: (EphemeralSignerConfiguration, PrivateKeyT, PublicKey.RSA, RsaSignatureAlgorithm)->SignerT,
        privateKey: PrivateKeyT, override val publicKey: PublicKey.RSA,
        val digests: Set<Digest>, val paddings: Set<RsaSignaturePadding>) : EphemeralKeyBase<PrivateKeyT>(privateKey), EphemeralKey.RSA {

        override fun signer(configure: DSLConfigureFn<EphemeralSignerConfiguration>): KmmResult<SignerT> = catching {
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
                    paddings.contains(PssRsaSignaturePadding) -> PssRsaSignaturePadding
                    paddings.contains(Pkcs1RsaSignaturePadding) -> Pkcs1RsaSignaturePadding
                    else -> paddings.first()
                }
            }
            return@catching signerFactory(config, privateKey, publicKey, SignatureAlgorithm.RSA(digest, padding))
        }
    }
}
