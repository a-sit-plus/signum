package at.asitplus.signum.supreme.sign

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoPrivateKey
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.nativeDigest
import at.asitplus.signum.indispensable.SecretExposure
import at.asitplus.signum.supreme.dsl.DSL
import at.asitplus.signum.supreme.dsl.DSLConfigureFn
import at.asitplus.signum.supreme.os.SignerConfiguration


internal expect fun makeEphemeralKey(configuration: EphemeralSigningKeyConfiguration) : EphemeralKey
internal expect fun makePrivateKeySigner(key: CryptoPrivateKey.EC.WithPublicKey, algorithm: SignatureAlgorithm.ECDSA) : Signer.ECDSA
internal expect fun makePrivateKeySigner(key: CryptoPrivateKey.RSA, algorithm: SignatureAlgorithm.RSA) : Signer.RSA

open class EphemeralSigningKeyConfigurationBase internal constructor(): SigningKeyConfiguration() {
    class ECConfiguration internal constructor(): SigningKeyConfiguration.ECConfiguration() {
        init { digests = (Digest.entries.asSequence() + sequenceOf<Digest?>(null)).toSet() }
    }
    override val ec = _algSpecific.option(::ECConfiguration)
    class RSAConfiguration internal constructor(): SigningKeyConfiguration.RSAConfiguration() {
        init {  parameters = SignatureAlgorithm.RSA.Parameters.entries}
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
 * Can be either [EC] or [RSA]. Has a [CryptoPublicKey], and you can obtain a [Signer] from it.
 *
 * To generate a key, use
 * ```
 * EphemeralKey {
 *  /* optional configuration */
 * }
 * ```
 */
sealed interface EphemeralKey {
    val publicKey: CryptoPublicKey

    @SecretExposure
    fun exportPrivateKey(): KmmResult<CryptoPrivateKey.WithPublicKey<*>>

    /** Create a signer that signs using this [EphemeralKey].
     * @see EphemeralSignerConfiguration */
    fun signer(configure: DSLConfigureFn<EphemeralSignerConfiguration> = null): KmmResult<Signer>

    /** An [EphemeralKey] suitable for ECDSA operations. */
    interface EC: EphemeralKey {
        override val publicKey: CryptoPublicKey.EC
        override fun signer(configure: DSLConfigureFn<EphemeralSignerConfiguration>): KmmResult<Signer.ECDSA>

        @SecretExposure
        override fun exportPrivateKey(): KmmResult<CryptoPrivateKey.EC.WithPublicKey>
    }
    /** An [EphemeralKey] suitable for RSA operations. */
    interface RSA: EphemeralKey {
        override val publicKey: CryptoPublicKey.RSA
        override fun signer(configure: DSLConfigureFn<EphemeralSignerConfiguration>): KmmResult<Signer.RSA>

        @SecretExposure
        override fun exportPrivateKey(): KmmResult<CryptoPrivateKey.RSA>
    }
    companion object {
        operator fun invoke(configure: DSLConfigureFn<EphemeralSigningKeyConfiguration> = null) =
            catching { makeEphemeralKey(DSL.resolve(::EphemeralSigningKeyConfiguration, configure)) }
    }
}

internal sealed class EphemeralKeyBase <PrivateKeyT>
    (internal val privateKey: PrivateKeyT): EphemeralKey {

    abstract class EC<PrivateKeyT, SignerT: Signer.ECDSA>(
        private val signerFactory: (EphemeralSignerConfiguration, PrivateKeyT, CryptoPublicKey.EC, SignatureAlgorithm.ECDSA)->SignerT,
        privateKey: PrivateKeyT, override val publicKey: CryptoPublicKey.EC,
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
        private val signerFactory: (EphemeralSignerConfiguration, PrivateKeyT, CryptoPublicKey.RSA, SignatureAlgorithm.RSA)->SignerT,
        privateKey: PrivateKeyT, override val publicKey: CryptoPublicKey.RSA,
        val parameters: Set<SignatureAlgorithm.RSA.Parameters<*>>) : EphemeralKeyBase<PrivateKeyT>(privateKey), EphemeralKey.RSA {

        override fun signer(configure: DSLConfigureFn<EphemeralSignerConfiguration>): KmmResult<SignerT> = catching {
            val config = DSL.resolve(::EphemeralSignerConfiguration, configure)
            val alg = config.rsa.v
            val params = when (alg.parametersSpecified) {
                true -> {
                    require (parameters.contains(alg.parameters))
                    { "Parameters ${alg.parameters} unsupported (supported: ${parameters.joinToString(", ")}" }
                    alg.parameters
                }
                false -> when {
                    parameters.contains(SignatureAlgorithm.RSAwithSHA256andPSSPadding.parameters) ->SignatureAlgorithm.RSAwithSHA256andPSSPadding.parameters
                    parameters.contains(SignatureAlgorithm.RSAwithSHA384andPSSPadding.parameters) ->SignatureAlgorithm.RSAwithSHA384andPSSPadding.parameters
                    parameters.contains(SignatureAlgorithm.RSAwithSHA512andPSSPadding.parameters) ->SignatureAlgorithm.RSAwithSHA512andPSSPadding.parameters

                    parameters.contains(SignatureAlgorithm.RSAwithSHA256andPKCS1Padding.parameters) ->SignatureAlgorithm.RSAwithSHA256andPKCS1Padding.parameters
                    parameters.contains(SignatureAlgorithm.RSAwithSHA384andPKCS1Padding.parameters) ->SignatureAlgorithm.RSAwithSHA384andPKCS1Padding.parameters
                    parameters.contains(SignatureAlgorithm.RSAwithSHA512andPKCS1Padding.parameters) ->SignatureAlgorithm.RSAwithSHA512andPKCS1Padding.parameters

                    else -> parameters.first()
                }
            }

            return@catching signerFactory(config, privateKey, publicKey, SignatureAlgorithm.RSA(params))
        }
    }
}
