package at.asitplus.signum.supreme.sign

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.dsl.EphemeralSignerConfiguration
import at.asitplus.signum.dsl.EphemeralSigningKeyConfiguration
import at.asitplus.signum.indispensable.CryptoPrivateKey
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.integrity.SignatureAlgorithm
import at.asitplus.signum.indispensable.SecretExposure
import at.asitplus.signum.indispensable.nativeDigest
import at.asitplus.signum.indispensable.sign.RSAAlgorithm
import at.asitplus.signum.supreme.dsl.DSL
import at.asitplus.signum.supreme.dsl.DSLConfigureFn
import at.asitplus.signum.dsl.ec
import at.asitplus.signum.dsl.rsa
import at.asitplus.signum.indispensable.sign.EC
import at.asitplus.signum.indispensable.sign.ECDSAAlgorithm
import at.asitplus.signum.indispensable.sign.ECDSAPrivateKey
import at.asitplus.signum.indispensable.sign.ECDSAPublicKey
import at.asitplus.signum.indispensable.sign.RSAPrivateKey
import at.asitplus.signum.indispensable.sign.RSAPublicKey


internal expect suspend fun makeEphemeralKeyImpl(configuration: EphemeralSigningKeyConfiguration) : EphemeralKey?
internal expect fun makePrivateKeySigner(key: ECDSAPrivateKey.WithPublicKey, algorithm: ECDSAAlgorithm) : Signer.ECDSA
internal expect fun makePrivateKeySigner(key: RSAPrivateKey, algorithm: RSAAlgorithm) : Signer.RSA

/**
 * An ephemeral keypair, not stored in any kind of persistent storage.
 * Has a [CryptoPublicKey], and you can obtain a [Signer] from it.
 *
 * To generate a key, use
 * ```
 * EphemeralKey {
 *  /* optional configuration */
 * }
 * ```
 */
interface EphemeralKey {
    val publicKey: CryptoPublicKey

    @SecretExposure
    suspend fun exportPrivateKey(): KmmResult<CryptoPrivateKey.WithPublicKey<*>>

    /** Create a signer that signs using this [EphemeralKey].
     * @see EphemeralSignerConfiguration */
    fun signer(configure: DSLConfigureFn<EphemeralSignerConfiguration> = null): KmmResult<Signer>

    companion object {
        suspend operator fun invoke(configure: DSLConfigureFn<EphemeralSigningKeyConfiguration> = null) =
            catching {
                ServiceLoader.load<EphemeralKeysProvider>().get(
                    DSL.resolve(::EphemeralSigningKeyConfiguration, configure))
                    { makeEphemeralKey(it) }
            }
    }
}

// @Service
interface EphemeralKeysProvider {
    suspend fun makeEphemeralKey(configuration: EphemeralSigningKeyConfiguration): EphemeralKey?
}

object SupremeEphemeralKeysProvider : EphemeralKeysProvider {
    override suspend fun makeEphemeralKey(configuration: EphemeralSigningKeyConfiguration) =
        makeEphemeralKeyImpl(configuration)
}

/** An [EphemeralKey] suitable for ECDSA operations. */
interface ECDSAEphemeralKey: EphemeralKey {
    override val publicKey: ECDSAPublicKey
    override fun signer(configure: DSLConfigureFn<EphemeralSignerConfiguration>): KmmResult<Signer.ECDSA>

    @SecretExposure
    override suspend fun exportPrivateKey(): KmmResult<EC.WithPublicKey>
}
/** An [EphemeralKey] suitable for RSA operations. */
interface RSAEphemeralKey: EphemeralKey {
    override val publicKey: RSAPublicKey
    override fun signer(configure: DSLConfigureFn<EphemeralSignerConfiguration>): KmmResult<Signer.RSA>

    @SecretExposure
    override suspend fun exportPrivateKey(): KmmResult<RSAPrivateKey>
}

internal sealed class EphemeralKeyBase <PrivateKeyT>
    (internal val privateKey: PrivateKeyT): EphemeralKey {

    abstract class ECDSA<PrivateKeyT, SignerT: Signer.ECDSA>(
        private val signerFactory: (EphemeralSignerConfiguration, PrivateKeyT, CryptoPublicKey.EC, SignatureAlgorithm.ECDSA)->SignerT,
        privateKey: PrivateKeyT, override val publicKey: CryptoPublicKey.EC,
        val digests: Set<Digest?>) : EphemeralKeyBase<PrivateKeyT>(privateKey), ECDSAEphemeralKey {

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
        val digests: Set<Digest>, val paddings: Set<RSAAlgorithm.Padding>) : EphemeralKeyBase<PrivateKeyT>(privateKey), RSAEphemeralKey {

        override fun signer(configure: DSLConfigureFn<EphemeralSignerConfiguration>): KmmResult<SignerT> = catching {
            val config = DSL.resolve(::EphemeralSignerConfiguration, configure)
            val alg = config.rsa.v
            val digest = when (alg.digestSpecified) {
                true -> {
                    require(digests.contains(alg.digest))
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
                    require(paddings.contains(alg.padding))
                    { "Padding ${alg.padding} unsupported (supported: ${paddings.joinToString(", ")}" }
                    alg.padding
                }

                false -> when {
                    paddings.firstOrNull { it == RSAAlgorithm.Padding.PSS } != null -> RSAAlgorithm.Padding.PSS
                    paddings.contains(RSAAlgorithm.Padding.PKCS1) -> RSAAlgorithm.Padding.PKCS1
                    else -> paddings.first()
                }
            }
            return@catching signerFactory(config, privateKey, publicKey, SignatureAlgorithm.RSA(padding, digest))
        }
    }
}
