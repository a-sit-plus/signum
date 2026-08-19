package at.asitplus.signum.supreme.sign

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.dsl.EphemeralSigningKeyConfiguration
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.integrity.SignatureAlgorithm
import at.asitplus.signum.indispensable.SecretExposure
import at.asitplus.signum.indispensable.integrity.SignatureInput
import at.asitplus.signum.indispensable.integrity.verifierFor
import at.asitplus.signum.indispensable.sign.EC
import at.asitplus.signum.indispensable.sign.ECDSAAlgorithm
import at.asitplus.signum.indispensable.sign.ECDSAPublicKey
import at.asitplus.signum.indispensable.sign.RSAPrivateKey
import at.asitplus.signum.indispensable.sign.RSAAlgorithm
import at.asitplus.signum.indispensable.sign.RSAPublicKey
import at.asitplus.signum.supreme.SignatureResult
import at.asitplus.signum.supreme.agree.UsableECDHPrivateValue
import at.asitplus.signum.supreme.dsl.DSLConfigureFn
import at.asitplus.signum.supreme.os.SigningProvider

/**
 * Shared interface of all objects that can sign data.
 * Signatures are created using the [signatureAlgorithm], and can be verified using [publicKey], potentially with a [verifierFor] this object.
 *
 * Signers for your platform can be accessed using your platform's [SigningProvider].
 *
 * Ephemeral signers can be obtained using
 * ```
 * Signer.Ephemeral {
 *   /* optional key configuration */
 * }
 * ```
 * This will generate a throwaway [EphemeralKey] and return a Signer for it.
 *
 * Any actual instantiation will have an [AlgTrait], which will be either [ECDSA] or [RSA].
 * Instantiations may also be [WithAlias], usually because they come from a [SigningProvider].
 * They may also be [Attestable].
 *
 * Some signers [mayRequireUserUnlock]. If needed, they will ask for user interaction when you try to [sign] data.
 * You can try to authenticate a signer ahead of time using [trySetupUninterruptedSigning]; but it might do nothing for some Signers.
 * There is never a guarantee that signing is uninterrupted if [mayRequireUserUnlock] is true.
 *
 */
interface Signer {
    val signatureAlgorithm: SignatureAlgorithm
    val publicKey: CryptoPublicKey

    /** Whether the signer may ask for user interaction when [sign] is called */
    val mayRequireUserUnlock: Boolean get() = true

    @SecretExposure
    suspend fun exportPrivateKey(): KmmResult<CryptoPrivateKey.WithPublicKey<*>>

    /** Any [Signer] instantiation must be [ECDSA] or [RSA] */
    sealed interface AlgTrait : Signer

    /** A [Signer] that signs using ECDSA. */
    interface ECDSA : AlgTrait, UsableECDHPrivateValue {
        override val signatureAlgorithm: ECDSAAlgorithm
        override val publicKey: ECDSAPublicKey

        @SecretExposure
        override suspend fun exportPrivateKey(): KmmResult<EC.WithPublicKey>

        override val publicValue: KeyAgreementPublicValue.ECDH get() = publicKey
    }

    /**
     * A [Signer] that signs using RSA.
     *
     * On iOS, RSA-PSS supports only MGF1 using the signature digest, a salt length equal to the digest output length,
     * and trailer field `1`. Other RSA-PSS parameter combinations fail as unsupported by the platform.
     */
    interface RSA : AlgTrait {
        override val signatureAlgorithm: RSAAlgorithm
        override val publicKey: RSAPublicKey

        @SecretExposure
        override suspend fun exportPrivateKey(): KmmResult<at.asitplus.signum.indispensable.sign.RSAPrivateKey>
    }

    /** Some [Signer]s are retrieved from a signing provider, such as a key store, and have a string [alias]. */
    interface WithAlias : Signer {
        val alias: String
    }

    /** Some [Signer]s might have an attestation of some sort */
    interface Attestable<AttestationT : Attestation> : Signer {
        val attestation: AttestationT?
    }

    /** Try to ensure that the Signer is ready to immediately sign data, on a best-effort basis.
     * For example, if user authorization allows signing for a given timeframe, this will prompts for authorization now.
     *
     * If ahead-of-time authorization makes no sense for this [Signer], does nothing. */
    suspend fun trySetupUninterruptedSigning(): KmmResult<Unit> = KmmResult.success(Unit)

    /** Signs data. Might ask for user confirmation first if this [Signer] [mayRequireUserUnlock]. */
    suspend fun sign(data: SignatureInput): SignatureResult<*>
    suspend fun sign(data: ByteArray) = sign(SignatureInput(data))
    suspend fun sign(data: Sequence<ByteArray>) = sign(SignatureInput(data))

    companion object {
        suspend fun Ephemeral(configure: DSLConfigureFn<EphemeralSigningKeyConfiguration> = null) =
            EphemeralKey(configure).transform(EphemeralKey::signer)
    }
}

/**
 * Creates a signer for the specified [privateKey]. Fails if the key type does not match the signature algorithm type (EC/RSA)
 */
fun SignatureAlgorithm.signerFor(privateKey: CryptoPrivateKey.WithPublicKey<*>): KmmResult<Signer> =
    if ((this is ECDSAAlgorithm && privateKey is EC) ||
                (this is RSAAlgorithm && privateKey is RSAPrivateKey)) {
        when (this) {
            is ECDSAAlgorithm -> this.signerFor(privateKey as EC.WithPublicKey)
            is RSAAlgorithm -> this.signerFor(privateKey as RSAPrivateKey)
            else -> TODO("providerize")
        }
    } else {
        KmmResult.failure(IllegalArgumentException("Algorithm and Key mismatch: ${this::class.simpleName} + ${privateKey::class.simpleName}"))
    }

fun ECDSAAlgorithm.signerFor(privateKey: EC.WithPublicKey) =
    catching { makePrivateKeySigner(privateKey, this) }

/**
 * Creates an RSA signer for [privateKey].
 *
 * On iOS, RSA-PSS supports only MGF1 using the signature digest, a salt length equal to the digest output length,
 * and trailer field `1`.
 */
fun RSAAlgorithm.signerFor(privateKey: RSAPrivateKey) =
    catching { makePrivateKeySigner(privateKey, this) }

/**
 * Get a verifier for signatures generated by this [Signer].
 * @see SignatureAlgorithm.verifierFor
 */
fun Signer.makeVerifier(configure: ConfigurePlatformVerifier = null) =
    catching {
        // TODO: decide if we want to generalize this and make it work for everything (probably) and how to handle configuration for that
        // jh: probably add a configuration dsl for verifiers that is generic/extensible, akin to the extensible configuration dsl we already want
        SupremePlatformVerifierProvider.verifierFor(signatureAlgorithm, publicKey, configure)
            ?: throw UnsupportedCryptoException(signatureAlgorithm.toString())
    }

val Signer.ECDSA.curve get() = publicKey.curve
