package at.asitplus.signum.supreme.sign

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.RSAPadding
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.nativeDigest
import at.asitplus.signum.supreme.HazardousMaterials
import at.asitplus.signum.supreme.UnlockFailed
import at.asitplus.signum.supreme.dsl.DSL
import at.asitplus.signum.supreme.dsl.DSLConfigureFn
import at.asitplus.signum.supreme.os.Attestation
import at.asitplus.signum.supreme.os.SigningProvider
import com.ionspin.kotlin.bignum.integer.BigInteger

/** DSL for configuring a signing key.
 *
 * Defaults to an elliptic-curve key with a reasonable default configuration.
 *
 * @see ec
 * @see rsa
 */
open class SigningKeyConfiguration internal constructor(): DSL.Data() {
    sealed class AlgorithmSpecific: DSL.Data()

    internal val _algSpecific = subclassOf<AlgorithmSpecific>(default = ECConfiguration())
    /** Generates an elliptic-curve key. */
    open val ec = _algSpecific.option(::ECConfiguration)
    /** Generates an RSA key. */
    open val rsa = _algSpecific.option(::RSAConfiguration)

    open class ECConfiguration internal constructor() : AlgorithmSpecific() {
        /** The [ECCurve] on which to generate the key. Defaults to [P-256][ECCurve.SECP_256_R_1] */
        var curve: ECCurve = ECCurve.SECP_256_R_1

        private var _digests: Set<Digest?>? = null
        /** The digests supported by the key. If not specified, supports the curve's native digest only. */
        open var digests: Set<Digest?>
            get() = _digests ?: setOf(curve.nativeDigest)
            set(v) { _digests = v }
    }

    open class RSAConfiguration internal constructor(): AlgorithmSpecific() {
        companion object { val F0 = BigInteger(3); val F4 = BigInteger(65537) }
        /** The digests supported by the key. If not specified, defaults to [SHA256][Digest.SHA256]. */
        open var digests: Set<Digest> = setOf(Digest.SHA256)
        /** The paddings supported by the key. If not specified, defaults to [RSA-PSS][RSAPadding.PSS]. */
        open var paddings: Set<RSAPadding> = setOf(RSAPadding.PSS)
        /** The bit size of the generated key. If not specified, defaults to 3072 bits. */
        var bits: Int = 3072
        /** The public exponent to use. Defaults to F4.
         * This is treated as advisory, and may be ignored by some platforms. */
        var publicExponent: BigInteger = F4
    }
}

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
 * Any actual instantiation will have a [AlgTrait], which will be either [ECDSA] or [RSA].
 * Instantiations may also be [WithAlias], usually because they come from a [SigningProvider].
 * They may also be [Attestable].
 *
 * Some signers [mayRequireUserUnlock]. If needed, they will ask for user interaction when you try to [sign] data.
 * Of these signers, some are also [Signer.TemporarilyUnlockable].
 * These signers can be used to sign multiple times in rapid succession with only a single user interaction.
 *
 */
interface Signer {
    val signatureAlgorithm: SignatureAlgorithm
    val publicKey: CryptoPublicKey
    /** Whether the signer may ask for user interaction when [sign] is called */
    val mayRequireUserUnlock: Boolean

    /** Any [Signer] instantiation must be [ECDSA] or [RSA] */
    sealed interface AlgTrait : Signer

    /** A [Signer] that signs using ECDSA. */
    interface ECDSA : Signer.AlgTrait {
        override val signatureAlgorithm: SignatureAlgorithm.ECDSA
        override val publicKey: CryptoPublicKey.EC
    }

    /** A [Signer] that signs using RSA. */
    interface RSA : Signer.AlgTrait {
        override val signatureAlgorithm: SignatureAlgorithm.RSA
        override val publicKey: CryptoPublicKey.Rsa
    }

    /** Some [Signer]s are retrieved from a signing provider, such as a key store, and have a string [alias]. */
    interface WithAlias: Signer {
        val alias: String
    }

    /** Some [Signer]s might have an attestation of some sort */
    interface Attestable<AttestationT: Attestation>: Signer {
        val attestation: AttestationT?
    }

    /** Signs data. Might ask for user confirmation first if this [Signer] [mayRequireUserUnlock]. */
    suspend fun sign(data: SignatureInput): KmmResult<CryptoSignature>

    /**
     * A handle to a [TemporarilyUnlockable] signer that is temporarily unlocked.
     * The handle is only guaranteed to be valid within the scope of the [withUnlock] block.
     */
    @OptIn(ExperimentalStdlibApi::class)
    interface UnlockedHandle: AutoCloseable, Signer {
        override val mayRequireUserUnlock: Boolean get() = false
    }

    /**
     * A signer that can be temporarily unlocked.
     * Once unlocked, multiple signing operations can be performed with a single unlock.
     *
     * @see withUnlock
     */
    abstract class TemporarilyUnlockable<Handle: UnlockedHandle> : Signer {
        override val mayRequireUserUnlock: Boolean get() = true

        /** Obtains a raw unlock handle. This is public because [withUnlock] needs to be inline.
         * If you use it directly, closing the returned handle is your responsibility! */
        @HazardousMaterials
        abstract suspend fun unlock(): KmmResult<Handle>

        /**
         * Unlocks the signer, then executes the block with the [UnlockedHandle] as its receiver.
         *
         * The handle's validity is only guaranteed in the block scope.
         */
        @OptIn(ExperimentalStdlibApi::class, HazardousMaterials::class)
        suspend inline fun <reified T> withUnlock(fn: Handle.()->T): KmmResult<T> =
            unlock().mapCatching { it.use(fn) }

        @OptIn(ExperimentalStdlibApi::class, HazardousMaterials::class)
        final override suspend fun sign(data: SignatureInput): KmmResult<CryptoSignature> =
            unlock().transform { h -> h.use { it.sign(data) } }
    }

    companion object {
        fun Ephemeral(configure: DSLConfigureFn<EphemeralSigningKeyConfiguration> = null) =
            EphemeralKey(configure).transform(EphemeralKey::signer)
    }
}

/**
 * Get a verifier for signatures generated by this [Signer].
 * @see SignatureAlgorithm.verifierFor
 */
fun Signer.makeVerifier(configure: ConfigurePlatformVerifier = null) = signatureAlgorithm.verifierFor(publicKey, configure)

/**
 * Gets a platform verifier for signatures generated by this [Signer].
 * @see SignatureAlgorithm.platformVerifierFor
 */
fun Signer.makePlatformVerifier(configure: ConfigurePlatformVerifier = null) = signatureAlgorithm.platformVerifierFor(publicKey, configure)

val Signer.ECDSA.curve get() = publicKey.curve

/**
 * Try to batch sign with this [Signer].
 * Might fail for locked [Signer]s that are not [Signer.TemporarilyUnlockable].
 */
suspend inline fun <reified T> Signer.withUnlock(fn: Signer.()->T) =
    when (this.mayRequireUserUnlock) {
        true ->
            if (this is Signer.TemporarilyUnlockable<*>)
                this.withUnlock(fn)
            else
                KmmResult.failure(UnlockFailed("This signer needs authentication for every use"))
        false -> catching { fn(this) }
    }

/** Sign the data. */
suspend inline fun Signer.sign(data: ByteArray) = sign(SignatureInput(data))
