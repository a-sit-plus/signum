package at.asitplus.signum.supreme.sign

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.supreme.UnlockFailed
import at.asitplus.signum.supreme.os.Attestation

interface Signer {
    val signatureAlgorithm: SignatureAlgorithm
    val publicKey: CryptoPublicKey

    /** Any [Signer] instantiation must be [ECDSA] or [RSA] */
    sealed interface AlgTrait : Signer

    /** ECDSA signer */
    interface ECDSA : Signer.AlgTrait {
        override val signatureAlgorithm: SignatureAlgorithm.ECDSA
        override val publicKey: CryptoPublicKey.EC
    }

    /** RSA signer */
    interface RSA : Signer.AlgTrait {
        override val signatureAlgorithm: SignatureAlgorithm.RSA
        override val publicKey: CryptoPublicKey.Rsa
    }

    /** Some [Signer]s might have an attestation of some sort */
    interface Attestable<AttestationT: Attestation>: Signer {
        val attestation: AttestationT?
    }

    /** Any [Signer] is either [Unlocked] or [Unlockable] */
    sealed interface UnlockTrait: Signer

    /**
     * This signer either does not require unlock, or is already unlocked.
     * Signing operations immediately complete.
     */
    interface Unlocked: Signer.UnlockTrait {
        /**
         * Signs the input.
         * This operation never suspends.
         */
        fun sign(data: SignatureInput): KmmResult<CryptoSignature>
    }

    /**
     * This signer might require unlock.
     * Signing operations might suspend while the user is prompted for confirmation.
     *
     * Some signers of this type are [TemporarilyUnlockable].
     */
    interface Unlockable: Signer.UnlockTrait {
        /**
         * Unlocks this signer, and signs the message once unlocked.
         * This operation might suspend and request unlock from the user.
         */
        suspend fun sign(data: SignatureInput): KmmResult<CryptoSignature>
    }

    /**
     * A handle to a [TemporarilyUnlockable] signer that is temporarily unlocked.
     * The handle is only guaranteed to be valid within the scope of the block.
     */
    @OptIn(ExperimentalStdlibApi::class)
    interface UnlockedHandle: AutoCloseable, Signer.Unlocked

    /**
     * An [Unlockable] signer that can be temporarily unlocked.
     * Once unlocked, multiple signing operations can be performed with a single unlock.
     */
    abstract class TemporarilyUnlockable<Handle: UnlockedHandle> : Signer.Unlockable {
        protected abstract suspend fun unlock(): KmmResult<Handle>

        /**
         * Unlocks the signer, then executes the block with the [UnlockedHandle] as its receiver.
         *
         * The handle's validity is only guaranteed in the block scope.
         */
        @OptIn(ExperimentalStdlibApi::class)
        suspend fun <T> withUnlock(fn: Handle.()->T): KmmResult<T> =
            unlock().mapCatching { it.use(fn) }

        final override suspend fun sign(data: SignatureInput): KmmResult<CryptoSignature> =
            withUnlock { sign(data).getOrThrow() }
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

/** Sign without caring what type of signer this is. Might suspend. */
suspend fun Signer.sign(data: SignatureInput): KmmResult<CryptoSignature> {
    this as Signer.UnlockTrait
    return when (this) {
        is Signer.Unlocked -> sign(data)
        is Signer.Unlockable -> sign(data)
    }
}

/**
 * Try to batch sign with this signer.
 * Might fail for unlockable signers that cannot be temporarily unlocked.
 */
suspend fun <T> Signer.withUnlock(fn: Signer.Unlocked.()->T) = catching {
    this as Signer.UnlockTrait
    when (this) {
        is Signer.Unlocked -> this.fn()
        is Signer.TemporarilyUnlockable<*> -> this.withUnlock(fn).getOrThrow()
        is Signer.Unlockable -> throw UnlockFailed("This signer needs authentication for every use")
    }
}

suspend inline fun Signer.sign(data: ByteArray) = sign(SignatureInput(data))
inline fun <T: Signer.Unlocked> T.sign(data: ByteArray) = sign(SignatureInput(data))
suspend inline fun <T: Signer.Unlockable> T.sign(data: ByteArray) = sign(SignatureInput(data))
