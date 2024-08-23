package at.asitplus.signum.supreme.os

import at.asitplus.KmmResult
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.RSAPadding
import at.asitplus.signum.indispensable.nativeDigest
import at.asitplus.signum.supreme.dsl.DISCOURAGED
import at.asitplus.signum.supreme.dsl.DSL
import at.asitplus.signum.supreme.dsl.DSLConfigureFn
import at.asitplus.signum.supreme.dsl.FeaturePreference
import at.asitplus.signum.supreme.dsl.REQUIRED
import at.asitplus.signum.supreme.sign.Signer
import com.ionspin.kotlin.bignum.integer.BigInteger
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

open class SigningKeyConfiguration internal constructor(): DSL.Data() {
    sealed class AlgorithmSpecific: DSL.Data()
    internal val _algSpecific = subclassOf<AlgorithmSpecific>(default = ECConfiguration())
    open class ECConfiguration internal constructor() : AlgorithmSpecific() {
        var curve: ECCurve = ECCurve.SECP_256_R_1

        private var _digests: Set<Digest?>? = null
        /** Specify the digests supported by the key. If not specified, supports the curve's native digest only. */
        var digests: Set<Digest?>
            get() = _digests ?: setOf(curve.nativeDigest)
            set(v) { _digests = v }
    }
    open val ec = _algSpecific.option(::ECConfiguration)

    open class RSAConfiguration internal constructor(): AlgorithmSpecific() {
        companion object { val F0 = BigInteger(3); val F4 = BigInteger(65537)}
        var digests: Set<Digest> = setOf(Digest.SHA1, Digest.SHA256, Digest.SHA384, Digest.SHA512)
        var paddings: Set<RSAPadding> = setOf(RSAPadding.PSS)
        var bits: Int = 4096
        var publicExponent: BigInteger = F4
    }
    open val rsa = _algSpecific.option(::RSAConfiguration)
}

open class PlatformSigningKeyConfiguration<PlatformSignerConfiguration: SignerConfiguration> internal constructor(): SigningKeyConfiguration() {
    open class AttestationConfiguration internal constructor(): DSL.Data() {
        /** The server-provided attestation challenge */
        lateinit var challenge: ByteArray
        override fun validate() {
            require(this::challenge.isInitialized) { "Server-provided attestation challenge must be set" }
        }
    }

    open class ProtectionFactorConfiguration internal constructor(): DSL.Data() {
        /** Whether a biometric factor (fingerprint, facial recognition, ...) can authorize this key */
        var biometry = true
        /** Whether a device unlock code, PIN, etc. can authorize this key */
        var deviceLock = true

        override fun validate() {
            require(biometry || deviceLock) { "At least one authentication factor must be permissible" }
        }
    }

    open class ProtectionConfiguration internal constructor(): DSL.Data() {
        /** The timeout before this key will need to be unlocked again. */
        var timeout: Duration = 0.seconds
        /** Which authentication factors can authorize this key;
         * if multiple factors are specified, any one of them can authorize the key */
        val factors = childOrDefault(::ProtectionFactorConfiguration)
    }

    open class SecureHardwareConfiguration: DSL.Data() {
        /** Whether to use hardware-backed storage, such as Android Keymaster or Apple's Secure Enclave.
         * @see FeaturePreference */
        var backing: FeaturePreference = REQUIRED
        open val attestation = childOrNull(::AttestationConfiguration)
        open val protection = childOrNull(::ProtectionConfiguration)
        override fun validate() {
            super.validate()
            require((backing != DISCOURAGED) || (attestation.v == null))
            { "To obtain hardware attestation, enable secure hardware support (do not set backing = DISCOURAGED, use backing = PREFERRED or backing = REQUIRED instead)."}
        }
    }

    open val hardware = childOrNull(::SecureHardwareConfiguration)

    open val signer = integratedReceiver<PlatformSignerConfiguration>()

    // TODO: figure out a reasonable common interface for biometry requirements
}

open class ECSignerConfiguration internal constructor(): DSL.Data() {
    internal var digestSpecified = false
    /**
     * Explicitly specify the digest to sign over.
     * Omit to default to the only supported digest.
     *
     * If the key supports multiple digests, you need to explicitly specify the digest to use.
     */
    var digest: Digest? = null; set(v) { digestSpecified = true; field = v }
}
open class RSASignerConfiguration internal constructor(): DSL.Data() {
    internal var digestSpecified = false
    /**
     * Explicitly specify the digest to sign over.
     * Omit to default to the only supported digest.
     *
     * If the key supports multiple digests, you need to explicitly specify the digest to use.
     */
    var digest: Digest = Digest.SHA256; set(v) { digestSpecified = true; field = v }

    internal var paddingSpecified = false
    /**
     * Explicitly specify the padding to use.
     * Omit to default to the only supported padding.
     *
     * If the key supports multiple padding modes, you need to explicitly specify the digest to use.
     */
    var padding: RSAPadding = RSAPadding.PKCS1; set(v) { paddingSpecified = true; field = v }


}
open class SignerConfiguration internal constructor(): DSL.Data() {
    open class AuthnPrompt: DSL.Data() {
        /** The prompt message to show to the user when asking for unlock */
        var message: String = "Please authorize cryptographic signature"
        /** The message to show on the cancellation button */
        var cancelText: String = "Abort"
    }
    open val unlockPrompt = childOrDefault(::AuthnPrompt)

    open val ec = childOrDefault(::ECSignerConfiguration)
    open val rsa = childOrDefault(::RSASignerConfiguration)
}

interface SigningProviderI<out SignerT: Signer,
        out SignerConfigT: SignerConfiguration,
        out KeyConfigT: PlatformSigningKeyConfiguration<*>> {
    suspend fun createSigningKey(alias: String, configure: DSLConfigureFn<KeyConfigT> = null) : KmmResult<SignerT>
    suspend fun getSignerForKey(alias: String, configure: DSLConfigureFn<SignerConfigT> = null) : KmmResult<SignerT>
    suspend fun deleteSigningKey(alias: String)
}
typealias SigningProvider = SigningProviderI<*,*,*>
