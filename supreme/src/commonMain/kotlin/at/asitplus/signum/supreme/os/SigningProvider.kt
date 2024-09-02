package at.asitplus.signum.supreme.os

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.RSAPadding
import at.asitplus.signum.supreme.SignatureResult
import at.asitplus.signum.supreme.dsl.DISCOURAGED
import at.asitplus.signum.supreme.dsl.DSL
import at.asitplus.signum.supreme.dsl.DSLConfigureFn
import at.asitplus.signum.supreme.dsl.FeaturePreference
import at.asitplus.signum.supreme.dsl.REQUIRED
import at.asitplus.signum.supreme.sign.SignatureInput
import at.asitplus.signum.supreme.sign.Signer
import at.asitplus.signum.supreme.sign.SigningKeyConfiguration
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

open class SigningProviderSigningKeyConfigurationBase<SignerConfigurationT: SignerConfiguration> internal constructor() : SigningKeyConfiguration() {
    /** Configure the signer that will be returned from [createSigningKey][SigningProviderI.createSigningKey] */
    open val signer = integratedReceiver<SignerConfigurationT>()
}
open class PlatformSigningKeyConfigurationBase<SignerConfigurationT: PlatformSignerConfigurationBase> internal constructor(): SigningProviderSigningKeyConfigurationBase<SignerConfigurationT>() {
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

    /** Require that this key is stored in some kind of hardware-backed storage, such as Android Keymaster or Apple Secure Enclave. */
    open val hardware = childOrNull(::SecureHardwareConfiguration)
}

open class ECSignerConfiguration internal constructor(): DSL.Data() {
    /**
     * Explicitly specify the digest to sign over.
     * Omit to default to the only supported digest.
     *
     * If the key stored in hardware supports multiple digests, you need to explicitly specify the digest to use.
     * (By default, hardware keys are configured to only support a single digest.)
     *
     * @see SigningKeyConfiguration.ECConfiguration.digests
     */
    var digest: Digest? = null; set(v) { digestSpecified = true; field = v }
    internal var digestSpecified = false
}
open class RSASignerConfiguration internal constructor(): DSL.Data() {
    /**
     * Explicitly specify the digest to sign over.
     * Omit to default to a reasonable default choice.
     *
     * If a key stored in hardware supports multiple digests, you need to explicitly specify the digest to use.
     * (By default, hardware keys are configured to only support a single digest.)
     *
     * @see SigningKeyConfiguration.RSAConfiguration.digests
     */
    lateinit var digest: Digest
    internal val digestSpecified get() = this::digest.isInitialized

    /**
     * Explicitly specify the padding to use.
     * Omit to default to the only supported padding.
     *
     * If the key stored in hardware supports multiple padding modes, you need to explicitly specify the digest to use.
     * (By default, hardware keys are configured to only support a single digest.)
     *
     * @see SigningKeyConfiguration.RSAConfiguration.paddings
     */
    lateinit var padding: RSAPadding
    internal val paddingSpecified get() = this::padding.isInitialized


}
open class SignerConfiguration internal constructor(): DSL.Data() {
    /** Algorithm-specific configuration for a returned ECDSA signer. Ignored for RSA keys. */
    open val ec = childOrDefault(::ECSignerConfiguration)
    /** Algorithm-specific configuration for a returned RSA signer. Ignored for ECDSA keys. */
    open val rsa = childOrDefault(::RSASignerConfiguration)
}

open class UnlockPromptConfiguration: DSL.Data() {

    internal val _message = Stackable<String>()
    /** The prompt message to show to the user when asking for unlock */
    var message by _message

    internal val _cancelText = Stackable<String>()
    /** The message to show on the cancellation button */
    var cancelText by _cancelText

    companion object {
        const val defaultMessage = "Please authorize cryptographic signature"
        const val defaultCancelText = "Cancel"
    }
}
open class PlatformSignerConfigurationBase internal constructor(): SignerConfiguration() {
    /** Configure the authorization prompt that will be shown to the user. */
    open val unlockPrompt = childOrDefault(::UnlockPromptConfiguration)
}

open class PlatformSigningProviderSignerSigningConfigurationBase internal constructor(): DSL.Data() {
    open val unlockPrompt = childOrDefault(::UnlockPromptConfiguration)
}

interface PlatformSigningProviderSigner<SigningConfiguration: PlatformSigningProviderSignerSigningConfigurationBase>
    : Signer.WithAlias {

    suspend fun trySetupUninterruptedSigning(configure: DSLConfigureFn<SigningConfiguration> = null) : KmmResult<Unit> = KmmResult.success(Unit)
    override suspend fun trySetupUninterruptedSigning() = trySetupUninterruptedSigning(null)

    suspend fun sign(data: SignatureInput, configure: DSLConfigureFn<SigningConfiguration> = null) : SignatureResult
    suspend fun sign(data: ByteArray, configure: DSLConfigureFn<SigningConfiguration> = null) =
        sign(SignatureInput(data), configure)
    suspend fun sign(data: Sequence<ByteArray>, configure: DSLConfigureFn<SigningConfiguration> = null) =
        sign(SignatureInput(data), configure)
    override suspend fun sign(data: SignatureInput) = sign(data, null)
    override suspend fun sign(data: ByteArray) = sign(SignatureInput(data), null)
    override suspend fun sign(data: Sequence<ByteArray>) = sign(SignatureInput(data), null)
}

open class PlatformSigningProviderConfigurationBase internal constructor(): DSL.Data()
internal expect fun getPlatformSigningProvider(configure: DSLConfigureFn<PlatformSigningProviderConfigurationBase>): PlatformSigningProvider

/** KT-71089 workaround
 * @see PlatformSigningProvider */
interface PlatformSigningProviderI<out SignerT: PlatformSigningProviderSigner<*>,
        out SignerConfigT: PlatformSignerConfigurationBase,
        out KeyConfigT: PlatformSigningKeyConfigurationBase<*>>
    : SigningProviderI<SignerT, SignerConfigT, KeyConfigT> {

    companion object {
        operator fun invoke(configure: DSLConfigureFn<PlatformSigningProviderConfigurationBase> = null) =
            catching { getPlatformSigningProvider(configure) }
    }
}

/** KT-71089 workaround
 * @see SigningProvider */
interface SigningProviderI<out SignerT: Signer.WithAlias,
        out SignerConfigT: DSL.Data,
        out KeyConfigT: PlatformSigningKeyConfigurationBase<*>> {
    suspend fun createSigningKey(alias: String, configure: DSLConfigureFn<KeyConfigT> = null): KmmResult<SignerT>
    suspend fun getSignerForKey(alias: String, configure: DSLConfigureFn<SignerConfigT> = null): KmmResult<SignerT>
    suspend fun deleteSigningKey(alias: String): KmmResult<Unit>

    companion object {
        fun Platform(configure: DSLConfigureFn<PlatformSigningProviderConfigurationBase> = null) =
            PlatformSigningProvider(configure)
    }
}
/**
 * An interface to some underlying persistent storage for private key material. Stored keys are identified by a unique string "alias" for each key.
 * You can [create signing keys][createSigningKey], [get signers for existing keys][getSignerForKey], or [delete signing keys][deleteSigningKey].
 *
 * To obtain a platform signing provider in platform-agnostic code, use `PlatformSigningProvider()`.
 * In platform-specific code, it is currently recommended to directly interface with your platform signing provider to get platform-specific functionality.
 * (Platform-specific return types from `PlatformSigningProvider()` are currently blocked by KT-71036.)
 *
 * Created keys can be configured using the [SigningKeyConfiguration] DSL.
 * Signers can be configured using the [SignerConfiguration] DSL.
 * When creating a key, the returned signer's configuration is embedded in the signing key configuration as `signer {}`.
 *
 * @see JKSProvider
 * @see AndroidKeyStoreProvider
 * @see IosKeychainProvider
 */
typealias PlatformSigningProvider = PlatformSigningProviderI<*,*,*>

/** @see PlatformSigningProvider */
typealias SigningProvider = SigningProviderI<*,*,*>
