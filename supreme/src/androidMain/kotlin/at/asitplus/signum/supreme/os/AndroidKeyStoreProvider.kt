package at.asitplus.signum.supreme.os

import android.annotation.SuppressLint
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import androidx.biometric.BiometricPrompt
import androidx.biometric.BiometricPrompt.AuthenticationResult
import androidx.biometric.BiometricPrompt.CryptoObject
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import androidx.fragment.app.FragmentActivity
import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.RSAPadding
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.getJCASignatureInstance
import at.asitplus.signum.indispensable.jcaName
import at.asitplus.signum.indispensable.parseFromJca
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.leaf
import at.asitplus.signum.supreme.AppLifecycleMonitor
import at.asitplus.signum.supreme.SignatureResult
import at.asitplus.signum.supreme.UnlockFailed
import at.asitplus.signum.supreme.UnsupportedCryptoException
import at.asitplus.signum.supreme.dsl.DISCOURAGED
import at.asitplus.signum.supreme.dsl.DSL
import at.asitplus.signum.supreme.dsl.DSLConfigureFn
import at.asitplus.signum.supreme.dsl.FeaturePreference
import at.asitplus.signum.supreme.dsl.PREFERRED
import at.asitplus.signum.supreme.dsl.REQUIRED
import at.asitplus.signum.supreme.sign.SignatureInput
import at.asitplus.signum.supreme.sign.SigningKeyConfiguration
import at.asitplus.signum.supreme.signCatching
import com.ionspin.kotlin.bignum.integer.base63.toJavaBigInteger
import at.asitplus.signum.supreme.sign.Signer as SignerI
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.RSAKeyGenParameterSpec
import java.time.Instant
import java.util.Date
import javax.security.auth.x500.X500Principal

internal sealed interface FragmentContext {
    @JvmInline value class OfActivity(val activity: FragmentActivity): FragmentContext
    @JvmInline value class OfFragment(val fragment: Fragment): FragmentContext
}


class AndroidKeymasterConfiguration internal constructor(): PlatformSigningKeyConfigurationBase.SecureHardwareConfiguration() {
    /** Whether a StrongBox TPM is required. */
    var strongBox: FeaturePreference = PREFERRED
}
class AndroidSigningKeyConfiguration internal constructor(): PlatformSigningKeyConfigurationBase<AndroidSignerConfiguration>() {
    override val hardware = childOrNull(::AndroidKeymasterConfiguration)
}

class AndroidUnlockPromptConfiguration internal constructor(): UnlockPromptConfiguration() {
    /** Explicitly specify the FragmentActivity to use for authentication prompts.
     * You will not need to set this in most cases; the default is the current activity. */
    lateinit var activity: FragmentActivity

    /** Explicitly set the Fragment to base authentication prompts on.
     * You will not need to set this in most cases; the default is the current activity.*/
    lateinit var fragment: Fragment

    internal val explicitContext: FragmentContext get() = when {
        this::fragment.isInitialized -> FragmentContext.OfFragment(fragment)
        else                         -> FragmentContext.OfActivity(activity)
    }
    internal val hasExplicitContext get() =
        (this::fragment.isInitialized || this::activity.isInitialized)

    internal val _subtitle = Stackable<String?>()
    /** @see [BiometricPrompt.PromptInfo.Builder.setSubtitle] */
    var subtitle by _subtitle

    internal val _description = Stackable<String?>()
    /** @see [BiometricPrompt.PromptInfo.Builder.setDescription] */
    var description by _description

    internal val _confirmationRequired = Stackable<Boolean?>()
    /** @see [BiometricPrompt.PromptInfo.Builder.setConfirmationRequired] */
    var confirmationRequired by _confirmationRequired

    internal val _allowedAuthenticators = Stackable<Int?>()
    /** @see [BiometricPrompt.PromptInfo.Builder.setAllowedAuthenticators] */
    var allowedAuthenticators by _allowedAuthenticators

    /** if the provided fingerprint could not be matched, but the user will be allowed to retry */
    var invalidBiometryCallback: (()->Unit)? = null
}

class AndroidSignerConfiguration: PlatformSignerConfigurationBase() {
    override val unlockPrompt = childOrDefault(::AndroidUnlockPromptConfiguration)
}

class AndroidSignerSigningConfiguration: PlatformSigningProviderSignerSigningConfigurationBase() {
    override val unlockPrompt = childOrDefault(::AndroidUnlockPromptConfiguration)
}

/**
 * Resolve [what] differently based on whether the [v]alue was [spec]ified.
 *
 * * [spec] = `true`: Check if [valid] contains [nameMap] applied to [v], return [v] if yes, throw otherwise
 * * [spec] = `false`: Check if [valid] contains exactly one element, if yes, return the [E] from [possible] for which [nameMap] returns that element, throw otherwise
 */
internal inline fun <reified E> resolveOption(what: String, valid: Array<String>, possible: Sequence<E>, spec: Boolean, v: E, crossinline nameMap: (E)->String): E =
    when (spec) {
        true -> {
            val vStr = nameMap(v)
            if (!valid.any { it.equals(vStr, ignoreCase=true) })
                throw IllegalArgumentException("Key does not support $what $v; supported: ${valid.joinToString(", ")}")
            v
        }
        false -> {
            if (valid.size != 1)
                throw IllegalArgumentException("Key supports multiple ${what}s (${valid.joinToString(", ")}). You need to specify $what in signer configuration.")
            val only = valid.first()
            possible.find {
                nameMap(it).equals(only, ignoreCase=true)
            } ?: throw UnsupportedCryptoException("Unsupported $what $only")
        }
    }

private fun attestationFor(chain: CertificateChain) =
    if (chain.size > 1) AndroidKeystoreAttestation(chain) else null

/**
 * A provider that manages keys in the [Android Key Store](https://developer.android.com/privacy-and-security/keystore).
 */
object AndroidKeyStoreProvider:
    PlatformSigningProviderI<AndroidKeystoreSigner, AndroidSignerConfiguration, AndroidSigningKeyConfiguration>
{

    private val ks: KeyStore get() =
        KeyStore.getInstance("AndroidKeyStore").apply { load(null, null) }

    @SuppressLint("WrongConstant")
    override suspend fun createSigningKey(
        alias: String,
        configure: DSLConfigureFn<AndroidSigningKeyConfiguration>
    ) = catching {
        if (ks.containsAlias(alias)) {
            throw NoSuchElementException("Key with alias $alias already exists")
        }
        val config = DSL.resolve(::AndroidSigningKeyConfiguration, configure)
        val spec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN
        ).apply {
            when(val algSpec = config._algSpecific.v) {
                is SigningKeyConfiguration.RSAConfiguration -> {
                    setAlgorithmParameterSpec(
                        RSAKeyGenParameterSpec(algSpec.bits, algSpec.publicExponent.toJavaBigInteger()))
                    setDigests(*algSpec.digests.map(Digest::jcaName).toTypedArray())
                    setSignaturePaddings(*algSpec.paddings.map {
                        when (it) {
                            RSAPadding.PKCS1 -> KeyProperties.SIGNATURE_PADDING_RSA_PKCS1
                            RSAPadding.PSS -> KeyProperties.SIGNATURE_PADDING_RSA_PSS
                        }
                    }.toTypedArray())
                }
                is SigningKeyConfiguration.ECConfiguration -> {
                    setAlgorithmParameterSpec(ECGenParameterSpec(algSpec.curve.jcaName))
                    setDigests(*algSpec.digests.map { it?.jcaName ?: KeyProperties.DIGEST_NONE }.toTypedArray())
                }
            }
            setCertificateNotBefore(Date.from(Instant.now()))
            setCertificateSubject(X500Principal("CN=$alias")) // TODO
            config.hardware.v?.let { hw ->
                setIsStrongBoxBacked(when (hw.strongBox) {
                    REQUIRED -> true
                    PREFERRED -> false // TODO
                    DISCOURAGED -> false
                })
                hw.attestation.v?.let {
                    setAttestationChallenge(it.challenge)
                }
                hw.protection.v?.let {
                    setUserAuthenticationRequired(true)
                    setUserAuthenticationParameters(it.timeout.inWholeSeconds.toInt(),
                        (if (it.factors.v.biometry) KeyProperties.AUTH_BIOMETRIC_STRONG else 0) or
                        (if (it.factors.v.deviceLock) KeyProperties.AUTH_DEVICE_CREDENTIAL else 0))
                }
            }
        }.build()
        KeyPairGenerator.getInstance(when(config._algSpecific.v) {
            is SigningKeyConfiguration.RSAConfiguration -> KeyProperties.KEY_ALGORITHM_RSA
            is SigningKeyConfiguration.ECConfiguration -> KeyProperties.KEY_ALGORITHM_EC
        }, "AndroidKeyStore").apply {
            initialize(spec)
        }.generateKeyPair()
        return@catching getSignerForKey(alias, config.signer.v).getOrThrow()
    }

    override suspend fun getSignerForKey(
        alias: String,
        configure: DSLConfigureFn<AndroidSignerConfiguration>
    ): KmmResult<AndroidKeystoreSigner> = catching {
        val config = DSL.resolve(::AndroidSignerConfiguration, configure)
        val (jcaPrivateKey, certificateChain) = ks.let {
            Pair(it.getKey(alias, null) as? PrivateKey
                ?: throw NoSuchElementException("No key for alias $alias exists"),
                it.getCertificateChain(alias).map { X509Certificate.decodeFromDer(it.encoded) })
        }

        val keyInfo = KeyFactory.getInstance(jcaPrivateKey.algorithm)
            .getKeySpec(jcaPrivateKey, KeyInfo::class.java)
        val algorithm = when (val publicKey = certificateChain.leaf.publicKey) {
            is CryptoPublicKey.EC -> {
                val ecConfig = config.ec.v
                val digest = resolveOption("digest", keyInfo.digests, Digest.entries.asSequence() + sequenceOf<Digest?>(null), ecConfig.digestSpecified, ecConfig.digest) { it?.jcaName ?: KeyProperties.DIGEST_NONE }
                SignatureAlgorithm.ECDSA(digest, publicKey.curve)
            }
            is CryptoPublicKey.Rsa -> {
                val rsaConfig = config.rsa.v
                val digest = resolveOption<Digest>("digest", keyInfo.digests, Digest.entries.asSequence(), rsaConfig.digestSpecified, rsaConfig.digest, Digest::jcaName)
                val padding = resolveOption<RSAPadding>("padding", keyInfo.signaturePaddings, RSAPadding.entries.asSequence(), rsaConfig.paddingSpecified, rsaConfig.padding) {
                    when (it) {
                        RSAPadding.PKCS1 -> KeyProperties.SIGNATURE_PADDING_RSA_PKCS1
                        RSAPadding.PSS -> KeyProperties.SIGNATURE_PADDING_RSA_PSS
                    }
                }
                SignatureAlgorithm.RSA(digest, padding)
            }
        }

        return@catching when (certificateChain.leaf.publicKey) {
            is CryptoPublicKey.EC ->
                AndroidKeystoreSigner.ECDSA(
                    jcaPrivateKey, alias, keyInfo, config, certificateChain,
                    algorithm as SignatureAlgorithm.ECDSA)
            is CryptoPublicKey.Rsa ->
                AndroidKeystoreSigner.RSA(
                    jcaPrivateKey, alias, keyInfo, config, certificateChain,
                    algorithm as SignatureAlgorithm.RSA)
        }
    }

    override suspend fun deleteSigningKey(alias: String) = catching {
        ks.deleteEntry(alias)
    }
}

sealed class AndroidKeystoreSigner private constructor(
    internal val jcaPrivateKey: PrivateKey,
    final override val alias: String,
    val keyInfo: KeyInfo,
    private val config: AndroidSignerConfiguration,
    certificateChain: CertificateChain
) : PlatformSigningProviderSigner<AndroidSignerSigningConfiguration>, SignerI.Attestable<AndroidKeystoreAttestation> {

    final override val mayRequireUserUnlock: Boolean get() = this.needsAuthentication

    final override val attestation = attestationFor(certificateChain)
    private sealed interface AuthResult {
        @JvmInline value class Success(val result: AuthenticationResult): AuthResult
        data class Error(val code: Int, val message: String): AuthResult
    }

    private suspend fun attemptBiometry(config: DSL.ConfigStack<AndroidUnlockPromptConfiguration>, forSpecificKey: CryptoObject?) {
        val channel = Channel<AuthResult>(capacity = Channel.RENDEZVOUS)
        val effectiveContext = config.getProperty(AndroidUnlockPromptConfiguration::explicitContext,
            checker = AndroidUnlockPromptConfiguration::hasExplicitContext, default = {
                (AppLifecycleMonitor.currentActivity as? FragmentActivity)?.let(FragmentContext::OfActivity)
                    ?: throw UnsupportedOperationException("The requested key with alias $alias requires unlock, but the current activity is not a FragmentActivity or could not be determined. " +
                    "Pass either { fragment = } or { activity = } inside authPrompt {}.")
            })
        val executor = when (effectiveContext) {
            is FragmentContext.OfActivity -> ContextCompat.getMainExecutor(effectiveContext.activity)
            is FragmentContext.OfFragment -> ContextCompat.getMainExecutor(effectiveContext.fragment.context)
        }
        executor.asCoroutineDispatcher().let(::CoroutineScope).launch {
            val promptInfo = BiometricPrompt.PromptInfo.Builder().apply {
                setTitle(config.getProperty(AndroidUnlockPromptConfiguration::_message,
                    default = UnlockPromptConfiguration.defaultMessage))
                setNegativeButtonText(config.getProperty(AndroidUnlockPromptConfiguration::_cancelText,
                    default = UnlockPromptConfiguration.defaultCancelText))
                config.getProperty(AndroidUnlockPromptConfiguration::_subtitle,null)?.let(this::setSubtitle)
                config.getProperty(AndroidUnlockPromptConfiguration::_description,null)?.let(this::setDescription)
                config.getProperty(AndroidUnlockPromptConfiguration::_allowedAuthenticators,null)?.let(this::setAllowedAuthenticators)
                config.getProperty(AndroidUnlockPromptConfiguration::_confirmationRequired,null)?.let(this::setConfirmationRequired)
            }.build()
            val siphon = object: BiometricPrompt.AuthenticationCallback() {
                private fun send(v: AuthResult) {
                    executor.asCoroutineDispatcher().let(::CoroutineScope).launch { channel.send(v) }
                }
                override fun onAuthenticationSucceeded(result: AuthenticationResult) {
                    send(AuthResult.Success(result))
                }
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    send(AuthResult.Error(errorCode, errString.toString()))
                }
                override fun onAuthenticationFailed() {
                    config.forEach { it.invalidBiometryCallback?.invoke() }
                }
            }
            val prompt = when (effectiveContext) {
                is FragmentContext.OfActivity -> BiometricPrompt(effectiveContext.activity, executor, siphon)
                is FragmentContext.OfFragment -> BiometricPrompt(effectiveContext.fragment, executor, siphon)
            }
            when (forSpecificKey) {
                null -> prompt.authenticate(promptInfo)
                else -> prompt.authenticate(promptInfo, forSpecificKey)
            }
        }
        when (val result = channel.receive()) {
            is AuthResult.Success -> return
            is AuthResult.Error -> throw UnlockFailed("${result.message} (code ${result.code})")
        }
    }

    internal suspend fun getJCASignature(signingConfig: AndroidSignerSigningConfiguration): Signature =
        signatureAlgorithm.getJCASignatureInstance().getOrThrow().also {
            if (needsAuthenticationForEveryUse) {
                it.initSign(jcaPrivateKey)
                attemptBiometry(DSL.ConfigStack(signingConfig.unlockPrompt.v, config.unlockPrompt.v), CryptoObject(it))
            } else {
                try {
                    it.initSign(jcaPrivateKey)
                } catch (_: UserNotAuthenticatedException) {
                    attemptBiometry(DSL.ConfigStack(signingConfig.unlockPrompt.v, config.unlockPrompt.v), null)
                    it.initSign(jcaPrivateKey)
                }
            }
        }

    final override suspend fun trySetupUninterruptedSigning(configure: DSLConfigureFn<AndroidSignerSigningConfiguration>) = catching {
        if (needsAuthentication && !needsAuthenticationForEveryUse) {
            getJCASignature(DSL.resolve(::AndroidSignerSigningConfiguration, configure))
        }
    }

    final override suspend fun sign(
        data: SignatureInput,
        configure: DSLConfigureFn<AndroidSignerSigningConfiguration>
    ): SignatureResult = signCatching {
        require(data.format == null)
        val jcaSig = getJCASignature(DSL.resolve(::AndroidSignerSigningConfiguration, configure))
            .let { data.data.forEach(it::update); it.sign() }

        return@signCatching when (this) {
            is ECDSA -> CryptoSignature.EC.parseFromJca(jcaSig).withCurve(publicKey.curve)
            is RSA -> CryptoSignature.RSAorHMAC.parseFromJca(jcaSig)
        }
    }

    class ECDSA internal constructor(jcaPrivateKey: PrivateKey,
                                     alias: String,
                                     keyInfo: KeyInfo,
                                     config: AndroidSignerConfiguration,
                                     certificateChain: CertificateChain,
                                     override val signatureAlgorithm: SignatureAlgorithm.ECDSA)
        : AndroidKeystoreSigner(jcaPrivateKey, alias, keyInfo, config, certificateChain), SignerI.ECDSA {
        override val publicKey = certificateChain.leaf.publicKey as CryptoPublicKey.EC
    }

    class RSA internal constructor(jcaPrivateKey: PrivateKey,
                                   alias: String,
                                   keyInfo: KeyInfo,
                                   config: AndroidSignerConfiguration,
                                   certificateChain: CertificateChain,
                                   override val signatureAlgorithm: SignatureAlgorithm.RSA)
        : AndroidKeystoreSigner(jcaPrivateKey, alias, keyInfo, config, certificateChain), SignerI.RSA {
        override val publicKey = certificateChain.leaf.publicKey as CryptoPublicKey.Rsa
    }
}

val AndroidKeystoreSigner.needsAuthentication inline get() =
    keyInfo.isUserAuthenticationRequired
val AndroidKeystoreSigner.needsAuthenticationForEveryUse inline get() =
    keyInfo.isUserAuthenticationRequired &&
            (keyInfo.userAuthenticationValidityDurationSeconds <= 0)

internal actual fun getPlatformSigningProvider(configure: DSLConfigureFn<PlatformSigningProviderConfigurationBase>): PlatformSigningProvider =
    AndroidKeyStoreProvider
