package at.asitplus.signum.supreme.os

import android.annotation.SuppressLint
import android.os.Build
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
import at.asitplus.signum.indispensable.*
import at.asitplus.awesn1.Asn1StructuralException
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.indispensable.pki.Certificate
import at.asitplus.signum.indispensable.pki.leaf
import at.asitplus.signum.supreme.AppLifecycleMonitor
import at.asitplus.signum.indispensable.SecretExposure
import at.asitplus.signum.indispensable.sign.RSAAlgorithm.Padding as RSAPadding
import at.asitplus.signum.supreme.SignatureResult
import at.asitplus.signum.supreme.UnlockFailed
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.dsl.AndroidSignerConfiguration
import at.asitplus.signum.dsl.AndroidSignerSigningConfiguration
import at.asitplus.signum.dsl.AndroidSigningKeyConfiguration
import at.asitplus.signum.dsl.AndroidUnlockPromptConfiguration
import at.asitplus.signum.dsl.PlatformSigningProviderConfigurationBase
import at.asitplus.signum.indispensable.integrity.SignatureAlgorithm
import at.asitplus.signum.indispensable.integrity.SignatureInput
import at.asitplus.signum.supreme.dsl.DISCOURAGED
import at.asitplus.signum.supreme.dsl.DSL
import at.asitplus.signum.supreme.dsl.DSLConfigureFn
import at.asitplus.signum.supreme.dsl.PREFERRED
import at.asitplus.signum.supreme.dsl.REQUIRED
import at.asitplus.signum.dsl.SigningKeyConfiguration
import at.asitplus.signum.dsl.UnlockPromptConfiguration
import at.asitplus.signum.dsl.attestation
import at.asitplus.signum.dsl.ec
import at.asitplus.signum.dsl.factors
import at.asitplus.signum.dsl.hardware
import at.asitplus.signum.dsl.protection
import at.asitplus.signum.dsl.rsa
import at.asitplus.signum.dsl.signer
import at.asitplus.signum.dsl.unlockPrompt
import at.asitplus.signum.indispensable.digest.WellKnownDigest
import at.asitplus.signum.indispensable.sign.ECDSAAlgorithm
import at.asitplus.signum.indispensable.sign.ECDSAPublicKey
import at.asitplus.signum.indispensable.sign.ECDSASignature
import at.asitplus.signum.indispensable.sign.RSAAlgorithm
import at.asitplus.signum.indispensable.sign.RSAPublicKey
import at.asitplus.signum.indispensable.sign.RSASignature
import at.asitplus.signum.supreme.signCatching
import com.ionspin.kotlin.bignum.integer.base63.toJavaBigInteger
import io.github.aakira.napier.Napier
import at.asitplus.signum.supreme.sign.Signer as SignerI
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.spec.ECGenParameterSpec
import java.security.spec.RSAKeyGenParameterSpec
import java.time.Instant
import java.util.Date
import javax.security.auth.x500.X500Principal
import kotlin.math.max

internal sealed interface FragmentContext {
    @JvmInline value class OfActivity(val activity: FragmentActivity): FragmentContext
    @JvmInline value class OfFragment(val fragment: Fragment): FragmentContext
}

private val dispatcher = Dispatchers.IO.limitedParallelism(1, "Android Keystore Operations")

/**
 * Resolve [what] differently based on whether the [vA]lue was [spec]ified.
 *
 * * [spec] = `true`: Check if [valid] contains [nameMap] applied to [vA()][vA], return [vA()][vA] if yes, throw otherwise
 * * [spec] = `false`: Check if [valid] contains exactly one element, if yes, return the [E] from [possible] for which [nameMap] returns that element, throw otherwise
 */
private inline fun <reified E> resolveOption(what: String, valid: Array<String>, possible: Sequence<E>, spec: Boolean, vA: ()->E, crossinline nameMap: (E)->String): E =
    when (spec) {
        true -> {
            val v = vA()
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

// @Service
interface AndroidKeyStoreOperationsProvider {
    /**
     * Allows overriding the entire key pair generation process if desired.
     * You will need to handle the entire [config] object, including attestation settings.
     * **This is likely not what you want to override**. A default implementation that forwards to [initKeyGenSpec] is provided.
     *
     * If you override this function, [initKeyGenSpec] becomes unused and can be dummied out
     */
    fun initKeyPairGenerator(alias: String, config: AndroidSigningKeyConfiguration): KeyPairGenerator? {
        val (algorithm, builder) = initKeyGenSpec(alias, config) ?: return null
        val algSpec = builder.apply {
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
                    setInvalidatedByBiometricEnrollment(it.factors.v.biometry &&
                            !it.factors.v.biometryWithNewFactors)
                    setUserAuthenticationRequired(true)
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                        setUserAuthenticationParameters(it.timeout.inWholeSeconds.toInt(),
                            (if (it.factors.v.biometry) KeyProperties.AUTH_BIOMETRIC_STRONG else 0) or
                                    (if (it.factors.v.deviceLock) KeyProperties.AUTH_DEVICE_CREDENTIAL else 0))
                    } else {
                        it.factors.v.let { factors -> when {
                            factors.biometry && !factors.deviceLock -> {
                                @Suppress("DEPRECATION")
                                setUserAuthenticationValidityDurationSeconds(-1)
                            }
                            else -> {
                                @Suppress("DEPRECATION")
                                setUserAuthenticationValidityDurationSeconds(max(1, it.timeout.inWholeSeconds.toInt()))
                            }
                        }}
                    }
                }
            }
        }.build()
        return KeyPairGenerator
            .getInstance(algorithm, "AndroidKeyStore")
            .apply { initialize(algSpec) }
    }

    /**
     * Set up a [KeyGenParameterSpec.Builder] for the configured algorithm-specific key configuration, if supported.
     * Returns the `algorithm` string for [KeyPairGenerator.getInstance] and the partially-built `Builder`.
     * If unsupported, should throw or return `null`.
     *
     * Implementations should only handle algorithm-specific setup, i.e., [java.security.spec.AlgorithmParameterSpec],
     * digests, paddings, etc., as appropriate for the implemented algorithm. Certificate/attestation setup is handled
     * by Signum.
     *
     * If full control over the key construction (including certificates, attestations, etc.) is desired, override
     * [initKeyPairGenerator] and dummy this function out.
     * (This function is only used in [initKeyPairGenerator]'s default implementation.)
     */
    fun initKeyGenSpec(alias: String, config: AndroidSigningKeyConfiguration): Pair<String, KeyGenParameterSpec.Builder>?

    /**
     * Construct an [AndroidKeystoreSigner] for the given values.
     * Implementers likely only need to determine the [SignatureAlgorithm] to expose, and have their subclass
     * implement the relevant [SignerI] marker interface (if applicable).
     *
     * They also need to integrate with X.509 classes to ensure certificate/public key parsing for their algorithm works,
     * as the public key is retrieved from the key's key store certificate.
     */
    fun getAndroidKeystoreSigner(jcaPrivateKey: PrivateKey, alias: String, keyInfo: KeyInfo,
                                 config: AndroidSignerConfiguration, publicKey: CryptoPublicKey,
                                 attestation: AndroidKeystoreAttestation?): AndroidKeystoreSigner?
}

object SupremeAndroidKeyStoreOperationsProvider : AndroidKeyStoreOperationsProvider {
    @SuppressLint("WrongConstant")
    override fun initKeyGenSpec(
        alias: String,
        config: AndroidSigningKeyConfiguration
    ): Pair<String, KeyGenParameterSpec.Builder>? {
        val algSpec = DSL.options(config.ec, config.rsa)
            ?: throw UnsupportedCryptoException("Unknown chosen key type")
        val builder = KeyGenParameterSpec.Builder(alias,
                (if (algSpec.allowsSigning) KeyProperties.PURPOSE_SIGN else 0) or
                    (if (algSpec.allowsKeyAgreement) KeyProperties.PURPOSE_AGREE_KEY else 0))
        return when (algSpec) {
            is SigningKeyConfiguration.RSAConfiguration ->
                Pair(KeyProperties.KEY_ALGORITHM_RSA, builder.apply {
                    setAlgorithmParameterSpec(
                        RSAKeyGenParameterSpec(algSpec.bits, algSpec.publicExponent.toJavaBigInteger()))
                    setDigests(*algSpec.digests.map {
                        (it as? WellKnownDigest)?.jcaName ?: throw UnsupportedCryptoException("Unknown digest $it")
                    }.toTypedArray())
                    setSignaturePaddings(*algSpec.paddings.map {
                        when (it) {
                            RSAPadding.PKCS1 -> KeyProperties.SIGNATURE_PADDING_RSA_PKCS1
                            RSAPadding.PSS -> KeyProperties.SIGNATURE_PADDING_RSA_PSS
                        }
                    }.toTypedArray())
                })
            is SigningKeyConfiguration.ECConfiguration ->
                Pair(KeyProperties.KEY_ALGORITHM_EC, builder.apply {
                    setAlgorithmParameterSpec(ECGenParameterSpec(algSpec.curve.jcaName))
                    setDigests(*algSpec.digests.map {
                        ((it ?: return@map KeyProperties.DIGEST_NONE) as? WellKnownDigest)?.jcaName
                            ?: throw UnsupportedCryptoException("Unknown digest $it")
                    }.toTypedArray())
                })
            else -> throw UnsupportedCryptoException("Unknown algorithm is configured")
        }
    }

    override fun getAndroidKeystoreSigner(
        jcaPrivateKey: PrivateKey, alias: String, keyInfo: KeyInfo, config: AndroidSignerConfiguration,
        publicKey: CryptoPublicKey, attestation: AndroidKeystoreAttestation?
    ): AndroidKeystoreSigner? = when (publicKey) {
        is ECDSAPublicKey -> {
            val ecConfig = config.ec.v
            val digest = resolveOption("digest", keyInfo.digests, WellKnownDigest.entries.asSequence() + sequenceOf<WellKnownDigest?>(null), ecConfig.digestSpecified, { ecConfig.digest as WellKnownDigest }) { it?.jcaName ?: KeyProperties.DIGEST_NONE }
            AndroidKeystoreSigner.ECDSA(
                jcaPrivateKey, alias, keyInfo, config, publicKey,
                attestation, ECDSAAlgorithm(digest, publicKey.curve)
            )
        }
        is RSAPublicKey -> {
            val rsaConfig = config.rsa.v
            val digest = resolveOption("digest", keyInfo.digests, WellKnownDigest.entries.asSequence(), rsaConfig.digestSpecified, { rsaConfig.digest as WellKnownDigest }, WellKnownDigest::jcaName)
            val padding = resolveOption<RSAPadding>("padding", keyInfo.signaturePaddings, RSAPadding.entries.asSequence(), rsaConfig.paddingSpecified, { rsaConfig.padding }) {
                when (it) {
                    RSAPadding.PKCS1 -> KeyProperties.SIGNATURE_PADDING_RSA_PKCS1
                    RSAPadding.PSS -> KeyProperties.SIGNATURE_PADDING_RSA_PSS
                }
            }
            AndroidKeystoreSigner.RSA(
                jcaPrivateKey, alias, keyInfo, config, publicKey,
                attestation, RSAAlgorithm(padding, digest)
            )

        }
        else -> throw UnsupportedCryptoException("Unknown public key type")
    }
}

/** A provider that manages keys in the [Android Key Store](https://developer.android.com/privacy-and-security/keystore). */
object AndroidKeyStoreProvider:
    PlatformSigningProviderI<AndroidKeystoreSigner, AndroidSignerConfiguration, AndroidSigningKeyConfiguration>
{

    private val ks: KeyStore get() =
        KeyStore.getInstance("AndroidKeyStore").apply { load(null, null) }

    override suspend fun createSigningKey(
        alias: String,
        configure: DSLConfigureFn<AndroidSigningKeyConfiguration>
    ) = withContext(dispatcher) { catching {
        if (ks.containsAlias(alias)) {
            throw NoSuchElementException("Key with alias $alias already exists")
        }
        val config = DSL.resolve(::AndroidSigningKeyConfiguration, configure)
        ServiceLoader.load<AndroidKeyStoreOperationsProvider>().get(alias) {
            initKeyPairGenerator(it, config)
        }.generateKeyPair()
        return@catching getSignerForKey(alias, config.signer.v).getOrThrow()
    }}

    override suspend fun getSignerForKey(
        alias: String,
        configure: DSLConfigureFn<AndroidSignerConfiguration>
    ): KmmResult<AndroidKeystoreSigner> = withContext(dispatcher) { catching {
        val config = DSL.resolve(::AndroidSignerConfiguration, configure)
        val jcaPrivateKey = ks.getKey(alias, null) as? PrivateKey
            ?: throw NoSuchElementException("No key for alias $alias exists")
        val publicKey: CryptoPublicKey
        val attestation: AndroidKeystoreAttestation?
        ks.getCertificateChain(alias).let { chain ->
            catching { chain.map { Certificate.decodeFromDer(it.encoded) } }.let { r ->
                if (r.isSuccess) r.getOrThrow().let {
                    publicKey = it.leaf.publicKey
                    attestation = if (it.size > 1) AndroidKeystoreAttestation(it) else null
                } else r.exceptionOrNull()!!.let {
                    if ((it is Asn1StructuralException) &&
                        (Build.VERSION.SDK_INT <= Build.VERSION_CODES.R) &&
                        (chain.size == 1) &&
                        (chain.first().encoded.takeLast(5) == listOf(0x03,0x03,0x00,0x30,0x00).map(Int::toByte))) {
                        Napier.v { "Correcting Android 10 AKS signature bug" }
                        publicKey = CertificateFactory.getInstance("X.509")
                            .generateCertificate(chain.first().encoded.inputStream())
                            .publicKey.toCryptoPublicKey().getOrThrow()
                        attestation = null
                    } else throw it
                }
            }
        }

        val keyInfo = KeyFactory.getInstance(jcaPrivateKey.algorithm)
            .getKeySpec(jcaPrivateKey, KeyInfo::class.java)

        return@catching ServiceLoader.load<AndroidKeyStoreOperationsProvider>().get(publicKey) {
            getAndroidKeystoreSigner(jcaPrivateKey, alias, keyInfo, config, it, attestation)
        }
    }}

    override suspend fun deleteSigningKey(alias: String) = catching { withContext(dispatcher) {
        ks.deleteEntry(alias)
    }}
}

abstract class AndroidKeystoreSigner protected constructor(
    internal val jcaPrivateKey: PrivateKey,
    final override val alias: String,
    val keyInfo: KeyInfo,
    protected val config: AndroidSignerConfiguration,
    final override val attestation: AndroidKeystoreAttestation?
) : PlatformSigningProviderSigner<AndroidSignerSigningConfiguration, AndroidKeystoreAttestation> {

    @SecretExposure
    override suspend fun exportPrivateKey(): KmmResult<Nothing> = KmmResult.failure(IllegalStateException("Non-Exportable key"))

    final override val mayRequireUserUnlock: Boolean get() = this.needsAuthentication

    private sealed interface AuthResult {
        @JvmInline value class Success(val result: AuthenticationResult): AuthResult
        data class Error(val code: Int, val message: String): AuthResult
    }

    protected suspend fun attemptBiometry(config: DSL.ConfigStack<AndroidUnlockPromptConfiguration>, forSpecificKey: CryptoObject?) {
        val channel = Channel<AuthResult>(capacity = Channel.RENDEZVOUS)
        val effectiveContext = config.getProperty(
            AndroidUnlockPromptConfiguration::explicitContext,
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
                setTitle(config.getProperty(
                    AndroidUnlockPromptConfiguration::_message,
                    default = UnlockPromptConfiguration.defaultMessage))
                setNegativeButtonText(config.getProperty(
                    AndroidUnlockPromptConfiguration::_cancelText,
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
        signatureAlgorithm.getJCASignatureInstance(provider = "AndroidKeyStore").also {
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
            withContext(dispatcher) { getJCASignature(DSL.resolve(::AndroidSignerSigningConfiguration, configure)) }
        }
    }

    final override suspend fun sign(
        data: SignatureInput,
        configure: DSLConfigureFn<AndroidSignerSigningConfiguration>
    ): SignatureResult<*> = withContext(dispatcher) { signCatching {
        require(data.format == null)
        val jcaSig = getJCASignature(DSL.resolve(::AndroidSignerSigningConfiguration, configure))
            .let { data.data.forEach(it::update); it.sign() }

        return@signCatching parseSignatureFromJca(jcaSig)
    }}

    abstract fun parseSignatureFromJca(jcaSig: ByteArray): CryptoSignature.RawByteEncodable

    class ECDSA internal constructor(jcaPrivateKey: PrivateKey,
                                     alias: String,
                                     keyInfo: KeyInfo,
                                     config: AndroidSignerConfiguration,
                                     override val publicKey: CryptoPublicKey.EC,
                                     attestation: AndroidKeystoreAttestation?,
                                     override val signatureAlgorithm: SignatureAlgorithm.ECDSA)
        : AndroidKeystoreSigner(jcaPrivateKey, alias, keyInfo, config, attestation),
        PlatformSigningProviderSigner.ECDSA<AndroidSignerSigningConfiguration, AndroidKeystoreAttestation>
    {
        override suspend fun keyAgreement(
            publicValue: KeyAgreementPublicValue.ECDH,
            configure: DSLConfigureFn<AndroidSignerSigningConfiguration>
        ) = catching {
            val signingConfig = DSL.resolve(::AndroidSignerSigningConfiguration, configure)
            javax.crypto.KeyAgreement.getInstance("ECDH", "AndroidKeyStore").run {
                //Android bug here: impossible to do for auth-on-every use keys. Earliest possible fix: Android 16, if ever
                try {
                    init(jcaPrivateKey)
                } catch (_: UserNotAuthenticatedException) {
                    attemptBiometry(DSL.ConfigStack(signingConfig.unlockPrompt.v, config.unlockPrompt.v), null)
                    init(jcaPrivateKey)
                }
                doPhase(publicValue.asCryptoPublicKey().toJcaPublicKey(), true)
                generateSecret()
            }
        }

        override fun parseSignatureFromJca(jcaSig: ByteArray) =
            ECDSASignature.parseFromJca(jcaSig).withCurve(publicKey.curve)
    }

    class RSA internal constructor(jcaPrivateKey: PrivateKey,
                                   alias: String,
                                   keyInfo: KeyInfo,
                                   config: AndroidSignerConfiguration,
                                   override val publicKey: CryptoPublicKey.RSA,
                                   attestation: AndroidKeystoreAttestation?,
                                   override val signatureAlgorithm: SignatureAlgorithm.RSA)
        : AndroidKeystoreSigner(jcaPrivateKey, alias, keyInfo, config, attestation), SignerI.RSA
    {
        override fun parseSignatureFromJca(jcaSig: ByteArray) =
            RSASignature.parseFromJca(jcaSig)
    }
}

val AndroidKeystoreSigner.needsAuthentication inline get() =
    keyInfo.isUserAuthenticationRequired
val AndroidKeystoreSigner.needsAuthenticationForEveryUse inline get() =
    keyInfo.isUserAuthenticationRequired &&
            (keyInfo.userAuthenticationValidityDurationSeconds <= 0)

internal actual fun getPlatformSigningProvider(configure: DSLConfigureFn<PlatformSigningProviderConfigurationBase>): PlatformSigningProviderI<*,*,*> =
    AndroidKeyStoreProvider
