@file:OptIn(ExperimentalForeignApi::class, at.asitplus.signum.SignumInternals::class)
package at.asitplus.signum.supreme.os

import at.asitplus.awesn1.crypto.X509SignatureValue
import at.asitplus.nonFatalOrThrow
import at.asitplus.signum.CryptoOperationFailed
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.dsl.*
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.agree.KeyAgreementPublicValue
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.digest.WellKnownDigest
import at.asitplus.signum.indispensable.digest.digest
import at.asitplus.signum.indispensable.sign.*
import at.asitplus.signum.internals.*
import at.asitplus.signum.supreme.CFCryptoOperationFailed
import at.asitplus.signum.supreme.swiftasync
import io.github.aakira.napier.Napier
import kotlinx.cinterop.*
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.encodeToJsonElement
import platform.CoreFoundation.*
import platform.DeviceCheck.DCAppAttestService
import platform.Foundation.NSBundle
import platform.Foundation.NSData
import platform.Security.kSecClassGenericPassword
import platform.Security.kSecAttrService
import platform.Security.kSecAttrAccount
import platform.Security.kSecValueData
import platform.Security.kSecAttrAccessible
import platform.Security.kSecAttrAccessibleAlways
import platform.Security.kSecAttrAccessibleAlwaysThisDeviceOnly
import platform.Security.kSecAttrAccessibleAfterFirstUnlock
import platform.Security.kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
import platform.Security.kSecAttrAccessibleWhenUnlocked
import platform.Security.kSecAttrAccessibleWhenUnlockedThisDeviceOnly
import platform.LocalAuthentication.*
import platform.Security.*
import kotlin.math.min
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.TimeSource
import at.asitplus.signum.indispensable.sign.RsaAlgorithm.Padding as RSAPadding

@OptIn(DelicateCoroutinesApi::class)
private val dispatcher = Dispatchers.IO.limitedParallelism(1, "iOS Keychain Operations")

private object OpaqueAliasNamespace {
    const val SERVICE = "at.asitplus.signum.opaque-signing-key.v1"
}

private sealed interface IosKeyBackendChoice {
    data class Opaque(val backend: OpaqueIosKeyBackend) : IosKeyBackendChoice
    data class SecKey(val attributes: Pair<CFMutableDictionaryRef, JsonElement?>) : IosKeyBackendChoice
}

private fun newOpaqueRecordId() = Random.nextBytes(32).toHexString()

private object KeychainTags {
    /** Bundle-id-free tags used for all newly created keys; tried first on retrieval and deletion. */
    const val NEW_PRIVATE_KEYS = "supreme.privatekey"
    const val NEW_PUBLIC_KEYS = "supreme.publickey"

    /**
     * Legacy, bundle-id-scoped tags, kept solely for backwards-compatible fallback lookups.
     * In any real app `bundleIdentifier` is non-null, so these reproduce the exact tag the previous
     * implementation used (`supreme.privatekey-<bundleId>`) and the fallback is always active.
     *
     * `bundleIdentifier` is only `null` in bundle-less contexts (a bare CLI binary, an XCTest bundle
     * without a host app). There, the previous implementation threw `UnsupportedCryptoException`, so
     * no legacy key can exist — we simply skip the fallback and rely on the new bundle-id-free tag,
     * which (unlike before) now works without a bundle.
     */
    private val legacyBundleId get() = NSBundle.mainBundle.bundleIdentifier
    private val LEGACY_PRIVATE_KEYS get() = legacyBundleId?.let { "supreme.privatekey-$it" }
    private val LEGACY_PUBLIC_KEYS get() = legacyBundleId?.let { "supreme.publickey-$it" }

    /**
     * Lookups to try, in order: first the new bundle-id-free tag
     * then the legacy bundle-id-scoped tag run
     */
    val PRIVATE_KEYS = listOfNotNull(NEW_PRIVATE_KEYS, LEGACY_PRIVATE_KEYS)
    val PUBLIC_KEYS = listOfNotNull(NEW_PUBLIC_KEYS, LEGACY_PUBLIC_KEYS)
}

/**
 * Resolve [what] differently based on whether the [vA]lue was [spec]ified.
 *
 * * [spec] = `true`: Check if [valid] contains [vA()][vA], return [vA()][vA] if yes, throw otherwise
 * * [spec] = `false`: Check if [valid] contains exactly one element, if yes, return it, throw otherwise
 */
private inline fun <reified E> resolveOption(what: String, valid: Set<E>, spec: Boolean, vA: ()->E): E =
    when (spec) {
        true -> {
            val v = vA()
            if (!valid.contains(v))
                throw IllegalArgumentException("Key does not support $what $v; supported: ${valid.joinToString(", ")}")
            v
        }
        false -> {
            if (valid.size != 1)
                throw IllegalArgumentException("Key supports multiple ${what}s (${valid.joinToString(", ")}). You need to specify $what in signer configuration.")
            valid.first()
        }
    }

private object LAContextStorage {
    data class SuccessfulAuthentication(
        val authnContext: LAContext, val authnTime: TimeSource.Monotonic.ValueTimeMark)
    var successfulAuthentication: SuccessfulAuthentication? = null
}

private object OpaqueLAContextStorage {
    data class SuccessfulAuthentication(
        val identity: String, val authnContext: LAContext, val authnTime: TimeSource.Monotonic.ValueTimeMark)
    var successfulAuthentication: SuccessfulAuthentication? = null
}

private fun authenticationIdentity(alias: String, backendId: String, recordId: String) = "$alias\u0000$backendId\u0000$recordId"

private fun LAContext.configureUnlockPrompt(signingConfig: IosSignerSigningConfiguration, signerConfig: IosSignerConfiguration) {
    val stack = DSL.ConfigStack(signingConfig.unlockPrompt.v, signerConfig.unlockPrompt.v)
    localizedReason = stack.getProperty(UnlockPromptConfiguration::_message, default = UnlockPromptConfiguration.defaultMessage)
    localizedCancelTitle = stack.getProperty(UnlockPromptConfiguration::_cancelText, default = UnlockPromptConfiguration.defaultCancelText)
}

internal fun shouldReuseAuthentication(timeout: Duration, identity: String, cachedIdentity: String?, elapsed: Duration): Boolean =
    timeout != Duration.ZERO && cachedIdentity == identity && elapsed < timeout

private fun authenticationContext(
    identity: String, metadata: IosKeyMetadata, signingConfig: IosSignerSigningConfiguration,
    signerConfig: IosSignerConfiguration,
): Pair<LAContext?, Boolean> {
    if (!metadata.needsUnlock) return null to false
    val previous = if (metadata.unlockTimeout != Duration.ZERO) OpaqueLAContextStorage.successfulAuthentication else null
    if (previous != null && shouldReuseAuthentication(
            metadata.unlockTimeout, identity, previous.identity, previous.authnTime.elapsedNow()))
        return previous.authnContext.also { it.configureUnlockPrompt(signingConfig, signerConfig) } to false
    val context = LAContext().apply {
        touchIDAuthenticationAllowableReuseDuration = 0.0
        configureUnlockPrompt(signingConfig, signerConfig)
    }
    return context to true
}

private fun recordOpaqueAuthentication(identity: String, context: LAContext) {
    OpaqueLAContextStorage.successfulAuthentication = OpaqueLAContextStorage.SuccessfulAuthentication(
        identity, context, TimeSource.Monotonic.markNow())
}

private fun mapUnlockFailure(failure: Throwable): Nothing {
    when (failure) {
        is CoreFoundationException -> if (failure.nsError.domain == LAErrorDomain) when (failure.nsError.code) {
            LAErrorUserCancel, LAErrorAuthenticationFailed, LAErrorBiometryLockout -> throw UnlockFailed(failure.nsError.localizedDescription, failure)
        }
        is CFCryptoOperationFailed -> when (failure.osStatus) {
            errSecUserCanceled, errSecAuthFailed -> throw UnlockFailed(failure.message, failure)
        }
    }
    throw failure
}

/**
 * A signer backed by an iOS Keychain key.
 *
 * RSA-PSS supports only MGF1 using the signature digest, a salt length equal to the digest output length, and trailer
 * field `1`, as required by the iOS Security framework.
 */
sealed class IosSigner(final override val alias: String,
                       protected val metadata: IosKeyMetadata,
                       private val signerConfig: IosSignerConfiguration)
    : PlatformSigningProviderSigner<IosSignerSigningConfiguration, IosHomebrewAttestation> {

    override val mayRequireUserUnlock get() = needsAuthentication

    /** Whether this key requires user authentication before use. */
    val needsAuthentication get() = authenticationTimeout != null

    /** Whether this key requires a fresh user authentication for every use. */
    val needsAuthenticationForEveryUse get() = authenticationTimeout == Duration.ZERO

    /**
     * The effective Signum reuse window for successful user authentication.
     *
     * `null` means that the key does not require user authentication, [Duration.ZERO] means that every use requires
     * authentication, and a positive duration is the time for which Signum may reuse authentication in the provider
     * process.
     *
     * This value is restored from Signum's stored key metadata. It is not an independent readback of an iOS Keychain
     * access-control attribute.
     */
    val authenticationTimeout: Duration? get() = metadata.rawUnlockTimeout
    override val attestation get() = metadata.attestation

    protected interface PrivateKeyManager { suspend fun get(operation: Long?, algorithm: SecKeyAlgorithm?, signingConfig: IosSignerSigningConfiguration): OwnedCFValue<SecKeyRef> }
    @SignumInternals
    /** For InternalsAccessor ONLY!!! */
    internal val DONOTUSEsecKeyRef get() = if (this is Opaque) null else runBlocking { privateKeyManager.get(null, null, IosSignerSigningConfiguration()) }
    protected val privateKeyManager = object : PrivateKeyManager {
        private var storedKey: OwnedCFValue<SecKeyRef>? = null
        override suspend fun get(operation: Long?, algorithm: SecKeyAlgorithm?, signingConfig: IosSignerSigningConfiguration) = withContext(dispatcher) {
            Napier.v { "Private Key access for alias $alias requested (needs unlock? ${metadata.needsUnlock}; timeout? ${metadata.unlockTimeout})" }

            val ctx: LAContext? /* the LAContext (potentially old if the timeout permits) to use */
            val recordable: Boolean /* whether this is a new context, which will prompt for actual authentication */
            if (metadata.needsUnlock) {
                val previousAuthn = if (metadata.unlockTimeout != Duration.ZERO) LAContextStorage.successfulAuthentication else null
                if ((previousAuthn != null) && (previousAuthn.authnTime.elapsedNow() < metadata.unlockTimeout)) {
                    // if we are allowed to reuse the key, and we have the key, then reuse the key
                    storedKey?.let {
                        Napier.v { "Re-using cached private key reference for alias $alias" }
                        return@withContext it
                    }
                    Napier.v { "Re-using successful LAContext to retrieve key with alias $alias" }
                    recordable = false
                    ctx = previousAuthn.authnContext
                } else {
                    Napier.v { "Forcing user to authenticate a new LAContext for alias $alias" }
                    recordable = true
                    ctx = LAContext().apply { touchIDAuthenticationAllowableReuseDuration = min(10.0, metadata.unlockTimeout.inWholeSeconds.toDouble()) }
                }
                ctx?.configureUnlockPrompt(signingConfig, signerConfig)
            } else {
                recordable = false
                ctx = null
            }

            // ok, we need to get the key from the keychain
            // try the new bundle-id-free tag first, then fall back to the legacy bundle-id-scoped tag
            val newPrivateKey: OwnedCFValue<SecKeyRef>
            memScoped {
                val newPrivateKeyVar = alloc<SecKeyRefVar>()
                KeychainTags.PRIVATE_KEYS.forEach { tag ->
                    val query = createCFDictionary {
                        kSecClass mapsTo kSecClassKey
                        kSecAttrKeyClass mapsTo kSecAttrKeyClassPrivate
                        kSecAttrApplicationLabel mapsTo alias
                        kSecAttrApplicationTag mapsTo tag
                        when (this@IosSigner) {
                            is Opaque -> throw UnsupportedCryptoException("Opaque signer has no SecKeyRef")
                            is ECDSA -> kSecAttrKeyType mapsTo kSecAttrKeyTypeEC
                            is RSA -> kSecAttrKeyType mapsTo kSecAttrKeyTypeRSA
                        }
                        kSecMatchLimit mapsTo kSecMatchLimitOne
                        kSecReturnRef mapsTo true

                        if (ctx != null) {
                            kSecUseAuthenticationContext mapsTo ctx
                            kSecUseAuthenticationUI mapsTo kSecUseAuthenticationUIAllow
                        } else {
                            kSecUseAuthenticationUI mapsTo kSecUseAuthenticationUIFail
                        }
                    }
                    when (val lastStatus = SecItemCopyMatching(query, newPrivateKeyVar.ptr.reinterpret())) {
                        errSecSuccess -> {
                            newPrivateKey = newPrivateKeyVar.value?.adopt()
                                ?: throw IllegalStateException("SecItemCopyMatching returned success, but no key")
                            return@memScoped
                        }
                        errSecItemNotFound -> {/*fall through*/}
                        else -> throw CFCryptoOperationFailed(
                            thing = "retrieve private key",
                            osStatus = lastStatus
                        )
                    }
                }
                //fall through to error handling
                throw CFCryptoOperationFailed(
                    thing = "retrieve private key",
                    osStatus = errSecItemNotFound
                )
            }
            if (operation != null && algorithm != null) {
                if (!SecKeyIsAlgorithmSupported(newPrivateKey.value, operation, algorithm)) {
                    throw UnsupportedCryptoException("Requested operation is not supported by this key")
                }
            }

            if (recordable && (ctx != null)) {
                Napier.v { "Going to record successful LAContext after retrieving key $alias" }
                // record the successful unlock timestamp and LAContext for reuse
                // produce a dummy signature to ensure that the unlock has succeeded; this is required by secure enclave keys, which do not prompt for unlock until signing time
                corecall { SecKeyCreateSignature(newPrivateKey.value, signatureAlgorithm.secKeyAlgorithm,
                    byteArrayOf(0x0).toNSData().giveToCF(), error)?.let(::CFRelease) }

                // if we have reached this point, the unlock operation has definitively succeeded
                LAContextStorage.successfulAuthentication = LAContextStorage.SuccessfulAuthentication(
                    authnContext = ctx, authnTime = TimeSource.Monotonic.markNow())
                Napier.v { "Successfully recorded LAContext for future re-use" }
            }
            if (!needsAuthenticationForEveryUse) {
                storedKey = newPrivateKey
            }
            return@withContext newPrivateKey
        }
    }

    final override suspend fun trySetupUninterruptedSigning(configure: DSLConfigureFn<IosSignerSigningConfiguration>) {
        if (this is Opaque) return
        if (needsAuthentication && !needsAuthenticationForEveryUse) {
            val config = DSL.resolve(::IosSignerSigningConfiguration, configure)
            val _ = privateKeyManager.get(null, null, config)
        }
    }

    protected abstract fun bytesToSignature(sigBytes: ByteArray): Signature

    @SignumInternals
    internal class Opaque internal constructor(
        alias: String,
        override val publicKey: PublicKey,
        private val recordId: String,
        metadata: IosKeyMetadata,
        private val backend: OpaqueIosKeyBackend,
        config: IosSignerConfiguration,
    ) : IosSigner(alias, metadata, config) {
        override val signatureAlgorithm: SignatureAlgorithm = backend.signatureAlgorithm(publicKey, config)
        override fun bytesToSignature(sigBytes: ByteArray): Signature =
            throw UnsupportedCryptoException("Opaque signatures are returned directly by the backend")

        internal suspend fun signOpaque(
            message: ByteArray, signingConfig: IosSignerSigningConfiguration, signerConfig: IosSignerConfiguration,
        ): Signature =
            IosKeychainProvider.withCurrentOpaqueRecord(alias, recordId) { liveRecord ->
                check(liveRecord.backendId == backend.backendId) { "Opaque key backend changed after signer lookup" }
                val identity = authenticationIdentity(alias, backend.backendId, liveRecord.recordId)
                val (context, isFresh) = authenticationContext(identity, metadata, signingConfig, signerConfig)
                try {
                    val opened = backend.reopen(liveRecord.representationVersion, liveRecord.representation, context)
                    requireOpaquePublicKeyMatch(liveRecord.publicKeySpki, opened.publicKey)
                    val signature = opened.sign(message)
                    if (isFresh && context != null && !needsAuthenticationForEveryUse)
                        recordOpaqueAuthentication(identity, context)
                    signature
                } catch (failure: Throwable) {
                    if (context != null && OpaqueLAContextStorage.successfulAuthentication?.authnContext === context) {
                        OpaqueLAContextStorage.successfulAuthentication = null
                        context.invalidate()
                    }
                    mapUnlockFailure(failure)
                }
            }
    }

    override suspend fun sign(data: SignatureInput, configure: DSLConfigureFn<IosSignerSigningConfiguration>): SignatureResult<*> =
    SignatureResult.make {
        require(data.format == null) { "Pre-hashed data is unsupported on iOS" }
        require(metadata.allowSigning) { "Signing key purpose not set! Signing disallowed!" }
        val signingConfig = DSL.resolve(::IosSignerSigningConfiguration, configure)
        if (this is Opaque) {
            val plaintext = data.collapsed().data.single()
            return@make signOpaque(plaintext, signingConfig, signerConfig)
        }
        val (algorithm, inputFormat) = signatureAlgorithm.suitableSecKeyAlgAndFormat
        val plaintext = data.convertTo(inputFormat).collapsed().data.single().toNSData()
        val signatureBytes = try {
            val key = privateKeyManager.get(kSecKeyOperationTypeSign, algorithm, signingConfig).value
            corecall {
                SecKeyCreateSignature(key, algorithm, plaintext.giveToCF(), error)
            }.takeFromCF<NSData>().toByteArray()
        } catch (x: CoreFoundationException) { /* secure enclave failure */
            mapUnlockFailure(x)
        } catch (x: CFCryptoOperationFailed) { /* keychain failure */
            mapUnlockFailure(x)
        }
        return@make bytesToSignature(signatureBytes)
    }

    class ECDSA internal constructor
        (alias: String, override val publicKey: EcdsaPublicKey, metadata: IosKeyMetadata, config: IosSignerConfiguration)
        : IosSigner(alias, metadata, config),
            PlatformSigningProviderSigner.ECDSA<IosSignerSigningConfiguration, IosHomebrewAttestation>
    {
        override val signatureAlgorithm: EcdsaAlgorithm
        init {
            val algMetadata = Json.decodeFromJsonElement<IosKeyAlgSpecificMetadata.ECDSA>(metadata.algSpecific!!)
            signatureAlgorithm = when (
                val digest = resolveOption("digest", algMetadata.supportedDigests, config.ec.v.digestSpecified, { config.ec.v.digest })
            ){
                Digest.SHA256, Digest.SHA384, Digest.SHA512 -> EcdsaAlgorithm(digest, publicKey.curve)
                else -> throw UnsupportedCryptoException("ECDSA with $digest is not supported on iOS")
            }
        }
        override fun bytesToSignature(sigBytes: ByteArray) =
            EcdsaSignature.fromAsn1(X509SignatureValue(sigBytes)).withCurve(publicKey.curve)

        override suspend fun keyAgreement(
            publicValue: KeyAgreementPublicValue.ECDH,
            configure: DSLConfigureFn<IosSignerSigningConfiguration>
        ): ByteArray {
            val peer = publicValue.asPublicKey()
            if (!peer.curve.isBuiltIn) throw UnsupportedCryptoException("iOS Keychain ECDH does not support curve ${peer.curve.jwkName}")
            require(peer.curve === publicKey.curve) { "ECDH peer curve ${peer.curve.jwkName} does not match local curve ${publicKey.curve.jwkName}" }
            require(metadata.allowKeyAgreement) { "Key agreement purpose not set! Key agreement disallowed!" }
            val config = DSL.resolve(::IosSignerSigningConfiguration, configure)
            val key = privateKeyManager.get(kSecKeyOperationTypeKeyExchange, kSecKeyAlgorithmECDHKeyExchangeStandard, config).value
            return corecall {
                SecKeyCopyKeyExchangeResult(
                    key,
                    kSecKeyAlgorithmECDHKeyExchangeStandard,
                    peer.toSecKey().value,
                    parameters = null,
                    error
                )
            }.takeFromCF<NSData>().toByteArray()
        }
    }

    class RSA internal constructor
        (alias: String, override val publicKey: RsaPublicKey, metadata: IosKeyMetadata, config: IosSignerConfiguration)
        : IosSigner(alias, metadata, config), at.asitplus.signum.indispensable.sign.RSASigner
    {
        override val signatureAlgorithm: RsaAlgorithm
        init {
            val algMetadata = Json.decodeFromJsonElement<IosKeyAlgSpecificMetadata.RSA>(metadata.algSpecific!!)

            signatureAlgorithm = RsaAlgorithm(
                digest = resolveOption("digest", algMetadata.supportedDigests, config.rsa.v.digestSpecified, { config.rsa.v.digest }),
                padding = resolveOption("padding", algMetadata.supportedPaddings, config.rsa.v.paddingSpecified, { config.rsa.v.padding })
            )
        }
        override fun bytesToSignature(sigBytes: ByteArray) =
            RsaSignature.fromAsn1(X509SignatureValue(sigBytes))
    }

}

interface IosKeyAlgSpecificMetadata {
    @Serializable
    @SerialName("ecdsa")
    data class ECDSA(
        val supportedDigests: Set<@Serializable(with = WellKnownDigest.Serializer::class) WellKnownDigest?>
    ) : IosKeyAlgSpecificMetadata

    @Serializable
    @SerialName("rsa")
    data class RSA(
        val supportedDigests: Set<@Serializable(with = WellKnownDigest.Serializer::class) WellKnownDigest>,
        val supportedPaddings: Set<RSAPadding>
    ): IosKeyAlgSpecificMetadata
}

@Serializable
data class IosKeyMetadata(
    val attestation: IosHomebrewAttestation?,
    val rawUnlockTimeout: Duration?,
    val algSpecific: JsonElement?,
    val allowSigning: Boolean = true,
    val allowKeyAgreement: Boolean = false,
    @SerialName("allowEncryption") // for compatibility reasons
    val allowDecryption: Boolean = false,
) {
    val needsUnlock inline get() = (rawUnlockTimeout != null)
    val unlockTimeout inline get() = rawUnlockTimeout ?: Duration.INFINITE
}

// @Service
interface IosKeychainOperationsProvider {
    interface OperationsBundle {
        fun CFDictionaryInitScope.initTopLevelDictionary()
        fun CFDictionaryInitScope.initPrivateKeyDictionary()
        fun GetAlgSpecificMetadata(): JsonElement?
    }

    /**
     * This is the extension point you likely want to override.
     * Check whether [config] is an algorithm you support. If it is, return an appropriate [OperationsBundle] that will
     * be used by [makeKeyAttributes]'s default implementation.
     *
     * This function is only called by [makeKeyAttributes]'s default implementation.
     * If you override [makeKeyAttributes], you can dummy this function out.
     */
    fun getOperationsBundle(config: IosSigningKeyConfiguration): OperationsBundle?

    /**
     * **You likely do not want to override this. Override [getOperationsBundle] instead.**
     * Provides (almost) full control over the dictionary passed to [SecKeyGeneratePair].
     * The [IosKeychainProvider] integrates the following after the fact:
     * - kSecAttrTokenID (to enable secure enclave)
     * - kSecAttrAccessControl (to enable access control)
     */
    context (scope: MemScope)
    fun makeKeyAttributes(alias: String, config: IosSigningKeyConfiguration): Pair<CFMutableDictionaryRef, JsonElement?>? {
        val bundle = getOperationsBundle(config) ?: return null
        return createCFDictionary {
            kSecAttrTokenID mapsTo "placeholder" // will be set in generate()
            with (bundle) { initTopLevelDictionary() }
            kSecPrivateKeyAttrs mapsTo createCFDictionary {
                kSecAttrApplicationLabel mapsTo alias
                kSecAttrIsPermanent mapsTo true
                kSecAttrApplicationTag mapsTo KeychainTags.NEW_PRIVATE_KEYS
                kSecAttrAccessControl mapsTo "placeholder" // populated in generate()
                with (bundle) { initPrivateKeyDictionary() }
            }
            kSecPublicKeyAttrs mapsTo cfDictionaryOf(
                kSecAttrApplicationLabel to alias,
                kSecAttrIsPermanent to true,
                kSecAttrApplicationTag to KeychainTags.NEW_PUBLIC_KEYS
            )
        }.let { Pair(it, bundle.GetAlgSpecificMetadata()) }
    }

    fun makeIosSigner(alias: String, publicKey: PublicKey, metadata: IosKeyMetadata, config: IosSignerConfiguration): IosSigner?

    /** Optional opaque-key backend. The additive default preserves existing providers. */
    @SignumInternals
    val opaqueKeyBackend: OpaqueIosKeyBackend? get() = null
}

/**
 * Creates and reopens Secure Enclave signing keys. Supreme owns the alias record and keeps the
 * representation private. The adapter owns the representation format and transfers its byte array to Supreme.
 *
 * The access control is borrowed through [generate]. The authentication context is borrowed through
 * the corresponding [reopen] and [OpenedKey.sign] operation. Leave releasing these objects to Supreme
 * and scope the native key to that operation.
 */
@SignumInternals
interface OpaqueIosKeyBackend {
    /** Stable, namespaced identifier persisted in Supreme's alias record. */
    val backendId: String

    /** Side-effect-free capability check, evaluated in provider registration order. */
    fun supports(config: IosSigningKeyConfiguration): Boolean

    /** Generates the configured Secure Enclave key using [accessControl]. */
    suspend fun generate(config: IosSigningKeyConfiguration, accessControl: SecAccessControlRef): OpaqueIosKeyMaterial

    /**
     * Reopens the stored representation with [authenticationContext]. Supreme checks [OpenedKey.publicKey]
     * before calling [OpenedKey.sign]. Report cancellation, failed authentication, or biometry lockout as
     * [UnlockFailed] from either callback when adapting a native error.
     */
    suspend fun reopen(representationVersion: Int, representation: ByteArray, authenticationContext: LAContext?): OpenedKey

    /** Resolve the signer algorithm from stored public-key/configuration metadata without reopening native key state. */
    fun signatureAlgorithm(publicKey: PublicKey, config: IosSignerConfiguration): SignatureAlgorithm
}

@SignumInternals
data class OpaqueIosKeyMaterial(
    val representation: ByteArray,
    val publicKey: PublicKey,
    val allowSigning: Boolean = true,
    val representationVersion: Int = 1,
) {
    override fun toString() = "OpaqueIosKeyMaterial(publicKey=$publicKey, allowSigning=$allowSigning, representation=<redacted>)"
}

@SignumInternals
interface OpenedKey {
    val publicKey: PublicKey
    suspend fun sign(message: ByteArray): Signature
}

/** Versioned private record; opaque representation remains inside Supreme's Keychain item. */
@Serializable
internal data class OpaqueIosAliasRecord(
    val version: Int = 1,
    val recordId: String,
    val backendId: String,
    val representationVersion: Int,
    val representation: ByteArray,
    val publicKeySpki: ByteArray,
    val metadata: IosKeyMetadata,
) {
    override fun toString() = "OpaqueIosAliasRecord(version=$version, recordId=$recordId, backendId=$backendId, representation=<redacted>)"
}

internal fun validateOpaqueBackendId(id: String): String {
    require(id.length in 3..200 && ('.' in id || ':' in id) && id.matches(Regex("[A-Za-z0-9][A-Za-z0-9._:-]*"))) {
        "Opaque iOS backend ID must be a stable namespaced identifier"
    }
    return id
}

internal fun requireOpaquePublicKeyMatch(expectedSpki: ByteArray, reopenedPublicKey: PublicKey) {
    require(reopenedPublicKey.asn1.toDer().contentEquals(expectedSpki)) {
        "Reopened opaque key does not match the public key stored for this alias"
    }
}

internal suspend fun prepareAppAttestBinding(publicKey: PublicKey, challenge: ByteArray): Pair<ByteArray, ByteArray> {
    val storedClientData = IosHomebrewAttestation.ClientData(publicKey, challenge).prepareDigestInput()
    return storedClientData to Digest.SHA256.digest(storedClientData)
}

private fun createOpaqueAliasRecord(
    backendId: String, material: OpaqueIosKeyMaterial, metadata: IosKeyMetadata,
): OpaqueIosAliasRecord {
    validateOpaqueBackendId(backendId)
    require(material.representationVersion > 0) { "Opaque representation version must be positive" }
    return OpaqueIosAliasRecord(
        recordId = newOpaqueRecordId(),
        backendId = backendId,
        representationVersion = material.representationVersion,
        representation = material.representation.copyOf(),
        publicKeySpki = material.publicKey.asn1.toDer(),
        metadata = metadata,
    )
}

object SupremeIosKeychainOperationsProvider: IosKeychainOperationsProvider {
    private class ECDSAOps(val config: PlatformSigningKeyConfigurationBase.ECConfiguration) : IosKeychainOperationsProvider.OperationsBundle {
        override fun CFDictionaryInitScope.initTopLevelDictionary() {
            kSecAttrKeyType mapsTo kSecAttrKeyTypeEC
            kSecAttrKeySizeInBits mapsTo config.curve.requireBuiltIn().coordinateLength.bits.toInt()
        }

        override fun CFDictionaryInitScope.initPrivateKeyDictionary() {
            kSecAttrCanSign mapsTo config.purposes.v.signing
            kSecAttrCanDecrypt mapsTo false
            kSecAttrCanUnwrap mapsTo false
            kSecAttrCanDerive mapsTo config.purposes.v.keyAgreement
        }

        override fun GetAlgSpecificMetadata() =
            Json.encodeToJsonElement(IosKeyAlgSpecificMetadata.ECDSA(config.digests.filterIsInstance<WellKnownDigest>().toSet()))
    }

    private class RSAOps(val config: PlatformSigningKeyConfigurationBase.RSAConfiguration) : IosKeychainOperationsProvider.OperationsBundle {
        override fun CFDictionaryInitScope.initTopLevelDictionary() {
            kSecAttrKeyType mapsTo kSecAttrKeyTypeRSA
            kSecAttrKeySizeInBits mapsTo config.bits
        }

        override fun CFDictionaryInitScope.initPrivateKeyDictionary() {
            kSecAttrCanSign mapsTo config.purposes.v.signing
            kSecAttrCanDecrypt mapsTo config.purposes.v.decrypting
            kSecAttrCanUnwrap mapsTo config.purposes.v.decrypting // TODO: expose this separately?
            kSecAttrCanDerive mapsTo false
        }

        override fun GetAlgSpecificMetadata() =
            Json.encodeToJsonElement(IosKeyAlgSpecificMetadata.RSA(config.digests.filterIsInstance<WellKnownDigest>().toSet(), config.paddings))
    }

    override fun getOperationsBundle(config: IosSigningKeyConfiguration): IosKeychainOperationsProvider.OperationsBundle? =
        when (val algSpecific = DSL.options(config.ec, config.rsa)) {
            is PlatformSigningKeyConfigurationBase.ECConfiguration -> if (algSpecific.curve.isBuiltIn) ECDSAOps(algSpecific) else null
            is PlatformSigningKeyConfigurationBase.RSAConfiguration -> RSAOps(algSpecific)
            else -> null
        }

    override fun makeIosSigner(alias: String, publicKey: PublicKey, metadata: IosKeyMetadata, config: IosSignerConfiguration): IosSigner? =
        when (publicKey) {
            is EcdsaPublicKey -> if (publicKey.curve.isBuiltIn) IosSigner.ECDSA(alias, publicKey, metadata, config) else null
            is RsaPublicKey -> IosSigner.RSA(alias, publicKey, metadata, config)
            else -> null
        }
}

/**
 * Signing provider backed by the iOS Keychain.
 *
 * RSA-PSS supports only MGF1 using the signature digest, a salt length equal to the digest output length, and trailer
 * field `1`, as required by the iOS Security framework.
 */
@OptIn(ExperimentalForeignApi::class)
object IosKeychainProvider: PlatformSigningProviderI<IosSigner, IosSignerConfiguration, IosSigningKeyConfiguration> {
    private val aliasMutationMutex = Mutex()

    private fun opaqueRecordExists(alias: String): Boolean = memScoped {
        val result = alloc<CFTypeRefVar>()
        when (val status = SecItemCopyMatching(createCFDictionary {
            kSecClass mapsTo kSecClassGenericPassword
            kSecAttrService mapsTo OpaqueAliasNamespace.SERVICE
            kSecAttrAccount mapsTo alias
            kSecReturnAttributes mapsTo true
            kSecMatchLimit mapsTo kSecMatchLimitOne
        }, result.ptr)) {
            errSecSuccess -> { result.value?.let { CFRelease(it) }; true }
            errSecItemNotFound -> false
            else -> throw CFCryptoOperationFailed("check opaque alias record", status)
        }
    }

    private fun readOpaqueRecord(alias: String): OpaqueIosAliasRecord? = memScoped {
        val result = alloc<CFTypeRefVar>()
        val status = SecItemCopyMatching(createCFDictionary {
            kSecClass mapsTo kSecClassGenericPassword
            kSecAttrService mapsTo OpaqueAliasNamespace.SERVICE
            kSecAttrAccount mapsTo alias
            kSecReturnData mapsTo true
            kSecMatchLimit mapsTo kSecMatchLimitOne
        }, result.ptr)
        when (status) {
            errSecItemNotFound -> null
            errSecSuccess -> {
                val data = result.value?.takeFromCF<NSData>() ?: error("Opaque alias record had no data")
                val decoded = try {
                    Json.decodeFromString<OpaqueIosAliasRecord>(data.toByteArray().decodeToString())
                } catch (_: kotlinx.serialization.SerializationException) {
                    throw UnsupportedCryptoException("Opaque iOS alias record is malformed")
                }
                decoded.also { record ->
                    require(record.version == 1) { "Unsupported opaque alias record version ${record.version}" }
                    validateOpaqueBackendId(record.backendId)
                    require(record.recordId.isNotBlank() && record.representationVersion > 0) { "Invalid opaque alias record identity/version" }
                }
            }
            else -> throw CFCryptoOperationFailed("retrieve opaque alias record", status)
        }
    }

    private fun hasSecKeyAlias(alias: String): Boolean = memScoped {
        if (getPublicKey(alias) != null) return@memScoped true
        KeychainTags.PRIVATE_KEYS.any { tag ->
            val result = alloc<CFTypeRefVar>()
            when (val status = SecItemCopyMatching(createCFDictionary {
                kSecClass mapsTo kSecClassKey
                kSecAttrKeyClass mapsTo kSecAttrKeyClassPrivate
                kSecAttrApplicationLabel mapsTo alias
                kSecAttrApplicationTag mapsTo tag
                kSecReturnAttributes mapsTo true
                kSecMatchLimit mapsTo kSecMatchLimitOne
            }, result.ptr)) {
                errSecSuccess -> { result.value?.let { CFRelease(it) }; true }
                errSecItemNotFound -> false
                else -> throw CFCryptoOperationFailed("check private key alias", status)
            }
        }
    }

    private fun generatedSecKeyReference(alias: String, keyClass: CFStringRef?, tag: String): NSData = memScoped {
        val result = alloc<CFTypeRefVar>()
        val status = SecItemCopyMatching(createCFDictionary {
            kSecClass mapsTo kSecClassKey
            kSecAttrKeyClass mapsTo keyClass
            kSecAttrApplicationLabel mapsTo alias
            kSecAttrApplicationTag mapsTo tag
            kSecReturnPersistentRef mapsTo true
        }, result.ptr)
        if (status != errSecSuccess) throw CFCryptoOperationFailed("identify generated SecKey", status)
        result.value.takeFromCF<NSData>()
    }

    private fun deleteSecKeyByReference(reference: NSData) = memScoped {
        val status = SecItemDelete(createCFDictionary { kSecValuePersistentRef mapsTo reference })
        if (status != errSecSuccess && status != errSecItemNotFound)
            throw CFCryptoOperationFailed("rollback generated SecKey", status)
    }

    private fun accessAvailability(config: IosSecureEnclaveConfiguration): CFStringRef? = when (config.availability) {
        IosSecureEnclaveConfiguration.Availability.ALWAYS -> if (config.allowBackup) kSecAttrAccessibleAlways else kSecAttrAccessibleAlwaysThisDeviceOnly
        IosSecureEnclaveConfiguration.Availability.AFTER_FIRST_UNLOCK -> if (config.allowBackup) kSecAttrAccessibleAfterFirstUnlock else kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        IosSecureEnclaveConfiguration.Availability.WHILE_UNLOCKED -> if (config.allowBackup) kSecAttrAccessibleWhenUnlocked else kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    }

    private fun resolvedAccessControl(
        config: IosSigningKeyConfiguration, secureEnclave: Boolean, checkAvailableFactors: Boolean = false,
    ): SecAccessControlRef {
        val hardware = config.hardware.v
        val factors = hardware.protection.v?.factors?.v
        if (factors != null && checkAvailableFactors) {
            val context = LAContext()
            val canBiometry = if (factors.biometry) context.canEvaluatePolicy(LAPolicyDeviceOwnerAuthenticationWithBiometrics, null) else false
            val canDeviceLock = if (factors.deviceLock) context.canEvaluatePolicy(LAPolicyDeviceOwnerAuthentication, null) else false
            if (!canBiometry && !canDeviceLock)
                throw UnsupportedCryptoException("None of the requested iOS authentication factors is available")
        }
        val flags = when {
            factors == null -> 0uL
            factors.biometry && factors.deviceLock -> kSecAccessControlUserPresence
            factors.biometry -> if (factors.biometryWithNewFactors) kSecAccessControlBiometryAny else kSecAccessControlBiometryCurrentSet
            factors.deviceLock -> kSecAccessControlDevicePasscode
            else -> 0uL
        }.let { if (secureEnclave) it or kSecAccessControlPrivateKeyUsage else it }
        return corecall { SecAccessControlCreateWithFlags(null, accessAvailability(hardware), flags, error) }
    }

    private fun addOpaqueRecord(alias: String, record: OpaqueIosAliasRecord, config: IosSigningKeyConfiguration) = memScoped {
        val bytes = Json.encodeToString(record).encodeToByteArray().toNSData()
        val status = SecItemAdd(createCFDictionary {
            kSecClass mapsTo kSecClassGenericPassword
            kSecAttrService mapsTo OpaqueAliasNamespace.SERVICE
            kSecAttrAccount mapsTo alias
            kSecAttrAccessible mapsTo accessAvailability(config.hardware.v)
            kSecValueData mapsTo bytes.giveToCF()
        }, null)
        when (status) {
            errSecSuccess -> Unit
            errSecDuplicateItem -> throw NoSuchElementException("Key with alias $alias already exists")
            else -> throw CFCryptoOperationFailed("store opaque alias record", status)
        }
    }

    private fun deleteOpaqueRecord(alias: String) = memScoped {
        val status = SecItemDelete(createCFDictionary {
            kSecClass mapsTo kSecClassGenericPassword
            kSecAttrService mapsTo OpaqueAliasNamespace.SERVICE
            kSecAttrAccount mapsTo alias
        })
        if (status != errSecSuccess && status != errSecItemNotFound)
            throw CFCryptoOperationFailed("delete opaque alias record", status)
    }

    internal suspend fun <T> withCurrentOpaqueRecord(
        alias: String, expectedRecordId: String, operation: suspend (OpaqueIosAliasRecord) -> T,
    ): T = aliasMutationMutex.withLock {
        withContext(dispatcher) {
            val record = readOpaqueRecord(alias)
            require(record?.recordId == expectedRecordId) { "Opaque key alias '$alias' changed after signer lookup" }
            operation(checkNotNull(record))
        }
    }

    private fun backendForId(id: String): OpaqueIosKeyBackend? {
        val matches = ServiceLoader.load<IosKeychainOperationsProvider>().mapNotNull { provider ->
            provider.opaqueKeyBackend?.takeIf { it.backendId == id }
        }.toList()
        check(matches.size <= 1) { "Opaque backend ID '$id' is registered more than once" }
        return matches.singleOrNull()
    }

    context (scope: MemScope)
    private fun getPublicKey(alias: String): OwnedCFValue<SecKeyRef>? {
        // try the new bundle-id-free tag first, then fall back to the legacy bundle-id-scoped tag
        KeychainTags.PUBLIC_KEYS.forEach { tag ->
            val it = scope.alloc<SecKeyRefVar>()
            val query = createCFDictionary {
                kSecClass mapsTo kSecClassKey
                kSecAttrKeyClass mapsTo kSecAttrKeyClassPublic
                kSecAttrApplicationLabel mapsTo alias
                kSecAttrApplicationTag mapsTo tag
                kSecReturnRef mapsTo true
            }
            when (val status = SecItemCopyMatching(query, it.ptr.reinterpret())) {
                errSecSuccess -> { require (it.value != null); return it.value!!.adopt() }
                errSecItemNotFound -> {/* fall through */}
                else -> throw CFCryptoOperationFailed(thing = "retrieve public key", osStatus = status)
            }
        }
        return null
    }

    /** Stores metadata on the freshly created public key, which always carries the new tag. */
    private fun storeKeyMetadata(alias: String, metadata: IosKeyMetadata) = memScoped {
        val status = SecItemUpdate(
            cfDictionaryOf(
                kSecClass to kSecClassKey,
                kSecAttrKeyClass to kSecAttrKeyClassPublic,
                kSecAttrApplicationLabel to alias,
                kSecAttrApplicationTag to KeychainTags.NEW_PUBLIC_KEYS
            ),
            cfDictionaryOf(
                kSecAttrLabel to Json.encodeToString(metadata)
            ))
        if (status != errSecSuccess) {
            throw CFCryptoOperationFailed(thing = "store key metadata", osStatus = status)
        }
    }

    private fun getKeyMetadata(alias: String): IosKeyMetadata = memScoped {
        // try the new bundle-id-free tag first, then fall back to the legacy bundle-id-scoped tag
        KeychainTags.PUBLIC_KEYS.forEach { tag ->
            val dict = alloc<CFDictionaryRefVar>()
            val query = createCFDictionary {
                kSecClass mapsTo kSecClassKey
                kSecAttrKeyClass mapsTo kSecAttrKeyClassPublic
                kSecAttrApplicationLabel mapsTo alias
                kSecAttrApplicationTag mapsTo tag
                kSecReturnAttributes mapsTo true
            }
            when (val status = SecItemCopyMatching(query, dict.ptr.reinterpret())) {
                errSecSuccess -> return dict.value!!.getAndTake<String>(kSecAttrLabel).let { Json.decodeFromString<IosKeyMetadata>(it) }
                    .also { _ -> CFRelease(dict.value) }
                errSecItemNotFound -> {/* fall through */}
                else -> throw CFCryptoOperationFailed(thing = "retrieve key metadata", osStatus = status)
            }
        }
        throw CFCryptoOperationFailed(thing = "retrieve key metadata", osStatus = errSecItemNotFound)
    }

    private suspend fun getSignerInternal(alias: String, publicKey: PublicKey, metadata: IosKeyMetadata, config: IosSignerConfiguration): IosSigner =
        ServiceLoader.load<IosKeychainOperationsProvider>()
            .get(publicKey) { makeIosSigner(alias, it, metadata, config) }

    override suspend fun createSigningKey(
        alias: String,
        configure: DSLConfigureFn<IosSigningKeyConfiguration>
    ): IosSigner = aliasMutationMutex.withLock { withContext(dispatcher) {
        memScoped {
            // also catches legacy bundle-id-tagged keys, so we never shadow an existing key
            if (hasSecKeyAlias(alias) || opaqueRecordExists(alias))
                throw NoSuchElementException("Key with alias $alias already exists")
        }

        val config: IosSigningKeyConfiguration = DSL.resolve(::IosSigningKeyConfiguration, configure)

        val choice = memScoped {
            ServiceLoader.load<IosKeychainOperationsProvider>().get(alias) {
                val opaque = opaqueKeyBackend?.takeIf { it.supports(config) }
                if (opaque != null) IosKeyBackendChoice.Opaque(opaque)
                else makeKeyAttributes(alias, config)?.let { attributes ->
                    CFRetain(attributes.first)
                    IosKeyBackendChoice.SecKey(attributes)
                }
            }
        }
        try {
            when (choice) {
                is IosKeyBackendChoice.Opaque -> createOpaqueSigner(alias, choice.backend, config)
                is IosKeyBackendChoice.SecKey -> createSecKeySigner(alias, choice.attributes, config)
            }
        } finally {
            if (choice is IosKeyBackendChoice.SecKey) CFRelease(choice.attributes.first)
        }
    } }

    private suspend fun createOpaqueSigner(
        alias: String, backend: OpaqueIosKeyBackend, config: IosSigningKeyConfiguration,
    ): IosSigner {
        validateOpaqueBackendId(backend.backendId)
        check(backendForId(backend.backendId) != null) { "Selected opaque iOS backend is unavailable" }
        if (config.hardware.v.backing == DISCOURAGED)
            throw UnsupportedCryptoException("Opaque iOS backends require Secure Enclave backing; backing = DISCOURAGED is incompatible")

        val accessControl = resolvedAccessControl(config, secureEnclave = true, checkAvailableFactors = true)
        val material = try { backend.generate(config, accessControl) } finally { CFRelease(accessControl) }
        val attestation = createAppAttestBinding(alias, material.publicKey, config, usedSecureEnclave = true)
        val metadata = IosKeyMetadata(
            attestation = attestation,
            rawUnlockTimeout = config.hardware.v.protection.v?.timeout,
            algSpecific = null,
            allowSigning = material.allowSigning,
            allowKeyAgreement = false,
            allowDecryption = false,
        )
        val record = createOpaqueAliasRecord(backend.backendId, material, metadata)
        val signerConfiguration = DSL.resolve(::IosSignerConfiguration, config.signer.v)
        // Resolve all fallible signer binding before the alias record becomes visible.
        val signer = IosSigner.Opaque(alias, material.publicKey, record.recordId, metadata, backend, signerConfiguration)
        if (hasSecKeyAlias(alias)) throw NoSuchElementException("Key with alias $alias already exists")
        currentCoroutineContext().ensureActive()
        addOpaqueRecord(alias, record, config)
        return signer
    }

    private suspend fun createSecKeySigner(
        alias: String, attributes: Pair<CFMutableDictionaryRef, JsonElement?>, config: IosSigningKeyConfiguration,
    ): IosSigner {
        val createdKeyReferences = mutableListOf<NSData>()
        fun rollbackSecKeys(failure: Throwable) {
            createdKeyReferences.forEach { reference ->
                try { deleteSecKeyByReference(reference) }
                catch (cleanup: Throwable) { failure.addSuppressed(cleanup.nonFatalOrThrow()) }
            }
            createdKeyReferences.clear()
        }
        try {
            lateinit var publicKey: PublicKey
            var usedSecureEnclave = false
            val attr = attributes.first
            val algSpecificMetadata = attributes.second
            val allowSigning: Boolean
            val allowDecryption: Boolean
            val allowKeyAgreement: Boolean
            memScoped {
                attr.get<CFDictionaryRef>(kSecPrivateKeyAttrs).value.let { privateAttrs ->
                    allowSigning = privateAttrs.getAndTake<Boolean?>(kSecAttrCanSign) ?: true
                    allowDecryption = privateAttrs.getAndTake<Boolean?>(kSecAttrCanDecrypt) ?: true
                    allowKeyAgreement = privateAttrs.getAndTake<Boolean?>(kSecAttrCanDerive) ?: true
                }

                data class KeyPair(val public: OwnedCFValue<SecKeyRef>, val private: OwnedCFValue<SecKeyRef>)
                fun generate(useSecureEnclave: Boolean): KeyPair {
                    if (useSecureEnclave) attr[kSecAttrTokenID] = kSecAttrTokenIDSecureEnclave
                    else CFDictionaryRemoveValue(attr, kSecAttrTokenID)
                    attr.get<CFMutableDictionaryRef>(kSecPrivateKeyAttrs).value[kSecAttrAccessControl] =
                        resolvedAccessControl(config, secureEnclave = useSecureEnclave).also { defer { CFRelease(it) } }

                    val pubkeyVar = alloc<SecKeyRefVar>()
                    val privkeyVar = alloc<SecKeyRefVar>()
                    val status = SecKeyGeneratePair(attr, pubkeyVar.ptr, privkeyVar.ptr)
                    val public = pubkeyVar.value?.adopt()
                    val private = privkeyVar.value?.adopt()
                    if (public != null) createdKeyReferences += generatedSecKeyReference(alias, kSecAttrKeyClassPublic, KeychainTags.NEW_PUBLIC_KEYS)
                    if (private != null) createdKeyReferences += generatedSecKeyReference(alias, kSecAttrKeyClassPrivate, KeychainTags.NEW_PRIVATE_KEYS)
                    if (status == errSecSuccess && public != null && private != null)
                        return KeyPair(public, private)
                    val failure = CFCryptoOperationFailed("generate key", status)
                    rollbackSecKeys(failure)
                    if (status == -50 && useSecureEnclave && failure.suppressedExceptions.isEmpty())
                        throw UnsupportedCryptoException("The iOS Secure Enclave does not support this configuration.", failure)
                    throw failure
                }

                val keyPair = when (config.hardware.v.backing) {
                    is REQUIRED -> generate(true)
                    is PREFERRED -> try { generate(true) } catch (failure: UnsupportedCryptoException) {
                        Napier.v("Secure Enclave generation failed with PREFERRED, falling back to without", failure)
                        generate(false)
                    }
                    is DISCOURAGED -> generate(false)
                }
                usedSecureEnclave = kSecAttrTokenIDSecureEnclave.toKotlinString() == corecall {
                    SecKeyCopyAttributes(keyPair.private.value).also { defer { CFRelease(it) } }
                }.getAndTake<String?>(kSecAttrTokenID)
                if (config.hardware.v.backing == REQUIRED)
                    require(usedSecureEnclave) { "Requested secure enclave key but received non-secure enclave key?" }
                publicKey = keyPair.public.value.toPublicKey()
            }

            val attestation = createAppAttestBinding(alias, publicKey, config, usedSecureEnclave)
            val metadata = IosKeyMetadata(
                attestation = attestation,
                rawUnlockTimeout = config.hardware.v.protection.v?.timeout,
                allowSigning = allowSigning,
                allowDecryption = allowDecryption,
                allowKeyAgreement = allowKeyAgreement,
                algSpecific = algSpecificMetadata,
            )
            currentCoroutineContext().ensureActive()
            storeKeyMetadata(alias, metadata)
            val signerConfiguration = DSL.resolve(::IosSignerConfiguration, config.signer.v)
            return getSignerInternal(alias, publicKey, metadata, signerConfiguration)
        } catch (failure: Throwable) {
            rollbackSecKeys(failure)
            throw failure
        }
    }

    private suspend fun createAppAttestBinding(
        alias: String, publicKey: PublicKey, config: IosSigningKeyConfiguration, usedSecureEnclave: Boolean,
    ): IosHomebrewAttestation? {
        if (!usedSecureEnclave) return null
        val attestationConfig = config.hardware.v.attestation.v ?: return null
        val service = DCAppAttestService.sharedService
        if (!service.isSupported()) {
            if (config.hardware.v.backing == REQUIRED) throw UnsupportedCryptoException("App Attestation is unavailable")
            Napier.v { "attestation is unsupported by the device" }
            return null
        }
        Napier.v { "going to create attestation for key $alias" }
        val keyId = swiftasync { service.generateKeyWithCompletionHandler(callback) }
        Napier.v { "created attestation key (keyId = $keyId)" }
        val (clientDataJSON, digest) = prepareAppAttestBinding(publicKey, attestationConfig.challenge)
        val statement = swiftasync { service.attestKey(keyId, digest.toNSData(), callback) }.toByteArray()
        Napier.v { "attested key (${statement.toHexString()})" }
        return IosHomebrewAttestation(attestation = statement, clientDataJSON = clientDataJSON)
    }

    override suspend fun getSignerForKey(
        alias: String,
        configure: DSLConfigureFn<IosSignerConfiguration>
    ): IosSigner = aliasMutationMutex.withLock { withContext(dispatcher) {
        val config = DSL.resolve(::IosSignerConfiguration, configure)
        val opaqueRecord = readOpaqueRecord(alias)
        if (opaqueRecord != null) {
            val secKeyAliasExists = hasSecKeyAlias(alias)
            check(!secKeyAliasExists) { "Alias '$alias' exists in both the opaque and SecKey stores" }
            val backend = backendForId(opaqueRecord.backendId)
                ?: throw UnsupportedCryptoException("Opaque iOS key backend '${opaqueRecord.backendId}' is unavailable; alias remains deletable")
            val publicKey = PublicKey.fromAsn1(opaqueRecord.publicKeySpki)
            return@withContext IosSigner.Opaque(
                alias, publicKey, opaqueRecord.recordId, opaqueRecord.metadata, backend, config)
        }
        val publicKey =
            memScoped {
                getPublicKey(alias)
                    ?: throw NoSuchElementException("No key for alias $alias exists")
            }.value.toPublicKey()
        val metadata = getKeyMetadata(alias)
        return@withContext getSignerInternal(alias, publicKey, metadata, config)
    } }

    override suspend fun deleteSigningKey(alias: String) = aliasMutationMutex.withLock { withContext(dispatcher) { deleteSigningKeyInternal(alias) } }

    private fun deleteSigningKeyInternal(alias: String) {
        deleteOpaqueRecord(alias)
        memScoped {
            // Deletes both the new bundle-id-free tag and the legacy bundle-id-scoped tag.
            listOf(
                Triple("public key", kSecAttrKeyClassPublic, KeychainTags.PUBLIC_KEYS),
                Triple("private key", kSecAttrKeyClassPrivate, KeychainTags.PRIVATE_KEYS)
            ).flatMap { (kind, keyClass, tags) ->
                tags.map { tag ->
                    val status = SecItemDelete(createCFDictionary {
                        kSecClass mapsTo kSecClassKey
                        kSecAttrKeyClass mapsTo keyClass
                        kSecAttrApplicationLabel mapsTo alias
                        kSecAttrApplicationTag mapsTo tag
                    })
                    if ((status != errSecSuccess) && (status != errSecItemNotFound))
                        CFCryptoOperationFailed(thing = "delete $kind", osStatus = status)
                    else
                        null
                }
            }.mapNotNull { it?.message }.let {
                if (it.isNotEmpty())
                    throw CryptoOperationFailed(it.joinToString(","))
            }
        }
    }
}

internal actual fun getPlatformSigningProvider(configure: DSLConfigureFn<PlatformSigningProviderConfigurationBase>): PlatformSigningProviderI<*,*,*> =
    IosKeychainProvider
