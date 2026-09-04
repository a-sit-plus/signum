@file:OptIn(ExperimentalForeignApi::class)
package at.asitplus.signum.supreme.os

import at.asitplus.awesn1.crypto.X509SignatureValue
import at.asitplus.nonFatalOrThrow
import at.asitplus.signum.CryptoOperationFailed
import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.dsl.*
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.agree.KeyAgreementPublicValue
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.digest.WellKnownDigest
import at.asitplus.signum.indispensable.digest.digest
import at.asitplus.signum.indispensable.sign.SignatureInput
import at.asitplus.signum.indispensable.sign.*
import at.asitplus.signum.internals.*
import at.asitplus.signum.supreme.CFCryptoOperationFailed
import at.asitplus.signum.supreme.swiftasync
import io.github.aakira.napier.Napier
import kotlinx.cinterop.*
import kotlinx.coroutines.*
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
import platform.LocalAuthentication.*
import platform.Security.*
import kotlin.math.min
import kotlin.time.Duration
import kotlin.time.TimeSource
import at.asitplus.signum.indispensable.sign.RSAAlgorithm.Padding as RSAPadding

@OptIn(DelicateCoroutinesApi::class)
private val dispatcher = Dispatchers.IO.limitedParallelism(1, "iOS Keychain Operations")

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
    val needsAuthentication get() = metadata.needsUnlock
    val needsAuthenticationForEveryUse get() = metadata.needsUnlock && (metadata.unlockTimeout == Duration.ZERO)
    override val attestation get() = metadata.attestation

    protected interface PrivateKeyManager { suspend fun get(operation: Long?, algorithm: SecKeyAlgorithm?, signingConfig: IosSignerSigningConfiguration): OwnedCFValue<SecKeyRef> }
    @HazardousMaterials
    /** For InternalsAccessor ONLY!!! */
    internal val DONOTUSEsecKeyRef get() = runBlocking { privateKeyManager.get(null, null, IosSignerSigningConfiguration()) }
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
                ctx.apply {
                    val stack = DSL.ConfigStack(signingConfig.unlockPrompt.v, signerConfig.unlockPrompt.v)
                    localizedReason = stack.getProperty(
                        UnlockPromptConfiguration::_message,
                        default = UnlockPromptConfiguration.defaultMessage)
                    localizedCancelTitle = stack.getProperty(
                        UnlockPromptConfiguration::_cancelText,
                        default = UnlockPromptConfiguration.defaultCancelText)
                }
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
        if (needsAuthentication && !needsAuthenticationForEveryUse) {
            val config = DSL.resolve(::IosSignerSigningConfiguration, configure)
            val _ = privateKeyManager.get(null, null, config)
        }
    }

    protected abstract fun bytesToSignature(sigBytes: ByteArray): CryptoSignature
    override suspend fun sign(data: SignatureInput, configure: DSLConfigureFn<IosSignerSigningConfiguration>): SignatureResult<*> =
    SignatureResult.make {
        require(data.format == null) { "Pre-hashed data is unsupported on iOS" }
        require(metadata.allowSigning) { "Signing key purpose not set! Signing disallowed!" }
        val signingConfig = DSL.resolve(::IosSignerSigningConfiguration, configure)
        val (algorithm, inputFormat) = signatureAlgorithm.suitableSecKeyAlgAndFormat
        val plaintext = data.convertTo(inputFormat).collapsed().data.single().toNSData()
        val signatureBytes = try {
            val key = privateKeyManager.get(kSecKeyOperationTypeSign, algorithm, signingConfig).value
            corecall {
                SecKeyCreateSignature(key, algorithm, plaintext.giveToCF(), error)
            }.takeFromCF<NSData>().toByteArray()
        } catch (x: CoreFoundationException) { /* secure enclave failure */
            if (x.nsError.domain == LAErrorDomain) when (x.nsError.code) {
                LAErrorUserCancel, LAErrorAuthenticationFailed, LAErrorBiometryLockout -> throw UnlockFailed(x.nsError.localizedDescription, x)
                else -> throw x
            } else throw x
        } catch (x: CFCryptoOperationFailed) { /* keychain failure */
            when (x.osStatus) {
                errSecUserCanceled, errSecAuthFailed -> throw UnlockFailed(x.message, x)
                else -> throw x
            }
        }
        return@make bytesToSignature(signatureBytes)
    }

    class ECDSA internal constructor
        (alias: String, override val publicKey: ECDSAPublicKey, metadata: IosKeyMetadata, config: IosSignerConfiguration)
        : IosSigner(alias, metadata, config),
            PlatformSigningProviderSigner.ECDSA<IosSignerSigningConfiguration, IosHomebrewAttestation>
    {
        override val signatureAlgorithm: ECDSAAlgorithm
        init {
            val algMetadata = Json.decodeFromJsonElement<IosKeyAlgSpecificMetadata.ECDSA>(metadata.algSpecific!!)
            signatureAlgorithm = when (
                val digest = resolveOption("digest", algMetadata.supportedDigests, config.ec.v.digestSpecified, { config.ec.v.digest })
            ){
                Digest.SHA256, Digest.SHA384, Digest.SHA512 -> ECDSAAlgorithm(digest, publicKey.curve)
                else -> throw UnsupportedCryptoException("ECDSA with $digest is not supported on iOS")
            }
        }
        override fun bytesToSignature(sigBytes: ByteArray) =
            ECDSASignature.decodeFromTlv(X509SignatureValue(sigBytes)).withCurve(publicKey.curve)

        override suspend fun keyAgreement(
            publicValue: KeyAgreementPublicValue.ECDH,
            configure: DSLConfigureFn<IosSignerSigningConfiguration>
        ): ByteArray {
            require(metadata.allowKeyAgreement) { "Key agreement purpose not set! Key agreement disallowed!" }
            val config = DSL.resolve(::IosSignerSigningConfiguration, configure)
            val key = privateKeyManager.get(kSecKeyOperationTypeKeyExchange, kSecKeyAlgorithmECDHKeyExchangeStandard, config).value
            return corecall {
                SecKeyCopyKeyExchangeResult(
                    key,
                    kSecKeyAlgorithmECDHKeyExchangeStandard,
                    publicValue.asCryptoPublicKey().toSecKey().value,
                    parameters = null,
                    error
                )
            }.takeFromCF<NSData>().toByteArray()
        }
    }

    class RSA internal constructor
        (alias: String, override val publicKey: RSAPublicKey, metadata: IosKeyMetadata, config: IosSignerConfiguration)
        : IosSigner(alias, metadata, config), at.asitplus.signum.indispensable.sign.RSASigner
    {
        override val signatureAlgorithm: RSAAlgorithm
        init {
            val algMetadata = Json.decodeFromJsonElement<IosKeyAlgSpecificMetadata.RSA>(metadata.algSpecific!!)

            signatureAlgorithm = RSAAlgorithm(
                digest = resolveOption("digest", algMetadata.supportedDigests, config.rsa.v.digestSpecified, { config.rsa.v.digest }),
                padding = resolveOption("padding", algMetadata.supportedPaddings, config.rsa.v.paddingSpecified, { config.rsa.v.padding })
            )
        }
        override fun bytesToSignature(sigBytes: ByteArray) =
            RSASignature.decodeFromTlv(X509SignatureValue(sigBytes))
    }

}

interface IosKeyAlgSpecificMetadata {
    @Serializable
    @SerialName("ecdsa")
    data class ECDSA(
        val supportedDigests: Set<WellKnownDigest?>
    ) : IosKeyAlgSpecificMetadata

    @Serializable
    @SerialName("rsa")
    data class RSA(
        val supportedDigests: Set<WellKnownDigest>,
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

    fun makeIosSigner(alias: String, publicKey: CryptoPublicKey, metadata: IosKeyMetadata, config: IosSignerConfiguration): IosSigner?
}

object SupremeIosKeychainOperationsProvider: IosKeychainOperationsProvider {
    private class ECDSAOps(val config: PlatformSigningKeyConfigurationBase.ECConfiguration) : IosKeychainOperationsProvider.OperationsBundle {
        override fun CFDictionaryInitScope.initTopLevelDictionary() {
            kSecAttrKeyType mapsTo kSecAttrKeyTypeEC
            kSecAttrKeySizeInBits mapsTo config.curve.coordinateLength.bits.toInt()
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
            is PlatformSigningKeyConfigurationBase.ECConfiguration -> ECDSAOps(algSpecific)
            is PlatformSigningKeyConfigurationBase.RSAConfiguration -> RSAOps(algSpecific)
            else -> null
        }

    override fun makeIosSigner(alias: String, publicKey: CryptoPublicKey, metadata: IosKeyMetadata, config: IosSignerConfiguration): IosSigner? =
        when (publicKey) {
            is ECDSAPublicKey -> IosSigner.ECDSA(alias, publicKey, metadata, config)
            is RSAPublicKey -> IosSigner.RSA(alias, publicKey, metadata, config)
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

    private suspend fun getSignerInternal(alias: String, publicKey: CryptoPublicKey, metadata: IosKeyMetadata, config: IosSignerConfiguration): IosSigner =
        ServiceLoader.load<IosKeychainOperationsProvider>()
            .get(publicKey) { makeIosSigner(alias, it, metadata, config) }

    override suspend fun createSigningKey(
        alias: String,
        configure: DSLConfigureFn<IosSigningKeyConfiguration>
    ): IosSigner = withContext(dispatcher) {
        memScoped {
            // also catches legacy bundle-id-tagged keys, so we never shadow an existing key
            if (getPublicKey(alias) != null)
                throw NoSuchElementException("Key with alias $alias already exists")
        }

        // ok, the key does not exist, create it
        try {
            deleteSigningKey(alias) /* make sure there are no leftover private keys */

            val config: IosSigningKeyConfiguration = DSL.resolve(::IosSigningKeyConfiguration, configure)
            val usedSecureEnclave: Boolean
            val publicKey: CryptoPublicKey
            val allowKeyAgreement: Boolean
            val allowDecryption: Boolean
            val allowSigning: Boolean
            val algSpecificMetadata: JsonElement?
            memScoped {
                val attr: CFMutableDictionaryRef
                ServiceLoader.load<IosKeychainOperationsProvider>()
                    .get(alias) { makeKeyAttributes(it, config) }
                    .let { attr = it.first; algSpecificMetadata = it.second }

                attr.get<CFDictionaryRef>(kSecPrivateKeyAttrs).value.let { privateAttrs ->
                    allowSigning = privateAttrs.getAndTake<Boolean?>(kSecAttrCanSign) ?: true
                    allowDecryption = privateAttrs.getAndTake<Boolean?>(kSecAttrCanDecrypt) ?: true
                    allowKeyAgreement = privateAttrs.getAndTake<Boolean?>(kSecAttrCanDerive) ?: true
                }

                val availability = config.hardware.v.let { c -> when (c.availability) {
                    IosSecureEnclaveConfiguration.Availability.ALWAYS -> if (c.allowBackup) kSecAttrAccessibleAlways else kSecAttrAccessibleAlwaysThisDeviceOnly
                    IosSecureEnclaveConfiguration.Availability.AFTER_FIRST_UNLOCK -> if (c.allowBackup) kSecAttrAccessibleAfterFirstUnlock else kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
                    IosSecureEnclaveConfiguration.Availability.WHILE_UNLOCKED -> if (c.allowBackup) kSecAttrAccessibleWhenUnlocked else kSecAttrAccessibleWhenUnlockedThisDeviceOnly
                } }
                data class KeyPair(val public: OwnedCFValue<SecKeyRef>, val private: OwnedCFValue<SecKeyRef>)
                fun generate(useSecureEnclave: Boolean): KeyPair {
                    if (useSecureEnclave)
                        attr[kSecAttrTokenID] = kSecAttrTokenIDSecureEnclave
                    else
                        CFDictionaryRemoveValue(attr, kSecAttrTokenID)

                    val factors = config.hardware.v.protection.v?.factors?.v
                    attr.get<CFMutableDictionaryRef>(kSecPrivateKeyAttrs).value[kSecAttrAccessControl] = corecall {
                        SecAccessControlCreateWithFlags(
                            null, availability,
                            when {
                                (factors == null) -> 0uL
                                (factors.biometry && factors.deviceLock) -> kSecAccessControlUserPresence
                                factors.biometry -> if (factors.biometryWithNewFactors) kSecAccessControlBiometryAny else kSecAccessControlBiometryCurrentSet
                                factors.deviceLock -> kSecAccessControlDevicePasscode
                                else -> 0uL
                            }.let {
                                if (useSecureEnclave) (it or kSecAccessControlPrivateKeyUsage) else it
                            }, error)
                    }.also { defer { CFRelease(it) } }

                    memScoped {
                        Napier.v { "Ready to generate iOS keypair for alias $alias (secure enclave? $useSecureEnclave)" }
                        val pubkeyVar = alloc<SecKeyRefVar>()
                        val privkeyVar = alloc<SecKeyRefVar>()
                        val status = SecKeyGeneratePair(attr, pubkeyVar.ptr, privkeyVar.ptr)
                        val pubkey = pubkeyVar.value
                        val privkey = privkeyVar.value

                        if ((status == errSecSuccess) && (pubkey != null) && (privkey != null)) {
                            Napier.v { "Successfully generated iOS keypair for alias $alias (secure enclave? $useSecureEnclave)" }
                            return KeyPair(public = pubkey.adopt(), private = privkey.adopt())
                        } else {
                            if (pubkey != null) CFRelease(pubkey)
                            if (privkey != null) CFRelease(privkey)
                            val x = CFCryptoOperationFailed(thing = "generate key", osStatus = status)
                            if ((status == -50) && useSecureEnclave)
                            {
                                throw UnsupportedCryptoException("The iOS Secure Enclave does not support this configuration.", x)
                            }
                            throw x
                        }
                    }
                }

                val keyPair = when (config.hardware.v.backing) {
                    is REQUIRED -> generate(true)
                    is PREFERRED -> try {
                        generate(true)
                    } catch (x: UnsupportedCryptoException) {
                        Napier.v("Secure Enclave generation failed with PREFERRED, falling back to without", x)
                        generate(false)
                    }
                    is DISCOURAGED -> generate(false)
                }
                usedSecureEnclave = kSecAttrTokenIDSecureEnclave.toKotlinString() == corecall {
                    SecKeyCopyAttributes(keyPair.private.value).also { defer { CFRelease(it) } }
                }.getAndTake<String?>(kSecAttrTokenID)

                if (config.hardware.v.backing == REQUIRED)
                    require(usedSecureEnclave) { "Requested secure enclave key but received non-secure enclave key?" }

                publicKey = keyPair.public.value.toCryptoPublicKey()
            }

            val attestation = if (usedSecureEnclave) {
                config.hardware.v.attestation.v?.let { attestationConfig ->
                    val service = DCAppAttestService.sharedService
                    if (!service.isSupported()) {
                        if (config.hardware.v.backing == REQUIRED) {
                            throw UnsupportedCryptoException("App Attestation is unavailable")
                        }
                        Napier.v { "attestation is unsupported by the device" }
                        return@let null
                    }
                    Napier.v { "going to create attestation for key $alias" }
                    val keyId = swiftasync {
                        service.generateKeyWithCompletionHandler(callback)
                    }
                    Napier.v { "created attestation key (keyId = $keyId)" }

                    val clientData = IosHomebrewAttestation.ClientData(
                        publicKey = publicKey, challenge = attestationConfig.challenge)
                    val clientDataJSON = clientData.prepareDigestInput()

                    val digest = WellKnownDigest.SHA256.digest(clientDataJSON)
                    val assertionKeyAttestation = swiftasync {
                        service.attestKey(keyId, digest.toNSData(), callback)
                    }.toByteArray()
                    Napier.v { "attested key (${assertionKeyAttestation.toHexString()})" }

                    return@let IosHomebrewAttestation(
                        attestation = assertionKeyAttestation,
                        clientDataJSON = clientDataJSON)
                }
            } else null

            val metadata = IosKeyMetadata(
                attestation = attestation,
                rawUnlockTimeout = config.hardware.v.protection.v?.timeout,
                allowSigning = allowSigning,
                allowDecryption = allowDecryption,
                allowKeyAgreement = allowKeyAgreement,
                algSpecific = algSpecificMetadata
            ).also { storeKeyMetadata(alias, metadata = it) }

            Napier.v { "key $alias metadata stored (has attestation? ${attestation != null})" }

            val signerConfiguration = DSL.resolve(::IosSignerConfiguration, config.signer.v)
            return@withContext getSignerInternal(alias, publicKey, metadata, signerConfiguration)
        } catch (e: Throwable) {
            // get rid of any "partial" keys
            try { deleteSigningKey(alias) } catch (x: Throwable) { e.addSuppressed(x.nonFatalOrThrow()) }
            throw e
        }
    }

    override suspend fun getSignerForKey(
        alias: String,
        configure: DSLConfigureFn<IosSignerConfiguration>
    ): IosSigner = withContext(dispatcher) {
        val config = DSL.resolve(::IosSignerConfiguration, configure)
        val publicKey =
            memScoped {
                getPublicKey(alias)
                    ?: throw NoSuchElementException("No key for alias $alias exists")
            }.value.toCryptoPublicKey()
        val metadata = getKeyMetadata(alias)
        return@withContext getSignerInternal(alias, publicKey, metadata, config)
    }

    override suspend fun deleteSigningKey(alias: String) = withContext(dispatcher) {
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
