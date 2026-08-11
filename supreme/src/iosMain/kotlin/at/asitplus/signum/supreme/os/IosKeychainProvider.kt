@file:OptIn(ExperimentalForeignApi::class)
package at.asitplus.signum.supreme.os

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.nonFatalOrThrow
import at.asitplus.signum.indispensable.sign.RSAAlgorithm.Padding as RSAPadding
import at.asitplus.signum.CryptoOperationFailed
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.dsl.PlatformSignerConfigurationBase
import at.asitplus.signum.dsl.PlatformSigningKeyConfigurationBase
import at.asitplus.signum.dsl.PlatformSigningProviderConfigurationBase
import at.asitplus.signum.dsl.PlatformSigningProviderSignerSigningConfigurationBase
import at.asitplus.signum.dsl.SigningKeyConfiguration
import at.asitplus.signum.dsl.UnlockPromptConfiguration
import at.asitplus.signum.dsl._algSpecific
import at.asitplus.signum.dsl.attestation
import at.asitplus.signum.dsl.ec
import at.asitplus.signum.dsl.factors
import at.asitplus.signum.dsl.protection
import at.asitplus.signum.dsl.rsa
import at.asitplus.signum.dsl.signer
import at.asitplus.signum.dsl.unlockPrompt
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.digest.digest
import at.asitplus.signum.indispensable.integrity.SignatureAlgorithm
import at.asitplus.signum.internals.*
import at.asitplus.signum.supreme.*
import at.asitplus.signum.supreme.dsl.*
import at.asitplus.signum.supreme.sign.*
import io.github.aakira.napier.Napier
import kotlinx.cinterop.*
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import platform.CoreFoundation.CFDictionaryRefVar
import platform.CoreFoundation.CFRelease
import platform.DeviceCheck.DCAppAttestService
import platform.Foundation.NSBundle
import platform.Foundation.NSData
import platform.LocalAuthentication.*
import platform.Security.*
import kotlin.math.min
import kotlin.time.Duration
import kotlin.time.TimeSource

@OptIn(DelicateCoroutinesApi::class)
private val dispatcher = Dispatchers.IO.limitedParallelism(1, "iOS Keychain Operations")

private fun isSecureEnclaveSupportedConfiguration(c: SigningKeyConfiguration.AlgorithmSpecific): Boolean {
    if (c !is SigningKeyConfiguration.ECConfiguration) return false
    return when (c.curve) {
        ECCurve.SECP_256_R_1 -> true
        else -> false
    }
}

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

class IosSecureEnclaveConfiguration internal constructor() : PlatformSigningKeyConfigurationBase.SecureHardwareConfiguration() {
    /** Set to true to allow this key to be backed up. */
    var allowBackup = false
    enum class Availability { ALWAYS, AFTER_FIRST_UNLOCK, WHILE_UNLOCKED }
    /** Specify when this key should be available */
    var availability = Availability.ALWAYS
}
class IosSigningKeyConfiguration internal constructor(): PlatformSigningKeyConfigurationBase<IosSignerConfiguration>() {
    override val hardware = childOrDefault(::IosSecureEnclaveConfiguration) {
        backing = DISCOURAGED
    }
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

class IosSignerConfiguration internal constructor(): PlatformSignerConfigurationBase()

private object LAContextStorage {
    data class SuccessfulAuthentication(
        val authnContext: LAContext, val authnTime: TimeSource.Monotonic.ValueTimeMark)
    var successfulAuthentication: SuccessfulAuthentication? = null
}

typealias IosSignerSigningConfiguration = PlatformSigningProviderSignerSigningConfigurationBase
/**
 * A signer backed by an iOS Keychain key.
 *
 * RSA-PSS supports only MGF1 using the signature digest, a salt length equal to the digest output length, and trailer
 * field `1`, as required by the iOS Security framework.
 */
sealed class IosSigner(final override val alias: String,
                       internal/*cannot be protected, as IosKeyMetadata is internal*/ val metadata: IosKeyMetadata,
                       private val signerConfig: IosSignerConfiguration)
    : PlatformSigningProviderSigner<IosSignerSigningConfiguration, IosHomebrewAttestation> {


    @SecretExposure
    override suspend fun exportPrivateKey(): KmmResult<Nothing> = KmmResult.failure(IllegalStateException("Non-Exportable key"))

    override val mayRequireUserUnlock get() = needsAuthentication
    val needsAuthentication get() = metadata.needsUnlock
    val needsAuthenticationForEveryUse get() = metadata.needsUnlock && (metadata.unlockTimeout == Duration.ZERO)
    override val attestation get() = metadata.attestation

    internal interface PrivateKeyManager { fun get(signingConfig: IosSignerSigningConfiguration): AutofreeVariable<SecKeyRef> }
    internal val privateKeyManager = object : PrivateKeyManager {
        private var storedKey: AutofreeVariable<SecKeyRef>? = null
        override fun get(signingConfig: IosSignerSigningConfiguration): AutofreeVariable<SecKeyRef> {
            Napier.v { "Private Key access for alias $alias requested (needs unlock? ${metadata.needsUnlock}; timeout? ${metadata.unlockTimeout})" }

            val ctx: LAContext? /* the LAContext (potentially old if the timeout permits) to use */
            val recordable: Boolean /* whether this is a new context, which will prompt for actual authentication */
            if (metadata.needsUnlock) {
                val previousAuthn = if (metadata.unlockTimeout != Duration.ZERO) LAContextStorage.successfulAuthentication else null
                if ((previousAuthn != null) && (previousAuthn.authnTime.elapsedNow() < metadata.unlockTimeout)) {
                    // if we are allowed to reuse the key, and we have the key, then reuse the key
                    storedKey?.let {
                        Napier.v { "Re-using cached private key reference for alias $alias" }
                        return it
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
            val newPrivateKey = AutofreeVariable<SecKeyRef>()
            memScoped {
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
                    when (val lastStatus = SecItemCopyMatching(query, newPrivateKey.ptr.reinterpret())) {
                        errSecSuccess -> { require(newPrivateKey.value != null); return@memScoped }
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
            if (!SecKeyIsAlgorithmSupported(newPrivateKey.value, kSecKeyOperationTypeSign, signatureAlgorithm.secKeyAlgorithmPreHashed)) {
                throw UnsupportedCryptoException("Requested operation is not supported by this key")
            }

            if (recordable && (ctx != null)) {
                Napier.v { "Going to record successful LAContext after retrieving key $alias" }
                // record the successful unlock timestamp and LAContext for reuse
                // produce a dummy signature to ensure that the unlock has succeeded; this is required by secure enclave keys, which do not prompt for unlock until signing time
                corecall { SecKeyCreateSignature(newPrivateKey.value, signatureAlgorithm.secKeyAlgorithmPreHashed,
                    ByteArray(signatureAlgorithm.preHashedSignatureFormat!!.outputLength.bytes.toInt()).toNSData().let(::giveToCF), error)?.let(::CFRelease) }

                // if we have reached this point, the unlock operation has definitively succeeded
                LAContextStorage.successfulAuthentication = LAContextStorage.SuccessfulAuthentication(
                    authnContext = ctx, authnTime = TimeSource.Monotonic.markNow())
                Napier.v { "Successfully recorded LAContext for future re-use" }
            }
            if (!needsAuthenticationForEveryUse) {
                storedKey = newPrivateKey
            }
            return newPrivateKey
        }
    }

    final override suspend fun trySetupUninterruptedSigning(configure: DSLConfigureFn<IosSignerSigningConfiguration>): KmmResult<Unit> =
    withContext(dispatcher) { catching {
        if (needsAuthentication && !needsAuthenticationForEveryUse) {
            val config = DSL.resolve(::IosSignerSigningConfiguration, configure)
            privateKeyManager.get(config)
        }
    } }

    protected abstract fun bytesToSignature(sigBytes: ByteArray): CryptoSignature.RawByteEncodable
    final override suspend fun sign(data: SignatureInput, configure: DSLConfigureFn<IosSignerSigningConfiguration>): SignatureResult<*> =
    withContext(dispatcher) { signCatching {
        require(data.format == null) { "Pre-hashed data is unsupported on iOS" }
        require(metadata.allowSigning) { "Signing key purpose not set! Signing disallowed!" }
        val signingConfig = DSL.resolve(::IosSignerSigningConfiguration, configure)
        val algorithm = signatureAlgorithm.secKeyAlgorithmPreHashed
        val plaintext = data.convertTo(signatureAlgorithm.preHashedSignatureFormat).getOrThrow().data.first().toNSData()
        val signatureBytes = try {
            corecall {
                SecKeyCreateSignature(privateKeyManager.get(signingConfig).value, algorithm, plaintext.let(::giveToCF), error)
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
        return@signCatching bytesToSignature(signatureBytes)
    }}

    class ECDSA internal constructor
        (alias: String, override val publicKey: CryptoPublicKey.EC, metadata: IosKeyMetadata, config: IosSignerConfiguration)
        : IosSigner(alias, metadata, config),
            PlatformSigningProviderSigner.ECDSA<IosSignerSigningConfiguration, IosHomebrewAttestation>
    {
        override val signatureAlgorithm: SignatureAlgorithm.ECDSA
        init {
            check (metadata.algSpecific is IosKeyAlgSpecificMetadata.ECDSA)
            { "Metadata type mismatch (ECDSA key, metadata not ECDSA)" }

            signatureAlgorithm = when (
                val digest = resolveOption("digest", metadata.algSpecific.supportedDigests, config.ec.v.digestSpecified, { config.ec.v.digest })
            ){
                Digest.SHA256, Digest.SHA384, Digest.SHA512 -> SignatureAlgorithm.ECDSA(digest, publicKey.curve)
                else -> throw UnsupportedCryptoException("ECDSA with $digest is not supported on iOS")
            }
        }
        override fun bytesToSignature(sigBytes: ByteArray) =
            CryptoSignature.EC.decodeFromDer(sigBytes).withCurve(publicKey.curve)

        final override suspend fun keyAgreement(
            publicValue: KeyAgreementPublicValue.ECDH,
            configure: DSLConfigureFn<IosSignerSigningConfiguration>
        ) = catching {
            require(metadata.allowKeyAgreement) { "Key agreement purpose not set! Key agreement disallowed!" }
            val config = DSL.resolve(::IosSignerSigningConfiguration, configure)
            performKeyAgreement(privateKeyManager.get(config).value, publicValue)
        }
    }

    class RSA internal constructor
        (alias: String, override val publicKey: CryptoPublicKey.RSA, metadata: IosKeyMetadata, config: IosSignerConfiguration)
        : IosSigner(alias, metadata, config), Signer.RSA
    {
        override val signatureAlgorithm: SignatureAlgorithm.RSA
        init {
            check (metadata.algSpecific is IosKeyAlgSpecificMetadata.RSA)
            { "Metadata type mismatch (RSA key, metadata not RSA) "}

            signatureAlgorithm = SignatureAlgorithm.RSA(
                digest = resolveOption("digest", metadata.algSpecific.supportedDigests, config.rsa.v.digestSpecified, { config.rsa.v.digest }),
                padding = resolveOption("padding", metadata.algSpecific.supportedPaddings, config.rsa.v.paddingSpecified, { config.rsa.v.padding })
            )
        }
        override fun bytesToSignature(sigBytes: ByteArray) =
            CryptoSignature.RSA(sigBytes)
    }

}

@Serializable
internal sealed interface IosKeyAlgSpecificMetadata {
    @Serializable
    @SerialName("ecdsa")
    data class ECDSA(
        val supportedDigests: Set<Digest?>
    ) : IosKeyAlgSpecificMetadata

    @Serializable
    @SerialName("rsa")
    data class RSA(
        val supportedDigests: Set<Digest>,
        val supportedPaddings: Set<RSAPadding>
    ): IosKeyAlgSpecificMetadata
}

@Serializable
internal data class IosKeyMetadata(
    val attestation: IosHomebrewAttestation?,
    private val rawUnlockTimeout: Duration?,
    val algSpecific: IosKeyAlgSpecificMetadata,
    val allowSigning: Boolean = true,
    val allowKeyAgreement: Boolean = false,
    val allowEncryption: Boolean = false,
) {
    init {
        require(!(allowSigning && allowEncryption)) //TODO is this really always illegal?
    }
    val needsUnlock inline get() = (rawUnlockTimeout != null)
    val unlockTimeout inline get() = rawUnlockTimeout ?: Duration.INFINITE
}

/**
 * Signing provider backed by the iOS Keychain.
 *
 * RSA-PSS supports only MGF1 using the signature digest, a salt length equal to the digest output length, and trailer
 * field `1`, as required by the iOS Security framework.
 */
@OptIn(ExperimentalForeignApi::class)
object IosKeychainProvider: PlatformSigningProviderI<IosSigner, IosSignerConfiguration, IosSigningKeyConfiguration> {

    private fun MemScope.getPublicKey(alias: String): OwnedCFValue<SecKeyRef>? {
        // try the new bundle-id-free tag first, then fall back to the legacy bundle-id-scoped tag
        KeychainTags.PUBLIC_KEYS.forEach { tag ->
            val it = alloc<SecKeyRefVar>()
            val query = createCFDictionary {
                kSecClass mapsTo kSecClassKey
                kSecAttrKeyClass mapsTo kSecAttrKeyClassPublic
                kSecAttrApplicationLabel mapsTo alias
                kSecAttrApplicationTag mapsTo tag
                kSecReturnRef mapsTo true
            }
            when (val status = SecItemCopyMatching(query, it.ptr.reinterpret())) {
                errSecSuccess -> { require (it.value != null); return it.value!!.manage() }
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
                errSecSuccess -> return dict.value!!.get<String>(kSecAttrLabel).let { Json.decodeFromString<IosKeyMetadata>(it) }
                    .also { _ -> CFRelease(dict.value) }
                errSecItemNotFound -> {/* fall through */}
                else -> throw CFCryptoOperationFailed(thing = "retrieve key metadata", osStatus = status)
            }
        }
        throw CFCryptoOperationFailed(thing = "retrieve key metadata", osStatus = errSecItemNotFound)
    }

    override suspend fun createSigningKey(
        alias: String,
        configure: DSLConfigureFn<IosSigningKeyConfiguration>
    ): KmmResult<IosSigner> = withContext(dispatcher) { catching {
        memScoped {
            // also catches legacy bundle-id-tagged keys, so we never shadow an existing key
            if (getPublicKey(alias) != null)
                throw NoSuchElementException("Key with alias $alias already exists")
        }

        // ok, the key does not exist, create it
        try {
            deleteSigningKey(alias).getOrThrow() /* make sure there are no leftover private keys */

            val config: IosSigningKeyConfiguration = DSL.resolve(::IosSigningKeyConfiguration, configure)
            val availability = config.hardware.v.let { c -> when (c.availability) {
                IosSecureEnclaveConfiguration.Availability.ALWAYS -> if (c.allowBackup) kSecAttrAccessibleAlways else kSecAttrAccessibleAlwaysThisDeviceOnly
                IosSecureEnclaveConfiguration.Availability.AFTER_FIRST_UNLOCK -> if (c.allowBackup) kSecAttrAccessibleAfterFirstUnlock else kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
                IosSecureEnclaveConfiguration.Availability.WHILE_UNLOCKED -> if (c.allowBackup) kSecAttrAccessibleWhenUnlocked else kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            } }

            val useSecureEnclave = when (config.hardware.v.backing) {
                is REQUIRED -> true
                is PREFERRED -> isSecureEnclaveSupportedConfiguration(config._algSpecific.v)
                is DISCOURAGED -> false
            }

            val publicKeyBytes: ByteArray = memScoped {
                val attr = createCFDictionary {
                    when (val alg = config._algSpecific.v) {
                        is SigningKeyConfiguration.ECConfiguration -> {
                            kSecAttrKeyType mapsTo kSecAttrKeyTypeEC
                            kSecAttrKeySizeInBits mapsTo alg.curve.coordinateLength.bits.toInt()
                        }

                        is SigningKeyConfiguration.RSAConfiguration -> {
                            kSecAttrKeyType mapsTo kSecAttrKeyTypeRSA
                            kSecAttrKeySizeInBits mapsTo alg.bits
                        }
                    }
                    if (useSecureEnclave) {
                        kSecAttrTokenID mapsTo kSecAttrTokenIDSecureEnclave
                    }
                    kSecPrivateKeyAttrs mapsTo createCFDictionary {
                        kSecAttrApplicationLabel mapsTo alias
                        kSecAttrIsPermanent mapsTo true
                        kSecAttrApplicationTag mapsTo KeychainTags.NEW_PRIVATE_KEYS

                        when (val hwProtection = config.hardware.v.protection.v) {
                            null -> {
                                kSecAttrAccessible mapsTo availability
                            }

                            else -> {
                                val factors = hwProtection.factors.v
                                kSecAttrAccessControl mapsTo corecall {
                                    SecAccessControlCreateWithFlags(
                                        null, availability,
                                        when {
                                            (factors.biometry && factors.deviceLock) -> kSecAccessControlUserPresence
                                            factors.biometry -> if (factors.biometryWithNewFactors) kSecAccessControlBiometryAny else kSecAccessControlBiometryCurrentSet
                                            else -> kSecAccessControlDevicePasscode
                                        }.let {
                                            if (useSecureEnclave) (it or kSecAccessControlPrivateKeyUsage) else it
                                        }, error)
                                }.also { defer { CFRelease(it) } }
                            }
                        }
                    }
                    kSecPublicKeyAttrs mapsTo cfDictionaryOf(
                        kSecAttrApplicationLabel to alias,
                        kSecAttrIsPermanent to true,
                        kSecAttrApplicationTag to KeychainTags.NEW_PUBLIC_KEYS
                    )
                }

                val pubkey = alloc<SecKeyRefVar>()
                val privkey = alloc<SecKeyRefVar>()

                Napier.v { "Ready to generate iOS keypair for alias $alias (secure enclave? $useSecureEnclave)" }
                val status = SecKeyGeneratePair(attr, pubkey.ptr, privkey.ptr)
                Napier.v { "Successfully generated iOS keypair for alias $alias (secure enclave? $useSecureEnclave)" }

                if ((status == errSecSuccess) && (pubkey.value != null) && (privkey.value != null)) {
                    return@memScoped corecall {
                        SecKeyCopyExternalRepresentation(pubkey.value, error)
                    }.takeFromCF<NSData>().toByteArray().also {
                        CFRelease(pubkey.value)
                        CFRelease(privkey.value)
                    }
                } else {
                    val x = CFCryptoOperationFailed(thing = "generate key", osStatus = status)
                    if ((status == -50) &&
                        useSecureEnclave &&
                        !isSecureEnclaveSupportedConfiguration(config._algSpecific.v))
                    {
                        throw UnsupportedCryptoException("The iOS Secure Enclave does not support this configuration.", x)
                    }
                    throw x
                }
            }

            val publicKey = when (val alg = config._algSpecific.v) {
                is SigningKeyConfiguration.ECConfiguration ->
                    CryptoPublicKey.EC.fromAnsiX963Bytes(alg.curve, publicKeyBytes)
                is SigningKeyConfiguration.RSAConfiguration ->
                    CryptoPublicKey.RSA.fromPKCS1encoded(publicKeyBytes)
            }

            val attestation = if (useSecureEnclave) {
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

                    val digest = Digest.SHA256.digest(clientDataJSON)
                val assertionKeyAttestation = swiftasync {
                    service.attestKey(keyId, digest.toNSData(), callback)
                    }.toByteArray()
                    Napier.v { "attested key ($assertionKeyAttestation)" }

                    return@let IosHomebrewAttestation(
                        attestation = assertionKeyAttestation,
                        clientDataJSON = clientDataJSON)
                }
            } else null

            val metadata = IosKeyMetadata(
                attestation = attestation,
                rawUnlockTimeout = config.hardware.v.protection.v?.timeout,
                allowSigning = config._algSpecific.v.allowsSigning,
                allowEncryption = config._algSpecific.v.allowsDecrypting,
                allowKeyAgreement = config._algSpecific.v.allowsKeyAgreement,
                algSpecific = when (val alg = config._algSpecific.v) {
                    is SigningKeyConfiguration.ECConfiguration -> IosKeyAlgSpecificMetadata.ECDSA(alg.digests)
                    is SigningKeyConfiguration.RSAConfiguration -> IosKeyAlgSpecificMetadata.RSA(alg.digests, alg.paddings)
                }
            ).also { storeKeyMetadata(alias, metadata = it) }

            Napier.v { "key $alias metadata stored (has attestation? ${attestation != null})" }

            val signerConfiguration = DSL.resolve(::IosSignerConfiguration, config.signer.v)

            return@catching when (publicKey) {
                is CryptoPublicKey.EC ->
                    IosSigner.ECDSA(alias, publicKey, metadata, signerConfiguration)
                is CryptoPublicKey.RSA ->
                    IosSigner.RSA(alias, publicKey, metadata, signerConfiguration)
            }
        } catch (e: Throwable) {
            // get rid of any "partial" keys
            try { deleteSigningKey(alias) } catch (x: Throwable) { e.addSuppressed(x.nonFatalOrThrow()) }
            throw e
        }
    }}

    override suspend fun getSignerForKey(
        alias: String,
        configure: DSLConfigureFn<IosSignerConfiguration>
    ): KmmResult<IosSigner> = withContext(dispatcher) { catching {
        val config = DSL.resolve(::IosSignerConfiguration, configure)
        val publicKeyBytes: ByteArray = memScoped {
            val publicKey = getPublicKey(alias)
                ?: throw NoSuchElementException("No key for alias $alias exists")
            return@memScoped corecall {
                SecKeyCopyExternalRepresentation(publicKey.value, error)
            }.takeFromCF<NSData>().toByteArray()
        }
        val publicKey =
            CryptoPublicKey.fromIosEncoded(publicKeyBytes)
        val metadata = getKeyMetadata(alias)
        return@catching when (publicKey) {
            is CryptoPublicKey.EC -> IosSigner.ECDSA(alias, publicKey, metadata, config)
            is CryptoPublicKey.RSA -> IosSigner.RSA(alias, publicKey, metadata, config)
        }
    }}

    override suspend fun deleteSigningKey(alias: String) = withContext(dispatcher) { catching {
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
    } }
}

internal actual fun getPlatformSigningProvider(configure: DSLConfigureFn<PlatformSigningProviderConfigurationBase>): PlatformSigningProviderI<*,*,*> =
    IosKeychainProvider
