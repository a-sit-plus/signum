@file:OptIn(ExperimentalForeignApi::class)
package at.asitplus.signum.supreme.os

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.supreme.CFCryptoOperationFailed
import at.asitplus.signum.supreme.CryptoOperationFailed
import at.asitplus.signum.supreme.UnsupportedCryptoException
import at.asitplus.signum.supreme.createCFDictionary
import at.asitplus.signum.supreme.cfDictionaryOf
import at.asitplus.signum.supreme.corecall
import at.asitplus.signum.supreme.dsl.DISCOURAGED
import at.asitplus.signum.supreme.dsl.DSL
import at.asitplus.signum.supreme.dsl.DSLConfigureFn
import at.asitplus.signum.supreme.dsl.PREFERRED
import at.asitplus.signum.supreme.dsl.REQUIRED
import at.asitplus.signum.supreme.get
import at.asitplus.signum.supreme.giveToCF
import at.asitplus.signum.supreme.hash.digest
import at.asitplus.signum.supreme.sign.SignatureInput
import at.asitplus.signum.supreme.sign.Signer
import at.asitplus.signum.supreme.swiftasync
import at.asitplus.signum.supreme.takeFromCF
import at.asitplus.signum.supreme.toByteArray
import at.asitplus.signum.supreme.toNSData
import io.github.aakira.napier.Napier
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.MemScope
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.value
import kotlinx.coroutines.newFixedThreadPoolContext
import kotlinx.coroutines.withContext
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import platform.CoreFoundation.CFDictionaryRefVar
import platform.DeviceCheck.DCAppAttestService
import platform.Foundation.CFBridgingRelease
import platform.Foundation.NSBundle
import platform.Foundation.NSData
import platform.LocalAuthentication.LAContext
import platform.Security.SecAccessControlCreateWithFlags
import platform.Security.SecItemCopyMatching
import platform.Security.SecItemDelete
import platform.Security.SecItemUpdate
import platform.Security.SecKeyCopyExternalRepresentation
import platform.Security.SecKeyCreateSignature
import platform.Security.SecKeyGeneratePair
import platform.Security.SecKeyIsAlgorithmSupported
import platform.Security.SecKeyRef
import platform.Security.SecKeyRefVar
import platform.Security.errSecItemNotFound
import platform.Security.errSecSuccess
import platform.Security.kSecAccessControlBiometryAny
import platform.Security.kSecAccessControlDevicePasscode
import platform.Security.kSecAccessControlPrivateKeyUsage
import platform.Security.kSecAccessControlUserPresence
import platform.Security.kSecAttrAccessControl
import platform.Security.kSecAttrAccessible
import platform.Security.kSecAttrAccessibleAfterFirstUnlock
import platform.Security.kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
import platform.Security.kSecAttrAccessibleAlways
import platform.Security.kSecAttrAccessibleAlwaysThisDeviceOnly
import platform.Security.kSecAttrAccessibleWhenUnlocked
import platform.Security.kSecAttrAccessibleWhenUnlockedThisDeviceOnly
import platform.Security.kSecAttrApplicationLabel
import platform.Security.kSecAttrApplicationTag
import platform.Security.kSecAttrIsPermanent
import platform.Security.kSecAttrKeyClass
import platform.Security.kSecAttrKeyClassPrivate
import platform.Security.kSecAttrKeyClassPublic
import platform.Security.kSecAttrKeySizeInBits
import platform.Security.kSecAttrKeyType
import platform.Security.kSecAttrKeyTypeEC
import platform.Security.kSecAttrKeyTypeRSA
import platform.Security.kSecAttrLabel
import platform.Security.kSecAttrTokenID
import platform.Security.kSecAttrTokenIDSecureEnclave
import platform.Security.kSecClass
import platform.Security.kSecClassKey
import platform.Security.kSecKeyOperationTypeSign
import platform.Security.kSecMatchLimit
import platform.Security.kSecMatchLimitOne
import platform.Security.kSecPrivateKeyAttrs
import platform.Security.kSecPublicKeyAttrs
import platform.Security.kSecReturnAttributes
import platform.Security.kSecReturnRef
import platform.Security.kSecUseAuthenticationContext
import platform.Security.kSecUseAuthenticationUI
import platform.Security.kSecUseAuthenticationUIAllow
import at.asitplus.signum.supreme.AutofreeVariable
import at.asitplus.signum.supreme.CoreFoundationException
import at.asitplus.signum.supreme.SignatureResult
import at.asitplus.signum.supreme.UnlockFailed
import at.asitplus.signum.supreme.sign.SigningKeyConfiguration
import at.asitplus.signum.supreme.sign.preHashedSignatureFormat
import at.asitplus.signum.supreme.signCatching
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import platform.LocalAuthentication.LAErrorAuthenticationFailed
import platform.LocalAuthentication.LAErrorBiometryLockout
import platform.LocalAuthentication.LAErrorDomain
import platform.LocalAuthentication.LAErrorUserCancel
import platform.Security.errSecAuthFailed
import platform.Security.errSecUserCanceled
import platform.Security.kSecAccessControlBiometryCurrentSet
import platform.Security.kSecUseAuthenticationUIFail
import kotlin.math.min
import kotlin.time.Duration
import kotlin.time.TimeSource


private val keychainThreads = newFixedThreadPoolContext(nThreads = 4, name = "iOS Keychain Operations")

private fun isSecureEnclaveSupportedConfiguration(c: SigningKeyConfiguration.AlgorithmSpecific): Boolean {
    if (c !is SigningKeyConfiguration.ECConfiguration) return false
    return when (c.curve) {
        ECCurve.SECP_256_R_1 -> true
        else -> false
    }
}

private object KeychainTags {
    private val tags by lazy {
        val bundleId = NSBundle.mainBundle.bundleIdentifier
            ?: throw UnsupportedCryptoException("Keychain access is unsupported outside of a Bundle")
        Pair("supreme.privatekey-$bundleId", "supreme.publickey-$bundleId")
    }
    val PRIVATE_KEYS get() = tags.first
    val PUBLIC_KEYS get() = tags.second
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
sealed class IosSigner(final override val alias: String,
                       private val metadata: IosKeyMetadata,
                       private val signerConfig: IosSignerConfiguration)
    : PlatformSigningProviderSigner<IosSignerSigningConfiguration>, Signer.Attestable<IosHomebrewAttestation> {

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
                    localizedReason = stack.getProperty(UnlockPromptConfiguration::_message,
                        default = UnlockPromptConfiguration.defaultMessage)
                    localizedCancelTitle = stack.getProperty(UnlockPromptConfiguration::_cancelText,
                        default = UnlockPromptConfiguration.defaultCancelText)
                }
            } else {
                recordable = false
                ctx = null
            }

            // ok, we need to get the key from the keychain
            val newPrivateKey = AutofreeVariable<SecKeyRef>()
            memScoped {
                val query = createCFDictionary {
                    kSecClass mapsTo kSecClassKey
                    kSecAttrKeyClass mapsTo kSecAttrKeyClassPrivate
                    kSecAttrApplicationLabel mapsTo alias
                    kSecAttrApplicationTag mapsTo KeychainTags.PRIVATE_KEYS
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
                val status = SecItemCopyMatching(query, newPrivateKey.ptr.reinterpret())
                if ((status == errSecSuccess) && (newPrivateKey.value != null)) {
                    return@memScoped
                } else {
                    throw CFCryptoOperationFailed(
                        thing = "retrieve private key",
                        osStatus = status
                    )
                }
            }
            if (!SecKeyIsAlgorithmSupported(newPrivateKey.value, kSecKeyOperationTypeSign, signatureAlgorithm.secKeyAlgorithmPreHashed)) {
                throw UnsupportedCryptoException("Requested operation is not supported by this key")
            }

            if (recordable && (ctx != null)) {
                Napier.v { "Going to record successful LAContext after retrieving key $alias" }
                // record the successful unlock timestamp and LAContext for reuse
                // produce a dummy signature to ensure that the unlock has succeeded; this is required by secure enclave keys, which do not prompt for unlock until signing time
                corecall { SecKeyCreateSignature(newPrivateKey.value, signatureAlgorithm.secKeyAlgorithmPreHashed,
                    ByteArray(signatureAlgorithm.preHashedSignatureFormat!!.outputLength.bytes.toInt()).toNSData().giveToCF(), error) }

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
    withContext(keychainThreads) { catching {
        if (needsAuthentication && !needsAuthenticationForEveryUse) {
            val config = DSL.resolve(::IosSignerSigningConfiguration, configure)
            privateKeyManager.get(config)
        }
    } }

    protected abstract fun bytesToSignature(sigBytes: ByteArray): CryptoSignature.RawByteEncodable
    final override suspend fun sign(data: SignatureInput, configure: DSLConfigureFn<IosSignerSigningConfiguration>): SignatureResult<*> =
    withContext(keychainThreads) { signCatching {
        require(data.format == null) { "Pre-hashed data is unsupported on iOS" }
        val signingConfig = DSL.resolve(::IosSignerSigningConfiguration, configure)
        val algorithm = signatureAlgorithm.secKeyAlgorithmPreHashed
        val plaintext = data.convertTo(signatureAlgorithm.preHashedSignatureFormat).getOrThrow().data.first().toNSData()
        val signatureBytes = try {
            corecall {
                SecKeyCreateSignature(privateKeyManager.get(signingConfig).value, algorithm, plaintext.giveToCF(), error)
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
        : IosSigner(alias, metadata, config), Signer.ECDSA
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
            CryptoSignature.RSAorHMAC(sigBytes)
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
    val algSpecific: IosKeyAlgSpecificMetadata
) {
    val needsUnlock inline get() = (rawUnlockTimeout != null)
    val unlockTimeout inline get() = rawUnlockTimeout ?: Duration.INFINITE
}

@OptIn(ExperimentalForeignApi::class)
object IosKeychainProvider: PlatformSigningProviderI<IosSigner, IosSignerConfiguration, IosSigningKeyConfiguration> {
    private fun MemScope.getPublicKey(alias: String): SecKeyRef? {
        val it = alloc<SecKeyRefVar>()
        val query = cfDictionaryOf(
            kSecClass to kSecClassKey,
            kSecAttrKeyClass to kSecAttrKeyClassPublic,
            kSecAttrApplicationLabel to alias,
            kSecAttrApplicationTag to KeychainTags.PUBLIC_KEYS,
            kSecReturnRef to true,
        )
        val status = SecItemCopyMatching(query, it.ptr.reinterpret())
        return when (status) {
            errSecSuccess -> it.value
            errSecItemNotFound -> null
            else -> {
                throw CFCryptoOperationFailed(thing = "retrieve public key", osStatus = status)
            }
        }
    }
    private fun storeKeyMetadata(alias: String, metadata: IosKeyMetadata) = memScoped {
        val status = SecItemUpdate(
            cfDictionaryOf(
                kSecClass to kSecClassKey,
                kSecAttrKeyClass to kSecAttrKeyClassPublic,
                kSecAttrApplicationLabel to alias,
                kSecAttrApplicationTag to KeychainTags.PUBLIC_KEYS),
            cfDictionaryOf(
                kSecAttrLabel to Json.encodeToString(metadata)
            ))
        if (status != errSecSuccess) {
            throw CFCryptoOperationFailed(thing = "store key metadata", osStatus = status)
        }
    }
    private fun getKeyMetadata(alias: String): IosKeyMetadata = memScoped {
        val it = alloc<CFDictionaryRefVar>()
        val query = cfDictionaryOf(
            kSecClass to kSecClassKey,
            kSecAttrKeyClass to kSecAttrKeyClassPublic,
            kSecAttrApplicationLabel to alias,
            kSecAttrApplicationTag to KeychainTags.PUBLIC_KEYS,
            kSecReturnAttributes to true
        )
        val status = SecItemCopyMatching(query, it.ptr.reinterpret())
        return when (status) {
            errSecSuccess -> it.value!!.get<String>(kSecAttrLabel).let(Json::decodeFromString)
            else -> {
                throw CFCryptoOperationFailed(thing = "retrieve key metadata", osStatus = status)
            }
        }
    }

    override suspend fun createSigningKey(
        alias: String,
        configure: DSLConfigureFn<IosSigningKeyConfiguration>
    ): KmmResult<IosSigner> = withContext(keychainThreads) { catching {
        memScoped {
            if (getPublicKey(alias) != null)
                throw NoSuchElementException("Key with alias $alias already exists")
        }
        deleteSigningKey(alias).getOrThrow() /* make sure there are no leftover private keys */

        val config = DSL.resolve(::IosSigningKeyConfiguration, configure)

        val availability = config.hardware.v.let { c-> when (c.availability) {
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
                    kSecAttrApplicationTag mapsTo KeychainTags.PRIVATE_KEYS
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
                                        if (useSecureEnclave) it or kSecAccessControlPrivateKeyUsage else it
                                    }, error)
                            }.also { defer { CFBridgingRelease(it) } }
                        }
                    }
                }
                kSecPublicKeyAttrs mapsTo cfDictionaryOf(
                    kSecAttrApplicationLabel to alias,
                    kSecAttrIsPermanent to true,
                    kSecAttrApplicationTag to KeychainTags.PUBLIC_KEYS
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
                }.let { it.takeFromCF<NSData>() }.toByteArray()
            } else {
                val x = CFCryptoOperationFailed(thing = "generate key", osStatus = status)
                if ((status == -50) &&
                    useSecureEnclave &&
                    !isSecureEnclaveSupportedConfiguration(config._algSpecific.v)) {
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

                val assertionKeyAttestation = swiftasync {
                    service.attestKey(keyId, Digest.SHA256.digest(clientDataJSON).toNSData(), callback)
                }.toByteArray()
                Napier.v { "attested key ($assertionKeyAttestation)" }

                return@let IosHomebrewAttestation(attestation = assertionKeyAttestation, clientDataJSON = clientDataJSON)
            }
        } else null

        val metadata = IosKeyMetadata(
            attestation = attestation,
            rawUnlockTimeout = config.hardware.v.protection.v?.timeout,
            algSpecific = when (val alg = config._algSpecific.v) {
                is SigningKeyConfiguration.ECConfiguration -> IosKeyAlgSpecificMetadata.ECDSA(alg.digests)
                is SigningKeyConfiguration.RSAConfiguration -> IosKeyAlgSpecificMetadata.RSA(alg.digests, alg.paddings)
            }
        ).also { storeKeyMetadata(alias, it) }

        Napier.v { "key $alias metadata stored (has attestation? ${attestation != null})" }

        val signerConfiguration = DSL.resolve(::IosSignerConfiguration, config.signer.v)
        return@catching when (publicKey) {
            is CryptoPublicKey.EC ->
                IosSigner.ECDSA(alias, publicKey, metadata, signerConfiguration)
            is CryptoPublicKey.RSA ->
                IosSigner.RSA(alias, publicKey, metadata, signerConfiguration)
        }
    }.also {
        val e = it.exceptionOrNull()
        if (e != null && e !is NoSuchElementException) {
            // get rid of any "partial" keys
            deleteSigningKey(alias)
        }
    }}

    override suspend fun getSignerForKey(
        alias: String,
        configure: DSLConfigureFn<IosSignerConfiguration>
    ): KmmResult<IosSigner> = withContext(keychainThreads) { catching {
        val config = DSL.resolve(::IosSignerConfiguration, configure)
        val publicKeyBytes: ByteArray = memScoped {
            val publicKey = getPublicKey(alias)
                ?: throw NoSuchElementException("No key for alias $alias exists")
            return@memScoped corecall {
                SecKeyCopyExternalRepresentation(publicKey, error)
            }.let { it.takeFromCF<NSData>() }.toByteArray()
        }
        val publicKey =
            CryptoPublicKey.fromIosEncoded(publicKeyBytes)
        val metadata = getKeyMetadata(alias)
        return@catching when (publicKey) {
            is CryptoPublicKey.EC -> IosSigner.ECDSA(alias, publicKey, metadata, config)
            is CryptoPublicKey.RSA -> IosSigner.RSA(alias, publicKey, metadata, config)
        }
    }}

    override suspend fun deleteSigningKey(alias: String) = withContext(keychainThreads) { catching {
        memScoped {
            mapOf(
                "public key" to cfDictionaryOf(
                    kSecClass to kSecClassKey,
                    kSecAttrKeyClass to kSecAttrKeyClassPublic,
                    kSecAttrApplicationLabel to alias,
                    kSecAttrApplicationTag to KeychainTags.PUBLIC_KEYS
                ), "private key" to cfDictionaryOf(
                    kSecClass to kSecClassKey,
                    kSecAttrKeyClass to kSecAttrKeyClassPrivate,
                    kSecAttrApplicationLabel to alias,
                    kSecAttrApplicationTag to KeychainTags.PRIVATE_KEYS
                )
            ).map { (kind, options) ->
                val status = SecItemDelete(options)
                if ((status != errSecSuccess) && (status != errSecItemNotFound))
                    CFCryptoOperationFailed(thing = "delete $kind", osStatus = status)
                else
                    null
            }.mapNotNull { it?.message }.let {
                if (it.isNotEmpty())
                    throw CryptoOperationFailed(it.joinToString(","))
            }
        }
    } }
}

internal actual fun getPlatformSigningProvider(configure: DSLConfigureFn<PlatformSigningProviderConfigurationBase>): PlatformSigningProviderI<*,*,*> =
    IosKeychainProvider
