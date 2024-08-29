@file:OptIn(ExperimentalForeignApi::class)
package at.asitplus.signum.supreme.os

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.RSAPadding
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.nativeDigest
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
import kotlinx.cinterop.Arena
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
import at.asitplus.signum.indispensable.secKeyAlgorithm
import at.asitplus.signum.supreme.HazardousMaterials
import at.asitplus.signum.supreme.sign.SigningKeyConfiguration
import kotlinx.serialization.Serializable
import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.InvocationKind
import kotlin.contracts.contract
import kotlin.math.min
import kotlin.time.Duration
import kotlin.time.TimeSource


val keychainThreads = newFixedThreadPoolContext(nThreads = 4, name = "iOS Keychain Operations")

private fun isSecureEnclaveSupportedCurve(c: SigningKeyConfiguration.AlgorithmSpecific): Boolean {
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
        Pair("kmp-crypto-privatekey-$bundleId", "kmp-crypto.publickey-$bundleId")
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

class IosSignerConfiguration internal constructor(): PlatformSignerConfigurationBase() {
}

sealed class UnlockedIosSigner(private val ownedArena: Arena, internal val privateKeyRef: SecKeyRef) : Signer.UnlockedHandle {
    abstract val parent: IosSigner<*>
    val alias get() = parent.alias

    var usable = true
    final override fun close() {
        if (!usable) return
        usable = false
        ownedArena.clear()
    }

    internal fun checkSupport() {
        if (!SecKeyIsAlgorithmSupported(privateKeyRef, kSecKeyOperationTypeSign, signatureAlgorithm.secKeyAlgorithm)) {
            close()
            throw UnsupportedCryptoException("Requested operation is not supported by this key")
        }
    }

    protected abstract fun bytesToSignature(sigBytes: ByteArray): CryptoSignature
    final override suspend fun sign(data: SignatureInput): KmmResult<CryptoSignature> =
    withContext(keychainThreads) { catching {
        if (!usable) throw IllegalStateException("Scoping violation; using key after it has been freed")
        require(data.format == null) { "Pre-hashed data is unsupported on iOS" }
        val algorithm = signatureAlgorithm.secKeyAlgorithm
        val plaintext = data.data.fold(byteArrayOf(), ByteArray::plus).toNSData()
        val signatureBytes = corecall {
            SecKeyCreateSignature(privateKeyRef, algorithm, plaintext.giveToCF(), error)
        }.let { it.takeFromCF<NSData>().toByteArray() }
        return@catching bytesToSignature(signatureBytes)
    }}

    class ECDSA(ownedArena: Arena,
                privateKeyRef: SecKeyRef,
                override val parent: IosSigner.ECDSA)
        : UnlockedIosSigner(ownedArena, privateKeyRef), Signer.ECDSA
    {
        override val signatureAlgorithm get() = parent.signatureAlgorithm
        override val publicKey get() = parent.publicKey
        override fun bytesToSignature(sigBytes: ByteArray) =
            CryptoSignature.EC.decodeFromDer(sigBytes).withCurve(publicKey.curve)
    }

    class RSA(ownedArena: Arena,
              privateKeyRef: SecKeyRef,
              override val parent: IosSigner.RSA)
        : UnlockedIosSigner(ownedArena, privateKeyRef), Signer.RSA
    {
        override val signatureAlgorithm get() = parent.signatureAlgorithm
        override val publicKey get() = parent.publicKey
        override fun bytesToSignature(sigBytes: ByteArray) =
            CryptoSignature.RSAorHMAC(sigBytes)
    }

}

@Serializable
data class IosKeyMetadata(
    internal val attestation: IosHomebrewAttestation?,
    internal val unlockTimeout: Duration
)

private object LAContextManager {
    private data class PreviousAuthentication(
        val authenticatedContext: LAContext,
        val authenticationTime: TimeSource.Monotonic.ValueTimeMark)
    private var previousAuthentication: PreviousAuthentication? = null
    @OptIn(ExperimentalContracts::class)
    inline fun <reified T> withLAContext(keyMetadata: IosKeyMetadata,
             signerConfig: IosSignerConfiguration, body: (LAContext)->T): T {
        contract { callsInPlace(body, InvocationKind.AT_MOST_ONCE) }

        val reusable = previousAuthentication?.takeIf {
            it.authenticationTime.elapsedNow() <= keyMetadata.unlockTimeout
        }
        if (reusable != null)
            return body(reusable.authenticatedContext.apply {
                /** Configure it to suit this signer just in case something has gone wrong */
                localizedReason = signerConfig.unlockPrompt.v.message
                localizedCancelTitle = signerConfig.unlockPrompt.v.cancelText
            })

        val newContext = LAContext().apply {
            localizedReason = signerConfig.unlockPrompt.v.message
            localizedCancelTitle = signerConfig.unlockPrompt.v.cancelText
            touchIDAuthenticationAllowableReuseDuration = min(10L,keyMetadata.unlockTimeout.inWholeSeconds).toDouble()
        }

        return body(newContext).also {
            // if this did not throw (e.g., succeeded)...
            previousAuthentication = PreviousAuthentication(newContext, TimeSource.Monotonic.markNow())
        }
    }
}

sealed class IosSigner<H : UnlockedIosSigner>(
    final override val alias: String,
    private val metadata: IosKeyMetadata,
    private val config: IosSignerConfiguration
) : Signer.TemporarilyUnlockable<H>(), Signer.Attestable<IosHomebrewAttestation>, Signer.WithAlias {
    final override val attestation get() = metadata.attestation
    @HazardousMaterials
    final override suspend fun unlock(): KmmResult<H> = withContext(keychainThreads) { catching {
        val arena = Arena()
        val privateKey = arena.alloc<SecKeyRefVar>()
        try {
            LAContextManager.withLAContext(keyMetadata = metadata, signerConfig = config) { ctx ->
                memScoped {
                    val query = cfDictionaryOf(
                        kSecClass to kSecClassKey,
                        kSecAttrKeyClass to kSecAttrKeyClassPrivate,
                        kSecAttrApplicationLabel to alias,
                        kSecAttrApplicationTag to KeychainTags.PRIVATE_KEYS,
                        kSecAttrKeyType to when (this@IosSigner) {
                            is ECDSA -> kSecAttrKeyTypeEC
                            is RSA -> kSecAttrKeyTypeRSA
                        },
                        kSecMatchLimit to kSecMatchLimitOne,
                        kSecReturnRef to true,

                        kSecUseAuthenticationContext to ctx,
                        kSecUseAuthenticationUI to kSecUseAuthenticationUIAllow
                    )
                    val status = SecItemCopyMatching(query, privateKey.ptr.reinterpret())
                    if ((status == errSecSuccess) && (privateKey.value != null)) {
                        return@withLAContext /* continue below try/catch */
                    } else {
                        throw CFCryptoOperationFailed(
                            thing = "retrieve private key",
                            osStatus = status
                        )
                    }
                }
            }
        } catch (e: Throwable) {
            arena.clear()
            throw e
        }
        /* if the block did not throw, the handle takes ownership of the arena */
        toUnlocked(arena, privateKey.value!!).also(UnlockedIosSigner::checkSupport)
    }}

    protected abstract fun toUnlocked(arena: Arena, key: SecKeyRef): H
    class ECDSA(alias: String, metadata: IosKeyMetadata, config: IosSignerConfiguration,
                override val publicKey: CryptoPublicKey.EC)
        : IosSigner<UnlockedIosSigner.ECDSA>(alias, metadata, config), Signer.ECDSA
    {
        override val signatureAlgorithm = when (val digest = if (config.ec.v.digestSpecified) config.ec.v.digest else publicKey.curve.nativeDigest){
            Digest.SHA256, Digest.SHA384, Digest.SHA512 -> SignatureAlgorithm.ECDSA(digest, publicKey.curve)
            else -> throw UnsupportedCryptoException("ECDSA with $digest is not supported on iOS")
        }

        override fun toUnlocked(arena: Arena, key: SecKeyRef) =
            UnlockedIosSigner.ECDSA(arena, key, this)
    }

    class RSA(alias: String, metadata: IosKeyMetadata, config: IosSignerConfiguration,
              override val publicKey: CryptoPublicKey.Rsa)
        : IosSigner<UnlockedIosSigner.RSA>(alias, metadata, config), Signer.RSA
    {
        override val signatureAlgorithm = SignatureAlgorithm.RSA(
            digest = if (config.rsa.v.digestSpecified) config.rsa.v.digest else Digest.SHA512,
            padding = if (config.rsa.v.paddingSpecified) config.rsa.v.padding else RSAPadding.PSS)

        override fun toUnlocked(arena: Arena, key: SecKeyRef) =
            UnlockedIosSigner.RSA(arena, key, this)
    }
}

@OptIn(ExperimentalForeignApi::class)
object IosKeychainProvider: SigningProviderI<IosSigner<*>, IosSignerConfiguration, IosSigningKeyConfiguration> {
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
            throw CFCryptoOperationFailed(thing = "store key attestation", osStatus = status)
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
                throw CFCryptoOperationFailed(thing = "retrieve attestation info", osStatus = status)
            }
        }
    }

    override suspend fun createSigningKey(
        alias: String,
        configure: DSLConfigureFn<IosSigningKeyConfiguration>
    ): KmmResult<IosSigner<*>> = withContext(keychainThreads) { catching {
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
            is PREFERRED -> isSecureEnclaveSupportedCurve(config._algSpecific.v)
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
                    when (val factors = config.hardware.v.protection.v?.factors?.v) {
                        null -> {
                            kSecAttrAccessible mapsTo availability
                        }
                        else -> {
                            kSecAttrAccessControl mapsTo corecall {
                                SecAccessControlCreateWithFlags(
                                    null, availability,
                                    when {
                                        (factors.biometry && factors.deviceLock) -> kSecAccessControlUserPresence
                                        factors.biometry -> kSecAccessControlBiometryAny
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
                    !isSecureEnclaveSupportedCurve(config._algSpecific.v)) {
                    throw UnsupportedCryptoException("iOS Secure Enclave does not support this configuration.", x)
                }
                throw x
            }
        }

        val publicKey = when (val alg = config._algSpecific.v) {
            is SigningKeyConfiguration.ECConfiguration ->
                CryptoPublicKey.EC.fromAnsiX963Bytes(alg.curve, publicKeyBytes)
            is SigningKeyConfiguration.RSAConfiguration ->
                CryptoPublicKey.Rsa.fromPKCS1encoded(publicKeyBytes)
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
                val clientDataJSON = Json.encodeToString(clientData).encodeToByteArray()

                val assertionKeyAttestation = swiftasync {
                    service.attestKey(keyId, Digest.SHA256.digest(clientDataJSON).toNSData(), callback)
                }.toByteArray()
                Napier.v { "attested key ($assertionKeyAttestation)" }

                return@let IosHomebrewAttestation(attestation = assertionKeyAttestation, clientDataJSON = clientDataJSON)
            }
        } else null

        val metadata = IosKeyMetadata(
            attestation = attestation,
            unlockTimeout = config.hardware.v.protection.v?.timeout ?: Duration.ZERO
        ).also { storeKeyMetadata(alias, it) }

        Napier.v { "key $alias metadata stored (has attestation? ${attestation != null})" }

        val signerConfiguration = DSL.resolve(::IosSignerConfiguration, config.signer.v)
        return@catching when (publicKey) {
            is CryptoPublicKey.EC ->
                IosSigner.ECDSA(alias, metadata, signerConfiguration, publicKey)
            is CryptoPublicKey.Rsa ->
                IosSigner.RSA(alias, metadata, signerConfiguration, publicKey)
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
    ): KmmResult<IosSigner<*>> = withContext(keychainThreads) { catching {
        val config = DSL.resolve(::IosSignerConfiguration, configure)
        val publicKeyBytes: ByteArray = memScoped {
            val publicKey = getPublicKey(alias)
                ?: throw NoSuchElementException("No key for alias $alias exists")
            return@memScoped corecall {
                SecKeyCopyExternalRepresentation(publicKey, error)
            }.let { it.takeFromCF<NSData>() }.toByteArray()
        }
        val metadata = getKeyMetadata(alias)
        return@catching when (val publicKey =
            CryptoPublicKey.fromIosEncoded(publicKeyBytes)) {
            is CryptoPublicKey.EC -> IosSigner.ECDSA(alias, metadata, config, publicKey)
            is CryptoPublicKey.Rsa -> IosSigner.RSA(alias, metadata, config, publicKey)
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

/*actual typealias PlatformSigningProviderSigner = iosSigner<*>
actual typealias PlatformSigningProviderSignerConfiguration = iosSignerConfiguration
actual typealias PlatformSigningProviderSigningKeyConfiguration = iosSigningKeyConfiguration
actual typealias PlatformSigningProvider = IosKeychainProvider
actual typealias PlatformSigningProviderConfiguration = PlatformSigningProviderConfigurationBase*/
internal actual fun getPlatformSigningProvider(configure: DSLConfigureFn<PlatformSigningProviderConfigurationBase>): SigningProvider =
    IosKeychainProvider
