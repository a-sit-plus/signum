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
import at.asitplus.signum.supreme.os.*
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
import at.asitplus.signum.supreme.sign.SigningKeyConfiguration


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

class iosSecureEnclaveConfiguration internal constructor() : PlatformSigningKeyConfiguration.SecureHardwareConfiguration() {
    /** Set to true to allow this key to be backed up. */
    var allowBackup = false
    enum class Availability { ALWAYS, AFTER_FIRST_UNLOCK, WHILE_UNLOCKED }
    /** Specify when this key should be available */
    var availability = Availability.ALWAYS
}
class iosSigningKeyConfiguration internal constructor(): PlatformSigningKeyConfiguration<iosSignerConfiguration>() {
    override val hardware = childOrDefault(::iosSecureEnclaveConfiguration) {
        backing = DISCOURAGED
    }
}

class iosSignerConfiguration internal constructor(): PlatformSignerConfiguration() {
}

sealed class unlockedIosSigner(private val ownedArena: Arena, internal val privateKeyRef: SecKeyRef) : Signer.UnlockedHandle {
    abstract val parent: iosSigner<*>
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
    override suspend fun sign(data: SignatureInput): KmmResult<CryptoSignature> =
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
                override val parent: iosSigner.ECDSA)
        : unlockedIosSigner(ownedArena, privateKeyRef), Signer.ECDSA
    {
        override val signatureAlgorithm get() = parent.signatureAlgorithm
        override val publicKey get() = parent.publicKey
        override fun bytesToSignature(sigBytes: ByteArray) =
            CryptoSignature.EC.decodeFromDer(sigBytes).withCurve(publicKey.curve)
    }

    class RSA(ownedArena: Arena,
              privateKeyRef: SecKeyRef,
              override val parent: iosSigner.RSA)
        : unlockedIosSigner(ownedArena, privateKeyRef), Signer.RSA
    {
        override val signatureAlgorithm get() = parent.signatureAlgorithm
        override val publicKey get() = parent.publicKey
        override fun bytesToSignature(sigBytes: ByteArray) =
            CryptoSignature.RSAorHMAC(sigBytes)
    }

}

sealed class iosSigner<H : unlockedIosSigner>(
    val alias: String,
    override val attestation: iosHomebrewAttestation?,
    private val config: iosSignerConfiguration
) : Signer.TemporarilyUnlockable<H>(), Signer.Attestable<iosHomebrewAttestation> {

    override suspend fun unlock(): KmmResult<H> = withContext(keychainThreads) { catching {
        val arena = Arena()
        val privateKey = arena.alloc<SecKeyRefVar>()
        try {
            memScoped {
                val query = cfDictionaryOf(
                    kSecClass to kSecClassKey,
                    kSecAttrKeyClass to kSecAttrKeyClassPrivate,
                    kSecAttrApplicationLabel to alias,
                    kSecAttrApplicationTag to KeychainTags.PRIVATE_KEYS,
                    kSecAttrKeyType to when (this@iosSigner) {
                        is ECDSA -> kSecAttrKeyTypeEC
                        is RSA -> kSecAttrKeyTypeRSA
                    },
                    kSecMatchLimit to kSecMatchLimitOne,
                    kSecReturnRef to true,

                    kSecUseAuthenticationContext to LAContext().apply {
                        setLocalizedReason(config.unlockPrompt.v.message)
                        setLocalizedCancelTitle(config.unlockPrompt.v.cancelText)
                    },
                    kSecUseAuthenticationUI to kSecUseAuthenticationUIAllow
                )
                val status = SecItemCopyMatching(query, privateKey.ptr.reinterpret())
                if ((status == errSecSuccess) && (privateKey.value != null)) {
                    return@memScoped /* continue below try/catch */
                } else {
                    throw CFCryptoOperationFailed(thing = "retrieve private key", osStatus = status)
                }
            }
        } catch (e: Throwable) {
            arena.clear()
            throw e
        }
        /* if the block did not throw, the handle takes ownership of the arena */
        toUnlocked(arena, privateKey.value!!).also(unlockedIosSigner::checkSupport)
    }}

    protected abstract fun toUnlocked(arena: Arena, key: SecKeyRef): H
    class ECDSA(alias: String, attestation: iosHomebrewAttestation?, config: iosSignerConfiguration,
                override val publicKey: CryptoPublicKey.EC)
        : iosSigner<unlockedIosSigner.ECDSA>(alias, attestation, config), Signer.ECDSA
    {
        override val signatureAlgorithm = when (val digest = if (config.ec.v.digestSpecified) config.ec.v.digest else publicKey.curve.nativeDigest){
            Digest.SHA256, Digest.SHA384, Digest.SHA512 -> SignatureAlgorithm.ECDSA(digest, publicKey.curve)
            else -> throw UnsupportedCryptoException("ECDSA with $digest is not supported on iOS")
        }

        override fun toUnlocked(arena: Arena, key: SecKeyRef) =
            unlockedIosSigner.ECDSA(arena, key, this)
    }

    class RSA(alias: String, attestation: iosHomebrewAttestation?, config: iosSignerConfiguration,
              override val publicKey: CryptoPublicKey.Rsa)
        : iosSigner<unlockedIosSigner.RSA>(alias, attestation, config), Signer.RSA
    {
        override val signatureAlgorithm = SignatureAlgorithm.RSA(
            digest = if (config.rsa.v.digestSpecified) config.rsa.v.digest else Digest.SHA512,
            padding = if (config.rsa.v.paddingSpecified) config.rsa.v.padding else RSAPadding.PSS)

        override fun toUnlocked(arena: Arena, key: SecKeyRef) =
            unlockedIosSigner.RSA(arena, key, this)
    }
}

@OptIn(ExperimentalForeignApi::class)
object IosKeychainProvider:  SigningProviderI<iosSigner<*>, iosSignerConfiguration, iosSigningKeyConfiguration> {
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
    private fun storeKeyAttestation(alias: String, attestation: iosHomebrewAttestation) = memScoped {
        val status = SecItemUpdate(
            cfDictionaryOf(
                kSecClass to kSecClassKey,
                kSecAttrKeyClass to kSecAttrKeyClassPublic,
                kSecAttrApplicationLabel to alias,
                kSecAttrApplicationTag to KeychainTags.PUBLIC_KEYS),
            cfDictionaryOf(
                kSecAttrLabel to Json.encodeToString(attestation)
            ))
        if (status != errSecSuccess) {
            throw CFCryptoOperationFailed(thing = "store key attestation", osStatus = status)
        }
    }
    private fun getKeyAttestation(alias: String): iosHomebrewAttestation? = memScoped {
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
            errSecSuccess -> it.value!!.let { attrs ->
                attrs.get<String?>(kSecAttrLabel)?.let(Json::decodeFromString)
            }
            errSecItemNotFound -> null
            else -> {
                throw CFCryptoOperationFailed(thing = "retrieve attestation info", osStatus = status)
            }
        }
    }

    override suspend fun createSigningKey(
        alias: String,
        configure: DSLConfigureFn<iosSigningKeyConfiguration>
    ): KmmResult<iosSigner<*>> = withContext(keychainThreads) { catching {
        memScoped {
            if (getPublicKey(alias) != null)
                throw NoSuchElementException("Key with alias $alias already exists")
        }
        deleteSigningKey(alias) /* make sure there are no leftover private keys */

        val config = DSL.resolve(::iosSigningKeyConfiguration, configure)

        val availability = config.hardware.v.let { c-> when (c.availability) {
            iosSecureEnclaveConfiguration.Availability.ALWAYS -> if (c.allowBackup) kSecAttrAccessibleAlways else kSecAttrAccessibleAlwaysThisDeviceOnly
            iosSecureEnclaveConfiguration.Availability.AFTER_FIRST_UNLOCK -> if (c.allowBackup) kSecAttrAccessibleAfterFirstUnlock else kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            iosSecureEnclaveConfiguration.Availability.WHILE_UNLOCKED -> if (c.allowBackup) kSecAttrAccessibleWhenUnlocked else kSecAttrAccessibleWhenUnlockedThisDeviceOnly
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

                val clientData = iosHomebrewAttestation.ClientData(
                    publicKey = publicKey, challenge = attestationConfig.challenge)
                val clientDataJSON = Json.encodeToString(clientData).encodeToByteArray()

                val assertionKeyAttestation = swiftasync {
                    service.attestKey(keyId, Digest.SHA256.digest(clientDataJSON).toNSData(), callback)
                }.toByteArray()
                Napier.v { "attested key ($assertionKeyAttestation)" }

                val attestation = iosHomebrewAttestation(attestation = assertionKeyAttestation, clientDataJSON = clientDataJSON)
                storeKeyAttestation(alias, attestation)
                return@let attestation
            }
        } else null

        Napier.v { "key $alias has attestation? ${attestation != null}" }

        val signerConfiguration = DSL.resolve(::iosSignerConfiguration, config.signer.v)
        return@catching when (publicKey) {
            is CryptoPublicKey.EC ->
                iosSigner.ECDSA(alias, attestation, signerConfiguration, publicKey)
            is CryptoPublicKey.Rsa ->
                iosSigner.RSA(alias, attestation, signerConfiguration, publicKey)
        }
    }.also {
        val e = it.exceptionOrNull()
        if (e != null && e !is NoSuchElementException) {
            // get rid of any "partial" keys
            runCatching { deleteSigningKey(alias) }
        }
    }}

    override suspend fun getSignerForKey(
        alias: String,
        configure: DSLConfigureFn<iosSignerConfiguration>
    ): KmmResult<iosSigner<*>> = withContext(keychainThreads) { catching {
        val config = DSL.resolve(::iosSignerConfiguration, configure)
        val publicKeyBytes: ByteArray = memScoped {
            val publicKey = getPublicKey(alias)
                ?: throw NoSuchElementException("No key for alias $alias exists")
            return@memScoped corecall {
                SecKeyCopyExternalRepresentation(publicKey, error)
            }.let { it.takeFromCF<NSData>() }.toByteArray()
        }
        val attestation = getKeyAttestation(alias)
        return@catching when (val publicKey =
            CryptoPublicKey.fromIosEncoded(publicKeyBytes)) {
            is CryptoPublicKey.EC -> iosSigner.ECDSA(alias, attestation, config, publicKey)
            is CryptoPublicKey.Rsa -> iosSigner.RSA(alias, attestation, config, publicKey)
        }
    }}

    override suspend fun deleteSigningKey(alias: String) = withContext(keychainThreads) {
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
    }

}
