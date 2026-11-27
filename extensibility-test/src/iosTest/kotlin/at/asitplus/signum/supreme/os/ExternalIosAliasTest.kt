@file:OptIn(ExperimentalForeignApi::class, SignumInternals::class, HazardousMaterials::class)

package at.asitplus.signum.supreme.os

import at.asitplus.awesn1.Asn1Exception
import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.Signum
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.dsl.DISCOURAGED
import at.asitplus.signum.dsl.DSL
import at.asitplus.signum.dsl.IosSignerConfiguration
import at.asitplus.signum.dsl.IosSigningKeyConfiguration
import at.asitplus.signum.dsl.PREFERRED
import at.asitplus.signum.dsl.PlatformSigningKeyConfigurationBase
import at.asitplus.signum.dsl.REQUIRED
import at.asitplus.signum.dsl.attestation
import at.asitplus.signum.dsl.factors
import at.asitplus.signum.dsl.hardware
import at.asitplus.signum.dsl.protection
import at.asitplus.signum.indispensable.IosHomebrewAttestation
import at.asitplus.signum.indispensable.PublicKey
import at.asitplus.signum.indispensable.sign.SignatureInput
import at.asitplus.signum.indispensable.sign.SignatureVerifier
import at.asitplus.signum.indispensable.sign.UnlockFailed
import at.asitplus.signum.indispensable.sign.signature
import at.asitplus.signum.indispensable.sign.verifierFor
import at.asitplus.signum.indispensable.sign.verify
import at.asitplus.signum.supreme.hazmat.secKeyRef
import at.asitplus.signum.supreme.installSupreme
import at.asitplus.signum.supreme.sign.CursorySignatureScheme
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import platform.CoreFoundation.CFDictionaryRef
import platform.CoreFoundation.CFRelease
import platform.CoreFoundation.CFRetain
import platform.CoreFoundation.CFStringRef
import platform.DeviceCheck.DCAppAttestService
import platform.Foundation.CFBridgingRelease
import platform.Foundation.CFBridgingRetain
import platform.Foundation.NSBundle
import platform.LocalAuthentication.LAContext
import platform.LocalAuthentication.LAPolicyDeviceOwnerAuthentication
import platform.Security.*
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
import kotlin.uuid.Uuid

private class OpaqueTestOptions : DSL.Data() {
    var allowSigning = true
    var unencodablePublicKey = false
}

private val PlatformSigningKeyConfigurationBase<*>.opaqueTest
    get() = _algSpecific.option("at.asitplus.test.opaque", ::OpaqueTestOptions)

// The simulator uses the existing test-only scheme to exercise Keychain storage and dispatch.
private class ExternalOpaqueProvider : IosKeychainOperationsProvider {
    var available = true
    var failNextSignature = false
    var reopenDifferentKey = false
    var lastAuthenticationContext: LAContext? = null
        private set

    private val backend = object : OpaqueIosKeyBackend {
        override val backendId = "at.asitplus.test.opaque"

        override fun supports(config: IosSigningKeyConfiguration) = config.opaqueTest.v != null

        override suspend fun generate(
            config: IosSigningKeyConfiguration,
            accessControl: SecAccessControlRef,
        ): OpaqueIosKeyMaterial {
            val options = checkNotNull(config.opaqueTest.v)
            val key = CursorySignatureScheme.Key(true)
            return OpaqueIosKeyMaterial(
                representation = byteArrayOf(1, 1),
                publicKey = if (options.unencodablePublicKey) object : PublicKey by key {} else key,
                allowSigning = options.allowSigning,
            )
        }

        override suspend fun reopen(
            representationVersion: Int,
            representation: ByteArray,
            authenticationContext: LAContext?,
        ): OpenedKey {
            check(representationVersion == 1 && representation.contentEquals(byteArrayOf(1, 1)))
            lastAuthenticationContext = authenticationContext
            return object : OpenedKey {
                override val publicKey = CursorySignatureScheme.Key(!reopenDifferentKey)
                override suspend fun sign(message: ByteArray): CursorySignatureScheme.Signature {
                    if (failNextSignature) {
                        failNextSignature = false
                        throw UnlockFailed("simulated cancellation")
                    }
                    return publicKey.sign(SignatureInput(message)).signature
                }
            }
        }

        override fun signatureAlgorithm(publicKey: PublicKey, config: IosSignerConfiguration) = CursorySignatureScheme
    }

    override val opaqueKeyBackend get() = backend.takeIf { available }
    override fun getOperationsBundle(config: IosSigningKeyConfiguration) = null
    override fun makeIosSigner(
        alias: String,
        publicKey: PublicKey,
        metadata: IosKeyMetadata,
        config: IosSignerConfiguration,
    ) = null
}

private fun retagAsLegacy(alias: String) {
    fun CFStringRef?.string() = CFBridgingRelease(CFRetain(this)) as String
    val bundleId = checkNotNull(NSBundle.mainBundle.bundleIdentifier)
    for ((keyClass, tag) in listOf(
        kSecAttrKeyClassPublic to "supreme.publickey",
        kSecAttrKeyClassPrivate to "supreme.privatekey",
    )) {
        val query = CFBridgingRetain(mapOf(
            kSecClass.string() to kSecClassKey.string(),
            kSecAttrKeyClass.string() to keyClass.string(),
            kSecAttrApplicationLabel.string() to alias,
            kSecAttrApplicationTag.string() to tag,
        )) as CFDictionaryRef
        val update = CFBridgingRetain(mapOf(kSecAttrApplicationTag.string() to "$tag-$bundleId")) as CFDictionaryRef
        try {
            val status = SecItemUpdate(query, update)
            check(status == errSecSuccess) { "Retagging the legacy alias fixture failed with status $status" }
        } finally {
            CFRelease(query)
            CFRelease(update)
        }
    }
}

val ExternalIosAliasTest by matrixSuite {
    Signum.installSupreme()
    val adapter = ExternalOpaqueProvider()
    ServiceLoader.register<IosKeychainOperationsProvider>(adapter)

    "built-in aliases round trip through the platform signing provider" {
        val provider = PlatformSigningProvider
        val alias = "external-ios-ec-${Uuid.random()}"
        try {
            val created = provider.createSigningKey(alias).shouldBeInstanceOf<IosSigner.ECDSA>()
            val loaded = provider.getSignerForKey(alias).shouldBeInstanceOf<IosSigner.ECDSA>()
            loaded.publicKey shouldBe created.publicKey
            val data = byteArrayOf(1, 2, 3)
            val signature = loaded.sign(data).signature
            loaded.signatureAlgorithm.verifierFor(created.publicKey).verify(data, signature) shouldBe
                SignatureVerifier.Success
        } finally {
            provider.deleteSigningKey(alias)
        }
        shouldThrow<NoSuchElementException> { provider.getSignerForKey(alias) }
    }

    "legacy bundle-tagged aliases still load, sign, and delete" {
        val provider = PlatformSigningProvider
        val alias = "external-ios-legacy-${Uuid.random()}"
        try {
            val original = provider.createSigningKey(alias)
            retagAsLegacy(alias)
            shouldThrow<NoSuchElementException> { provider.createSigningKey(alias) }
            val loaded = provider.getSignerForKey(alias)
            loaded.publicKey shouldBe original.publicKey
            val data = byteArrayOf(1, 2, 3)
            loaded.signatureAlgorithm.verifierFor(loaded.publicKey).verify(data, loaded.sign(data).signature) shouldBe
                SignatureVerifier.Success
        } finally {
            provider.deleteSigningKey(alias)
        }
        shouldThrow<NoSuchElementException> { provider.getSignerForKey(alias) }
    }

    "external opaque aliases use native Keychain storage and platform signing" {
        val provider = PlatformSigningProvider
        val alias = "external-ios-opaque-${Uuid.random()}"
        val builtinAlias = "external-ios-ec-${Uuid.random()}"
        val deniedAlias = "external-ios-denied-${Uuid.random()}"
        val message = byteArrayOf(1, 2, 3)
        try {
            shouldThrow<UnsupportedCryptoException> {
                provider.createSigningKey(alias) {
                    opaqueTest {}
                    hardware { backing = DISCOURAGED }
                }
            }
            shouldThrow<NoSuchElementException> { provider.getSignerForKey(alias) }

            shouldThrow<Asn1Exception> {
                provider.createSigningKey(alias) {
                    opaqueTest { unencodablePublicKey = true }
                    hardware { backing = REQUIRED }
                }
            }
            shouldThrow<NoSuchElementException> { provider.getSignerForKey(alias) }

            if (!DCAppAttestService.sharedService.isSupported()) {
                shouldThrow<UnsupportedCryptoException> {
                    provider.createSigningKey(alias) {
                        opaqueTest {}
                        hardware {
                            backing = REQUIRED
                            attestation { challenge = message }
                        }
                    }
                }
                shouldThrow<NoSuchElementException> { provider.getSignerForKey(alias) }

                val preferred = provider.createSigningKey(alias) {
                    opaqueTest {}
                    hardware {
                        backing = PREFERRED
                        attestation { challenge = message }
                    }
                }.shouldBeInstanceOf<IosSigner>()
                preferred.attestation shouldBe null
                provider.deleteSigningKey(alias)
            }

            provider.createSigningKey(deniedAlias) {
                opaqueTest { allowSigning = false }
                hardware { backing = REQUIRED }
            }
            val denied = provider.getSignerForKey(deniedAlias)
            shouldThrow<IllegalArgumentException> { denied.sign(message).signature }

            val builtin = provider.createSigningKey(builtinAlias)
            shouldThrow<NoSuchElementException> {
                provider.createSigningKey(builtinAlias) {
                    opaqueTest {}
                    hardware { backing = REQUIRED }
                }
            }
            provider.getSignerForKey(builtinAlias).publicKey shouldBe builtin.publicKey

            val created = provider.createSigningKey(alias) {
                opaqueTest {}
                hardware { backing = REQUIRED }
            }.shouldBeInstanceOf<IosSigner>()
            shouldThrow<NoSuchElementException> { provider.createSigningKey(alias) }
            val loaded = provider.getSignerForKey(alias).shouldBeInstanceOf<IosSigner>()
            loaded.publicKey shouldBe created.publicKey
            loaded.publicKey.shouldBeInstanceOf<CursorySignatureScheme.Key>()
            loaded.secKeyRef shouldBe null
            val clientData = IosHomebrewAttestation.ClientData(loaded.publicKey, message)
            val clientDataJson = clientData.prepareDigestInput().decodeToString()
            Json.parseToJsonElement(clientDataJson).jsonObject["version"] shouldBe JsonPrimitive(2)
            Json.decodeFromString<IosHomebrewAttestation.ClientData>(clientDataJson) shouldBe clientData

            val signature = loaded.sign(message).signature
            loaded.signatureAlgorithm.verifierFor(loaded.publicKey).verify(message, signature) shouldBe
                SignatureVerifier.Success

            adapter.reopenDifferentKey = true
            adapter.failNextSignature = true
            shouldThrow<IllegalArgumentException> { loaded.sign(message).signature }
            adapter.failNextSignature shouldBe true
            adapter.reopenDifferentKey = false
            adapter.failNextSignature = false

            if (LAContext().canEvaluatePolicy(LAPolicyDeviceOwnerAuthentication, null)) {
                for (timeout in listOf(Duration.ZERO, 30.seconds)) {
                    val protectedAlias = "external-ios-auth-${Uuid.random()}"
                    try {
                        val protected = provider.createSigningKey(protectedAlias) {
                            opaqueTest {}
                            hardware {
                                backing = REQUIRED
                                protection {
                                    this.timeout = timeout
                                    factors { biometry = false; deviceLock = true }
                                }
                            }
                        }.shouldBeInstanceOf<IosSigner>()
                        protected.authenticationTimeout shouldBe timeout
                        val beforePrewarming = adapter.lastAuthenticationContext
                        protected.trySetupUninterruptedSigning()
                        (adapter.lastAuthenticationContext === beforePrewarming) shouldBe true

                        adapter.failNextSignature = true
                        shouldThrow<UnlockFailed> { protected.sign(message).signature }
                        val failedContext = checkNotNull(adapter.lastAuthenticationContext)
                        val _ = protected.sign(message).signature
                        val successfulContext = checkNotNull(adapter.lastAuthenticationContext)
                        (successfulContext === failedContext) shouldBe false
                        val _ = protected.sign(message).signature
                        (adapter.lastAuthenticationContext === successfulContext) shouldBe (timeout > Duration.ZERO)
                    } finally {
                        provider.deleteSigningKey(protectedAlias)
                    }
                }
            }

            adapter.available = false
            shouldThrow<UnsupportedCryptoException> { provider.getSignerForKey(alias) }
            provider.deleteSigningKey(alias)
            shouldThrow<NoSuchElementException> { provider.getSignerForKey(alias) }

            adapter.available = true
            provider.createSigningKey(alias) {
                opaqueTest {}
                hardware { backing = REQUIRED }
            }
            shouldThrowAny { loaded.sign(message).signature }
        } finally {
            adapter.available = true
            provider.deleteSigningKey(alias)
            provider.deleteSigningKey(builtinAlias)
            provider.deleteSigningKey(deniedAlias)
        }
    }
}
