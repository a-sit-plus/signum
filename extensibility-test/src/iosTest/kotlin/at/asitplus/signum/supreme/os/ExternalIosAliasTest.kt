@file:OptIn(ExperimentalForeignApi::class, SignumInternals::class)

package at.asitplus.signum.supreme.os

import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.Signum
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.dsl.*
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.sign.*
import at.asitplus.signum.internals.CFDictionaryInitScope
import at.asitplus.signum.supreme.installSupreme
import at.asitplus.signum.supreme.sign.SupremeCCVerifier
import at.asitplus.signum.supreme.sign.SupremeCCVerifierProvider
import at.asitplus.signum.supreme.sign.InvalidSignature
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.serialization.json.JsonPrimitive
import platform.CoreFoundation.CFDictionaryRef
import platform.CoreFoundation.CFRelease
import platform.CoreFoundation.CFRetain
import platform.CoreFoundation.CFStringRef
import platform.Foundation.CFBridgingRelease
import platform.Foundation.CFBridgingRetain
import platform.Foundation.NSBundle
import platform.Security.*
import kotlin.uuid.Uuid

private object ExternalSha224 : SignatureAlgorithm {
    override val sourceRepresentation = SourceRepresentationStorage()
}

private class Sha224Options : DSL.Data() {
    var allowSigning = true
}

private val PlatformSigningKeyConfigurationBase<*>.sha224
    get() = _algSpecific.option("external.ecdsa.sha224", ::Sha224Options)

private val SignerConfiguration.failExternalSigner
    get() = childOrNull("external.test.fail") { DSL.Data() }

private class ExternalSha224Signer(
    alias: String,
    override val publicKey: EcdsaPublicKey,
    metadata: IosKeyMetadata,
    config: IosSignerConfiguration,
) : IosSigner(alias, metadata, config) {
    override val secKeyType get() = kSecAttrKeyTypeEC
    override val signatureAlgorithm = ExternalSha224
    override fun bytesToSignature(sigBytes: ByteArray) = signatureAlgorithm.parseSecKeySignature(sigBytes)
}

private object ExternalSha224Provider :
    IosKeychainOperationsProvider, IosMappingProvider, SignatureVerifierProvider {

    private val algorithmMetadata = JsonPrimitive("external.ecdsa.sha224")

    override fun getOperationsBundle(config: IosSigningKeyConfiguration): IosKeychainOperationsProvider.OperationsBundle? {
        val options = config.sha224.v ?: return null
        return object : IosKeychainOperationsProvider.OperationsBundle {
            override fun CFDictionaryInitScope.initTopLevelDictionary() {
                kSecAttrKeyType mapsTo kSecAttrKeyTypeEC
                kSecAttrKeySizeInBits mapsTo 256
            }

            override fun CFDictionaryInitScope.initPrivateKeyDictionary() {
                kSecAttrCanSign mapsTo options.allowSigning
                kSecAttrCanDecrypt mapsTo false
                kSecAttrCanDerive mapsTo false
            }

            override fun GetAlgSpecificMetadata() = algorithmMetadata
        }
    }

    override fun makeIosSigner(
        alias: String, publicKey: PublicKey, metadata: IosKeyMetadata, config: IosSignerConfiguration,
    ): IosSigner? {
        if (metadata.algSpecific != algorithmMetadata || publicKey !is EcdsaPublicKey) return null
        check(config.failExternalSigner.v == null) { "external signer setup failed" }
        return ExternalSha224Signer(alias, publicKey, metadata, config)
    }

    override fun signatureAlgorithmToSecKeyAlgorithm(algorithm: SignatureAlgorithm) =
        kSecKeyAlgorithmECDSASignatureMessageX962SHA224.takeIf { algorithm === ExternalSha224 }

    override fun parseSignatureBytes(algorithm: SignatureAlgorithm, sigBytes: ByteArray): Signature? =
        if (algorithm === ExternalSha224) EcdsaSignature.fromRawSignatureValue(sigBytes).withCurve(ECCurve.SECP_256_R_1)
        else null

    override fun verifierFor(
        algorithm: SignatureAlgorithm, key: PublicKey, config: VerifierConfiguration,
    ): SignatureVerifier? {
        if (algorithm !== ExternalSha224 || key !is EcdsaPublicKey) return null
        return object : SupremeCCVerifier() {
            override val signatureAlgorithm = ExternalSha224
            override val publicKey = key
        }
    }
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
    ServiceLoader.register<IosKeychainOperationsProvider>(ExternalSha224Provider)
    ServiceLoader.register<IosMappingProvider>(ExternalSha224Provider)
    ServiceLoader.register<SignatureVerifierProvider>(ExternalSha224Provider)

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

    "external SHA-224 reuses native generation, metadata, key lookup, and signing" {
        val provider = PlatformSigningProvider
        val alias = "external-ios-sha224-${Uuid.random()}"
        val message = byteArrayOf(1, 2, 3)
        try {
            val created = provider.createSigningKey(alias) { sha224 {} }.shouldBeInstanceOf<ExternalSha224Signer>()
            created.signatureAlgorithm shouldBe ExternalSha224
            created.needsAuthentication shouldBe false
            shouldThrow<NoSuchElementException> { provider.createSigningKey(alias) { sha224 {} } }

            val loaded = provider.getSignerForKey(alias).shouldBeInstanceOf<ExternalSha224Signer>()
            (loaded === created) shouldBe false
            loaded.publicKey shouldBe created.publicKey
            loaded.signatureAlgorithm shouldBe ExternalSha224
            val verifier = ExternalSha224.verifierFor(loaded.publicKey) {
                SupremeCCVerifierProvider.verifierFor(ExternalSha224, loaded.publicKey, this) shouldBe null
            }
            val signature = loaded.sign(message).signature
            verifier.verify(message, signature) shouldBe SignatureVerifier.Success
            shouldThrow<InvalidSignature> { verifier.verify(byteArrayOf(4, 5, 6), signature) }
        } finally {
            provider.deleteSigningKey(alias)
        }
        shouldThrow<NoSuchElementException> { provider.getSignerForKey(alias) }
    }

    "external signer preserves the native signing permission" {
        val provider = PlatformSigningProvider
        val alias = "external-ios-denied-${Uuid.random()}"
        try {
            provider.createSigningKey(alias) { sha224 { allowSigning = false } }
            val loaded = provider.getSignerForKey(alias).shouldBeInstanceOf<ExternalSha224Signer>()
            shouldThrow<IllegalArgumentException> { loaded.sign(byteArrayOf(1)).signature }
        } finally {
            provider.deleteSigningKey(alias)
        }
    }

    "external signer construction failure cleans up the generated keys" {
        val provider = PlatformSigningProvider
        val alias = "external-ios-failure-${Uuid.random()}"
        try {
            shouldThrow<UnsupportedCryptoException> {
                provider.createSigningKey(alias) {
                    sha224 {}
                    signer { failExternalSigner {} }
                }
            }
            shouldThrow<NoSuchElementException> { provider.getSignerForKey(alias) }
            provider.createSigningKey(alias) { sha224 {} }.shouldBeInstanceOf<ExternalSha224Signer>()
        } finally {
            provider.deleteSigningKey(alias)
        }
    }
}
