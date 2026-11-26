@file:OptIn(at.asitplus.signum.SignumInternals::class)

package at.asitplus.signum.extensibility.test

import android.app.KeyguardManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import androidx.test.platform.app.InstrumentationRegistry
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.Signum
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.dsl.*
import at.asitplus.signum.indispensable.AndroidKeystoreAttestation
import at.asitplus.signum.indispensable.PublicKey
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.parseJCASignature
import at.asitplus.signum.indispensable.sign.*
import at.asitplus.signum.supreme.installSupreme
import at.asitplus.signum.supreme.os.*
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import java.security.KeyPair
import java.security.PrivateKey
import java.security.spec.ECGenParameterSpec
import java.util.UUID
import kotlin.time.Duration.Companion.seconds

private class ExternalTeeConfiguration : DSL.Data()
private val AndroidSigningKeyConfiguration.externalTee get() =
    _algSpecific.option("EXT_TEST_TEE_ECDSA", ::ExternalTeeConfiguration)

private object ExternalTeeProvider : AndroidKeyStoreOperationsProvider {
    override fun initKeyGenSpec(
        alias: String,
        config: AndroidSigningKeyConfiguration,
    ): Pair<String, KeyGenParameterSpec.Builder>? {
        if (config.externalTee.v == null) return null
        return KeyProperties.KEY_ALGORITHM_EC to KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
    }

    override fun generateKeyPair(alias: String, config: AndroidSigningKeyConfiguration): KeyPair? {
        val (algorithm, builder) = initKeyGenSpec(alias, config) ?: return null
        check(!alias.startsWith("external-tee-generation-failure-")) { "test generation failure" }
        return generateAndroidKeystoreKeyPair(alias, config, algorithm, builder, supportsStrongBox = false)
    }

    override fun getAndroidKeystoreSigner(
        jcaPrivateKey: PrivateKey,
        alias: String,
        keyInfo: KeyInfo,
        config: AndroidSignerConfiguration,
        publicKey: PublicKey,
        attestation: AndroidKeystoreAttestation?,
    ): AndroidKeystoreSigner? {
        // The fixture uses real EC keys. The alias prefix distinguishes them from built-in EC keys.
        if (!alias.startsWith("external-tee-") || publicKey !is EcdsaPublicKey) return null
        check(!alias.startsWith("external-tee-signer-failure-")) { "test signer construction failure" }
        return object : AndroidKeystoreSigner(jcaPrivateKey, alias, keyInfo, "SHA256withECDSA", config, attestation) {
            override val publicKey = publicKey
            override val signatureAlgorithm = EcdsaAlgorithm(Digest.SHA256, publicKey.curve)
            override fun parseSignatureFromJca(jcaSig: ByteArray) = signatureAlgorithm.parseJCASignature(jcaSig)
        }
    }
}

private object FallbackProbeProvider : AndroidKeyStoreOperationsProvider by SupremeAndroidKeyStoreOperationsProvider {
    override fun generateKeyPair(alias: String, config: AndroidSigningKeyConfiguration): KeyPair? {
        check(!alias.startsWith("external-tee-generation-failure-")) { "generation fell through after an error" }
        return null
    }
}

val AndroidProviderReuseTests by matrixSuite {
    Signum.installSupreme()
    ServiceLoader.register<AndroidKeyStoreOperationsProvider>(FallbackProbeProvider)
    ServiceLoader.register<AndroidKeyStoreOperationsProvider>(ExternalTeeProvider)
    val provider = AndroidKeyStoreProvider

    "external TEE provider creates, reloads, signs, and deletes" {
        val alias = "external-tee-" + UUID.randomUUID()
        val builtinAlias = "builtin-" + UUID.randomUUID()
        try {
            val created = provider.createSigningKey(alias) {
                externalTee {}
                hardware {
                    strongBox = PREFERRED
                    attestation { challenge = byteArrayOf(1, 2, 3) }
                }
            }
            (created is AndroidKeystoreSigner.ECDSA) shouldBe false
            created.keyInfo.keySize shouldBe 256
            (created.isStrongBoxBacked != true) shouldBe true
            if (created.isInsideSecureHardware) {
                (checkNotNull(created.attestation).certificateChain.size > 1) shouldBe true
            }

            shouldThrow<NoSuchElementException> { provider.createSigningKey(alias) }
            val loaded = provider.getSignerForKey(alias)
            loaded.publicKey shouldBe created.publicKey
            (loaded is AndroidKeystoreSigner.ECDSA) shouldBe false
            val data = byteArrayOf(4, 5, 6)
            val signature = loaded.sign(data).signature
            loaded.signatureAlgorithm.verifierFor(loaded.publicKey).verify(data, signature) shouldBe SignatureVerifier.Success

            val builtin = provider.createSigningKey(builtinAlias).shouldBeInstanceOf<AndroidKeystoreSigner.ECDSA>()
            builtin.signatureAlgorithm.verifierFor(builtin.publicKey).verify(data, builtin.sign(data).signature) shouldBe
                SignatureVerifier.Success

            if (!created.isInsideSecureHardware) {
                val requiredAlias = "external-tee-required-backing-" + UUID.randomUUID()
                try {
                    shouldThrow<UnsupportedCryptoException> {
                        provider.createSigningKey(requiredAlias) {
                            externalTee {}
                            hardware { backing = REQUIRED }
                        }
                    }
                    shouldThrow<NoSuchElementException> { provider.getSignerForKey(requiredAlias) }
                    provider.getSignerForKey(alias).publicKey shouldBe created.publicKey
                } finally {
                    provider.deleteSigningKey(requiredAlias)
                }
            }
        } finally {
            provider.deleteSigningKey(alias)
            provider.deleteSigningKey(builtinAlias)
        }
        shouldThrow<NoSuchElementException> { provider.getSignerForKey(alias) }
    }

    "TEE-only keys reject REQUIRED StrongBox before generation" {
        val alias = "external-tee-strongbox-" + UUID.randomUUID()
        try {
            shouldThrow<UnsupportedCryptoException> {
                provider.createSigningKey(alias) {
                    externalTee {}
                    hardware { strongBox = REQUIRED }
                }
            }
            shouldThrow<NoSuchElementException> { provider.getSignerForKey(alias) }
        } finally {
            provider.deleteSigningKey(alias)
        }
    }

    "generation failures retain their diagnostic" {
        val alias = "external-tee-generation-failure-" + UUID.randomUUID()
        val error = shouldThrow<IllegalStateException> {
            provider.createSigningKey(alias) {
                externalTee {}
                hardware { strongBox = PREFERRED }
            }
        }
        error.message shouldBe "test generation failure"
        shouldThrow<NoSuchElementException> { provider.getSignerForKey(alias) }
    }

    "signer construction failure rolls back the new alias" {
        val alias = "external-tee-signer-failure-" + UUID.randomUUID()
        try {
            shouldThrow<UnsupportedCryptoException> {
                provider.createSigningKey(alias) {
                    externalTee {}
                    signer { ec { digest = Digest.SHA512 } }
                }
            }
            shouldThrow<NoSuchElementException> { provider.getSignerForKey(alias) }
        } finally {
            provider.deleteSigningKey(alias)
        }
    }

    "native authentication policy is applied to external keys" {
        val alias = "external-tee-auth-" + UUID.randomUUID()
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        suspend fun createProtected() = provider.createSigningKey(alias) {
            externalTee {}
            hardware {
                protection {
                    timeout = 30.seconds
                    factors {
                        biometry = false
                        deviceLock = true
                    }
                }
            }
        }
        try {
            if (context.getSystemService(KeyguardManager::class.java)?.isDeviceSecure == true) {
                val signer = createProtected()
                signer.keyInfo.isUserAuthenticationRequired shouldBe true
                signer.keyInfo.userAuthenticationValidityDurationSeconds shouldBe 30
                signer.mayRequireUserUnlock shouldBe true
            } else {
                shouldThrowAny { createProtected() }
                shouldThrow<NoSuchElementException> { provider.getSignerForKey(alias) }
            }
        } finally {
            provider.deleteSigningKey(alias)
        }
    }
}
