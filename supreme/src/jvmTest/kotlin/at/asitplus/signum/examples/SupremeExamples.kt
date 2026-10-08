@file:OptIn(at.asitplus.signum.indispensable.SecretExposure::class, ExperimentalStdlibApi::class)
package at.asitplus.signum.examples

import at.asitplus.signum.Signum
import at.asitplus.signum.dsl.*
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.agree.KeyAgreementPrivateValue
import at.asitplus.signum.indispensable.agree.keyAgreement
import at.asitplus.signum.indispensable.digest.*
import at.asitplus.signum.indispensable.mac.*
import at.asitplus.signum.indispensable.kdf.*
import at.asitplus.signum.indispensable.misc.bytes
import at.asitplus.signum.indispensable.sign.*
import at.asitplus.signum.indispensable.symmetric.*
import at.asitplus.signum.indispensable.asymmetric.AsymmetricEncryptionAlgorithm
import at.asitplus.signum.supreme.installSupreme
import at.asitplus.signum.supreme.agree.Ephemeral
import at.asitplus.signum.supreme.asymmetric.*
import at.asitplus.signum.supreme.kdf.*
import at.asitplus.signum.supreme.os.JKSProvider
import at.asitplus.signum.supreme.symmetric.*
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.shouldBe
import java.nio.file.Files
import java.security.KeyStore

val SupremeExamples by matrixSuite {
    "Provider setup" {
        // --8<-- [start:supreme-bootstrap]
        Signum.installSupreme() // install once at application startup, before registering overrides
        Digest.SHA256.digest(byteArrayOf()).size shouldBe 32
        // --8<-- [end:supreme-bootstrap]
    }
    "Provider and key management" {
        val directory = Files.createTempDirectory("signum-docs")
        try {
            val keystorePath = directory.resolve("keys.p12")
            // --8<-- [start:supreme-jks-file]
            val fileProvider = JKSProvider {
                file { file = keystorePath; password = "example-password".toCharArray() }
            }
            val persistentSigner = fileProvider.createSigningKey("persistent")
            fileProvider.getSignerForKey("persistent").publicKey shouldBe persistentSigner.publicKey
            // --8<-- [end:supreme-jks-file]
            // --8<-- [start:supreme-jks-memory]
            val keyStore = KeyStore.getInstance("PKCS12").apply { load(null, null) }
            val prov = JKSProvider { withBackingObject { store = keyStore } }
            // --8<-- [end:supreme-jks-memory]
            // --8<-- [start:supreme-key-ec]
            val ecSigner = prov.createSigningKey("ec") {
                ec { curve = ECCurve.SECP_256_R_1; digests = setOf(Digest.SHA256) }
            }
            ecSigner.publicKey shouldBe prov.getSignerForKey("ec").publicKey
            // --8<-- [end:supreme-key-ec]
            // --8<-- [start:supreme-key-rsa]
            val rsaSigner = prov.createSigningKey("rsa") {
                rsa { bits = 2048; digests = setOf(Digest.SHA256); paddings = setOf(RsaAlgorithm.Padding.PSS) }
            }
            rsaSigner.makeVerifier().verify("RSA".encodeToByteArray(), rsaSigner.sign("RSA".encodeToByteArray()).signature) shouldBe SignatureVerifier.Success
            // --8<-- [end:supreme-key-rsa]
            // --8<-- [start:supreme-key-agreement-purpose]
            val agreementSigner = prov.createSigningKey("agreement") {
                ec { purposes { keyAgreement = true; signing = true } }
            }
            agreementSigner.alias shouldBe "agreement"
            // --8<-- [end:supreme-key-agreement-purpose]
            // --8<-- [start:supreme-key-loading]
            val loaded = prov.getSignerForKey("ec") { ec { digest = Digest.SHA256 } }
            loaded.publicKey shouldBe ecSigner.publicKey
            // --8<-- [end:supreme-key-loading]
            // --8<-- [start:supreme-key-deletion]
            prov.deleteSigningKey("ec")
            shouldThrowAny { prov.getSignerForKey("ec") }
            // --8<-- [end:supreme-key-deletion]
        } finally {
            Files.deleteIfExists(directory.resolve("keys.p12"))
            Files.deleteIfExists(directory)
        }
    }
    "Signing, verification and private keys" {
        // --8<-- [start:supreme-ephemeral]
        val signer = Signer.Ephemeral { ec { curve = ECCurve.SECP_256_R_1; digest = Digest.SHA256 } }
        // --8<-- [end:supreme-ephemeral]
        // --8<-- [start:supreme-signing]
        val data = "You want to trust this.".encodeToByteArray()
        val signature = signer.sign(data).signature /* (1)! */
        // --8<-- [end:supreme-signing]
        // --8<-- [start:supreme-verification]
        val verifier = signer.signatureAlgorithm.verifierFor(signer.publicKey)
        verifier.verify(data, signature) shouldBe SignatureVerifier.Success
        shouldThrowAny { verifier.verify("tampered".encodeToByteArray(), signature) } /* (1)! */
        // --8<-- [end:supreme-verification]
        // --8<-- [start:supreme-private-key]
        val privateKey = signer.exportPrivateKey() // requires SecretExposure opt-in
        // --8<-- [start:supreme-private-key-decode]
        val pem = Signum.Der.encodeToPem(privateKey)
        val decoded = Signum.Der.decodeFromPem<CryptoPrivateKey>(pem) as CryptoPrivateKey.WithPublicKey
        // --8<-- [end:supreme-private-key-decode]
        // --8<-- [start:supreme-private-key-import]
        val importedSigner = signer.signatureAlgorithm.signerFor(decoded)
        importedSigner.makeVerifier().verify(data, importedSigner.sign(data).signature) shouldBe SignatureVerifier.Success
        // --8<-- [end:supreme-private-key-import]
        // --8<-- [end:supreme-private-key]
    }
    "Digest and HMAC" {
        // --8<-- [start:supreme-digest]
        val digest = Digest.SHA256.digest("abc".encodeToByteArray())
        digest.toHexString() shouldBe "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        // --8<-- [end:supreme-digest]
        // --8<-- [start:supreme-hmac]
        val mac = HMAC.SHA256.mac(ByteArray(20) { 0x0b }, "Hi There".encodeToByteArray())
        mac.toHexString() shouldBe "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        // --8<-- [end:supreme-hmac]
    }
    "Symmetric encryption" {
        // --8<-- [start:supreme-symmetric]
        val secret = "Top Secret".encodeToByteArray()
        val algorithm = SymmetricEncryptionAlgorithm.ChaCha20Poly1305
        val secretKey = algorithm.randomKey()
        val encrypted = secretKey.encrypt(secret).getOrThrow() /* (1)! */
        encrypted.decrypt(secretKey).getOrThrow() shouldBe secret
        // --8<-- [end:supreme-symmetric]
        // --8<-- [start:supreme-symmetric-components]
        val nonce = encrypted.nonce
        val ciphertext = encrypted.encryptedData
        val authTag = encrypted.authTag
        val keyBytes = secretKey.secretKey.getOrThrow()
        val preSharedKey = algorithm.keyFrom(keyBytes).getOrThrow()
        // --8<-- [end:supreme-symmetric-components]
        // --8<-- [start:supreme-symmetric-external]
        val box = algorithm.sealedBox.withNonce(nonce).from(ciphertext, authTag).getOrThrow()
        box.decrypt(preSharedKey).getOrThrow() shouldBe secret
        preSharedKey.decrypt(nonce, ciphertext, authTag).getOrThrow() shouldBe secret
        // --8<-- [end:supreme-symmetric-external]
        // --8<-- [start:supreme-cbc-hmac]
        val customAlgorithm = SymmetricEncryptionAlgorithm.AES_192.CBC.HMAC.SHA_512
            .Custom(32.bytes) { ciphertext, iv, aad -> aad + iv + ciphertext }
        val key = customAlgorithm.randomKey(macKeyLength = 32.bytes)
        val aad = "fixed application context".encodeToByteArray()
        val payload = "More matter, with less art!".encodeToByteArray()
        val sealedBox = key.encrypt(payload, authenticatedData = aad).getOrThrow()
        sealedBox.decrypt(key, aad).getOrThrow() shouldBe payload
        val reconstructed = customAlgorithm.sealedBox.withNonce(sealedBox.nonce)
            .from(sealedBox.encryptedData, sealedBox.authTag).getOrThrow()
        reconstructed.decrypt(customAlgorithm.keyFrom(key.encryptionKey.getOrThrow(), key.macKey.getOrThrow()).getOrThrow(), aad)
            .getOrThrow() shouldBe payload
        // --8<-- [end:supreme-cbc-hmac]
    }
    "RSA encryption" {
        // --8<-- [start:supreme-rsa-encryption]
        val rsaSigner = Signer.Ephemeral { rsa { bits = 2048 } }
        val key = rsaSigner.exportPrivateKey() as RsaPrivateKey
        val algorithm = AsymmetricEncryptionAlgorithm.RSA.OAEP.SHA256
        val plaintext = "Short RSA message".encodeToByteArray()
        val encrypted = algorithm.encryptorFor(key.publicKey).encrypt(plaintext).getOrThrow()
        algorithm.decryptorFor(key).decrypt(encrypted).getOrThrow() shouldBe plaintext
        // --8<-- [end:supreme-rsa-encryption]
    }
    "Key derivation" {
        // --8<-- [start:supreme-kdf]
        val ikm = "input key material".encodeToByteArray()
        val salt = "example salt".encodeToByteArray()
        val info = "application context".encodeToByteArray()
        val hkdf = HKDF.SHA256(info)
        val derived = hkdf.deriveKey(salt, ikm, 32.bytes)
        HKDF.SHA256.expandStep(HKDF.SHA256.extractStep(salt, ikm), info, 32.bytes) shouldBe derived
        PBKDF2.HMAC_SHA256(iterations = 1000).deriveKey(salt, ikm, 32.bytes).size shouldBe 32
        SCrypt(cost = 16, parallelization = 1, blockSize = 1).deriveKey(salt, ikm, 32.bytes).size shouldBe 32
        // --8<-- [end:supreme-kdf]
    }
    "ECDH" {
        // --8<-- [start:supreme-agreement]
        val alice = KeyAgreementPrivateValue.ECDH.Ephemeral(ECCurve.SECP_256_R_1)
        val bob = KeyAgreementPrivateValue.ECDH.Ephemeral(ECCurve.SECP_256_R_1)
        alice.keyAgreement(bob.publicValue) shouldBe bob.keyAgreement(alice.publicValue)
        // --8<-- [end:supreme-agreement]
    }
}
