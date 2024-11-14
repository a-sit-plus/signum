package at.asitplus.signum.supreme.os

import at.asitplus.signum.indispensable.*
import at.asitplus.signum.supreme.UnsupportedCryptoException
import at.asitplus.signum.supreme.sign.*
import at.asitplus.signum.supreme.signature
import at.asitplus.signum.supreme.succeed
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.should
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNot
import io.kotest.property.azstring
import java.nio.file.Files
import kotlin.random.Random

class JKSProviderTest : FreeSpec({
    "Ephemeral" {
        val ks = JKSProvider.Ephemeral().getOrThrow()
        val alias = "Elfenbeinschloss"
        ks.getSignerForKey(alias) shouldNot succeed
        val signer = ks.createSigningKey(alias).getOrThrow()
        val otherSigner = ks.getSignerForKey(alias).getOrThrow()

        val data = Random.Default.nextBytes(64)
        val signature = signer.sign(data).signature
        otherSigner.makeVerifier().getOrThrow().verify(data, signature) should succeed
    }
    "File-based persistence" {
        val tempfile = Files.createTempFile(Random.azstring(16),null).also { Files.delete(it) }
        try {
            val alias = "Elfenbeinturm"
            val correctPassword = "Schwertfischfilet".toCharArray()
            val wrongPassword = "Bartfischfilet".toCharArray()

            val ks1 = JKSProvider {
                file {
                    file = tempfile
                    password = correctPassword
                }
            }.getOrThrow().also {
                it.getSignerForKey(alias) shouldNot succeed
                it.createSigningKey(alias) should succeed
                it.createSigningKey(alias) shouldNot succeed
                it.getSignerForKey(alias) should succeed
                it.deleteSigningKey(alias)
                it.getSignerForKey(alias) shouldNot succeed
                it.createSigningKey(alias) should succeed
            }

            JKSProvider {
                file {
                    file = tempfile
                    password = wrongPassword
                }
            }.getOrThrow().let {
                // wrong password should fail
                it.getSignerForKey(alias) shouldNot succeed
            }

            JKSProvider {
                file {
                    file = tempfile
                    password = correctPassword
                }
            }.getOrThrow().let {
                it.getSignerForKey(alias) should succeed
                it.deleteSigningKey(alias)
            }

            // check that ks1 "sees" the deletion that was made by ks3
            ks1.getSignerForKey(alias) shouldNot succeed
        } finally { Files.deleteIfExists(tempfile) }
    }
    "Certificate encoding" - {
        withData(TestSuites.ALL) { test ->
            val alias = Random.azstring(16)
            val ks = JKSProvider().getOrThrow()
            val signer = ks.createSigningKey(alias) {
                test.configure(this)
            }.getOrThrow()

            val data = SignatureInput(Random.nextBytes(1200)).let {
                if (test.isPreHashed) it.convertTo(signer.signatureAlgorithm.preHashedSignatureFormat).getOrThrow()
                else it
            }
            val signature = try {
                signer.sign(data).signature
            } catch (x: UnsupportedOperationException) {
                return@withData
            }
            CryptoSignature.parseFromJca(signature.jcaSignatureBytes, signer.signatureAlgorithm) shouldBe signature
            when (signer.signatureAlgorithm) {
                is SignatureAlgorithm.RSA, is SignatureAlgorithm.HMAC ->
                    CryptoSignature.RSAorHMAC.parseFromJca(signature.jcaSignatureBytes) shouldBe signature
                is SignatureAlgorithm.ECDSA ->
                    CryptoSignature.EC.parseFromJca(signature.jcaSignatureBytes) shouldBe signature
            }

            signer.signatureAlgorithm.let {
                if (test.isPreHashed) it.getJCASignatureInstancePreHashed()
                else it.getJCASignatureInstance()
            }.getOrThrow().let { sig ->
                sig.initVerify(signer.publicKey.getJcaPublicKey().getOrThrow())
                data.data.forEach(sig::update)
                sig.verify(signature.jcaSignatureBytes) shouldBe true
            }
        }
    }
})
