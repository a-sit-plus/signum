package at.asitplus.signum.examples

import at.asitplus.signum.indispensable.misc.bytes
import at.asitplus.signum.supreme.asymmetric.HPKE
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.shouldBe

val HpkeExamples by matrixSuite {
    "Base and context" {
        // --8<-- [start:hpke-base]
        val kem = HPKE.KEM.DHKEM_P256_HKDF_SHA256
        val suite = HPKE(kem, HPKE.KDF.HKDF_SHA256, HPKE.AEAD.AES_128_GCM)
        val recipient = kem.GenerateKeyPair()
        val info = "application protocol v1".encodeToByteArray()
        val aad = "message header".encodeToByteArray()
        val plaintext = "Top Secret".encodeToByteArray()
        val sealed = suite.SealBase(recipient.pk, info, aad, plaintext)
        suite.OpenBase(sealed.encapsulatedSecret, recipient.sk, info, aad, sealed.ciphertext) shouldBe plaintext
        shouldThrowAny { suite.OpenBase(sealed.encapsulatedSecret, recipient.sk, info, byteArrayOf(), sealed.ciphertext) }
        // --8<-- [end:hpke-base]
        // --8<-- [start:hpke-context]
        val sender = suite.SetupBaseS(recipient.pk, info)
        val receiver = suite.SetupBaseR(sender.encapsulatedSecret, recipient.sk, info)
        repeat(3) { sequence ->
            val message = "Message $sequence".encodeToByteArray()
            receiver.Open(aad, sender.context.Seal(aad, message)) shouldBe message
        }
        // --8<-- [end:hpke-context]
    }
    "PSK and authenticated modes" {
        // --8<-- [start:hpke-psk-auth]
        val kem = HPKE.KEM.DHKEM_P256_HKDF_SHA256
        val suite = HPKE(kem, HPKE.KDF.HKDF_SHA256, HPKE.AEAD.AES_256_GCM)
        val recipient = kem.GenerateKeyPair()
        val sender = kem.GenerateKeyPair()
        val psk = ByteArray(32) { it.toByte() } // fixed test fixture; use a securely distributed secret!
        val pskId = "pre-shared-key-id".encodeToByteArray()
        val info = "protocol v1".encodeToByteArray()
        val aad = "header".encodeToByteArray()
        val plaintext = "Authenticated message".encodeToByteArray()
        val pskBox = suite.SealPSK(recipient.pk, info, aad, plaintext, psk, pskId)
        suite.OpenPSK(pskBox.encapsulatedSecret, recipient.sk, info, aad, pskBox.ciphertext, psk, pskId) shouldBe plaintext
        val authBox = suite.SealAuth(recipient.pk, info, aad, plaintext, sender.sk)
        suite.OpenAuth(authBox.encapsulatedSecret, recipient.sk, info, aad, authBox.ciphertext, sender.pk) shouldBe plaintext
        val combined = suite.SealAuthPSK(recipient.pk, info, aad, plaintext, psk, pskId, sender.sk)
        suite.OpenAuthPSK(combined.encapsulatedSecret, recipient.sk, info, aad, combined.ciphertext, psk, pskId, sender.pk) shouldBe plaintext
        // --8<-- [end:hpke-psk-auth]
    }
    "Export only" {
        // --8<-- [start:hpke-export]
        val kem = HPKE.KEM.DHKEM_P256_HKDF_SHA256
        val suite = HPKE(kem, HPKE.KDF.HKDF_SHA256, HPKE.AEAD.EXPORT_ONLY)
        val recipient = kem.GenerateKeyPair()
        val info = "protocol v1".encodeToByteArray()
        val context = "application key".encodeToByteArray()
        val sent = suite.SendExportBase(recipient.pk, info, context, 32.bytes)
        suite.ReceiveExportBase(sent.encapsulatedSecret, recipient.sk, info, context, 32.bytes) shouldBe sent.exported
        sent.exported.size shouldBe 32
        // --8<-- [end:hpke-export]
    }
}
