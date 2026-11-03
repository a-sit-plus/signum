@file:Suppress("DEPRECATION")

package at.asitplus.signum.migration

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoPrivateKey
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.SpecializedCryptoPublicKey
import at.asitplus.signum.indispensable.PrivateKey
import at.asitplus.signum.indispensable.agree.KeyAgreementPublicValue
import at.asitplus.signum.indispensable.sign.EcdsaPublicKey.Companion.asPublicKey
import at.asitplus.signum.indispensable.sign.RsaSignature
import at.asitplus.signum.indispensable.toCryptoPrivateKey
import at.asitplus.signum.indispensable.toCryptoPublicKey
import at.asitplus.signum.indispensable.toPrivateKey
import at.asitplus.signum.indispensable.toPublicKey
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeSameInstanceAs
import java.security.KeyPairGenerator
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

val CryptoNamesMigrationTest by matrixSuite {
    "Old type names and member conversions forward to the new APIs" {
        val key = ECCurve.SECP_256_R_1.generator.asPublicKey()
        val generic: CryptoPublicKey = CryptoPublicKey.fromDid(key.didEncoded)
        generic shouldBe key
        val agreement: KeyAgreementPublicValue.ECDH = key
        agreement.asCryptoPublicKey() shouldBeSameInstanceAs key
        key.asCryptoPublicKey() shouldBeSameInstanceAs key
        val specialized: SpecializedCryptoPublicKey = object : SpecializedCryptoPublicKey {
            override fun toPublicKey(): KmmResult<CryptoPublicKey> = KmmResult.success(key)
        }
        specialized.toCryptoPublicKey().getOrThrow() shouldBeSameInstanceAs key
        val signature = RsaSignature(byteArrayOf(1))
        val genericSignature: CryptoSignature = signature
        genericSignature shouldBeSameInstanceAs signature
    }

    "All six JCA bridges and their replacements preserve main's KmmResult contract" {
        for (algorithm in listOf("EC", "RSA")) {
            val pair = KeyPairGenerator.getInstance(algorithm).apply {
                initialize(if (algorithm == "EC") 256 else 2048)
            }.generateKeyPair()
            val publicKey: KmmResult<CryptoPublicKey> = pair.public.toCryptoPublicKey()
            val privateKey: KmmResult<PrivateKey.WithPublicKey> = pair.private.toCryptoPrivateKey()
            publicKey.getOrThrow() shouldBe catching { pair.public.toPublicKey() }.getOrThrow()
            privateKey.getOrThrow() shouldBe catching { pair.private.toPrivateKey() }.getOrThrow()
            val genericPrivateKey: CryptoPrivateKey = privateKey.getOrThrow()
            genericPrivateKey shouldBe privateKey.getOrThrow()
            privateKey.getOrThrow().publicKey shouldBe publicKey.getOrThrow()
            if (algorithm == "EC") {
                (pair.public as ECPublicKey).toCryptoPublicKey().getOrThrow() shouldBe pair.public.toPublicKey()
                (pair.private as ECPrivateKey).toCryptoPrivateKey().getOrThrow() shouldBe pair.private.toPrivateKey()
            } else {
                (pair.public as RSAPublicKey).toCryptoPublicKey().getOrThrow() shouldBe pair.public.toPublicKey()
                (pair.private as RSAPrivateKey).toCryptoPrivateKey().getOrThrow() shouldBe pair.private.toPrivateKey()
            }
        }
        val unsupported = object : java.security.PublicKey {
            override fun getAlgorithm() = "unsupported"
            override fun getFormat() = "X.509"
            override fun getEncoded() = byteArrayOf()
        }
        unsupported.toCryptoPublicKey().isFailure shouldBe true
        catching { unsupported.toPublicKey() }.isFailure shouldBe true
        val malformed = object : java.security.PrivateKey {
            override fun getAlgorithm() = "EC"
            override fun getFormat() = "PKCS#8"
            override fun getEncoded() = byteArrayOf()
        }
        malformed.toCryptoPrivateKey().isFailure shouldBe true
        catching { malformed.toPrivateKey() }.isFailure shouldBe true
    }
}
