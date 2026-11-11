package at.asitplus.signum.indispensable

import at.asitplus.signum.indispensable.sign.EcdsaPrivateKey
import at.asitplus.signum.indispensable.sign.RsaPrivateKey
import at.asitplus.signum.indispensable.sign.RsaPublicKey
import at.asitplus.signum.indispensable.sign.asn1
import at.asitplus.signum.indispensable.sign.fromAsn1
import at.asitplus.testballoon.matrix.matrixSuite
import com.ionspin.kotlin.bignum.integer.BigInteger
import io.kotest.matchers.shouldBe
import java.security.KeyPairGenerator

val PemKeyRegressionTest by matrixSuite {
    "CryptoPublicKey decodes RSA PUBLIC KEY PEM" {
        val native = KeyPairGenerator.getInstance("RSA").apply { initialize(512) }.generateKeyPair().public
        val key = RsaPublicKey.fromAsn1(native.encoded)

        CryptoPublicKey.fromAsn1(key.asn1.pkcs1.toPem()) shouldBe key
    }

    "CryptoPrivateKey decodes RSA PRIVATE KEY PEM" {
        val native = KeyPairGenerator.getInstance("RSA").apply { initialize(512) }.generateKeyPair().private
        val key = RsaPrivateKey.fromAsn1(native.encoded)

        CryptoPrivateKey.fromAsn1(key.asn1.pkcs1.toPem()) shouldBe key
    }

    "CryptoPrivateKey decodes EC PRIVATE KEY PEM" {
        val key = EcdsaPrivateKey.WithPublicKey(BigInteger.ONE, ECCurve.SECP_256_R_1)

        CryptoPrivateKey.fromAsn1(key.asn1.sec1.toPem()) shouldBe key
    }
}
