package at.asitplus.signum.supreme.sign

import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.Signum
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.dsl.VerifierConfiguration
import at.asitplus.signum.dsl.ec
import at.asitplus.signum.ecmath.double
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.ECCurveSerializer
import at.asitplus.signum.indispensable.PublicKey
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.iosEncodedPublicKeyLength
import at.asitplus.signum.indispensable.sign.*
import at.asitplus.signum.supreme.installSupreme
import at.asitplus.testballoon.matrix.matrixSuite
import com.ionspin.kotlin.bignum.integer.toBigInteger
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json

private val builtInCurve = ECCurve.SECP_256_R_1
private val externalCurve = object : ECCurve by builtInCurve {
    override val oid = ObjectIdentifier("1.3.6.1.4.1.55555.3")
}

private object ExternalCurveVerifierProvider : SignatureVerifierProvider {
    override fun verifierFor(
        algorithm: SignatureAlgorithm,
        key: PublicKey,
        config: VerifierConfiguration,
    ): SignatureVerifier? {
        if (algorithm !is EcdsaAlgorithm || algorithm.requiredCurve !== externalCurve ||
            key !is EcdsaPublicKey || key.curve !== externalCurve) return null
        val delegateKey = EcdsaPublicKey.fromUncompressed(builtInCurve, key.xBytes, key.yBytes)
        val delegate = EcdsaAlgorithm(algorithm.digest, builtInCurve).verifierFor(delegateKey)
        return object : SignatureVerifier by delegate {
            override val signatureAlgorithm = algorithm
            override val publicKey = key
        }
    }
}

val ExternalCurveSelectionTest by matrixSuite {
    Signum.installSupreme()
    ServiceLoader.register<SignatureVerifierProvider>(ExternalCurveVerifierProvider)
    val builtInPrivateKey = EcdsaPrivateKey.WithPublicKey(1.toBigInteger(), builtInCurve)

    "the direct curve serializer keeps the legacy names and descriptor" {
        ECCurveSerializer.descriptor.serialName shouldBe "EcCurveSerializer"
        for ((name, curve) in listOf(
            "P-256" to ECCurve.SECP_256_R_1,
            "P-384" to ECCurve.SECP_384_R_1,
            "P-521" to ECCurve.SECP_521_R_1,
        )) {
            val wire = "\"$name\""
            Json.encodeToString(ECCurveSerializer, curve) shouldBe wire
            (Json.decodeFromString(ECCurveSerializer, wire) === curve) shouldBe true
        }
        shouldThrow<SerializationException> { Json.encodeToString(ECCurveSerializer, externalCurve) }
    }

    "same-size custom EC keys can select an external verifier" {
        val publicKey = EcdsaPublicKey.fromUncompressed(
            externalCurve, builtInPrivateKey.publicKey.xBytes, builtInPrivateKey.publicKey.yBytes,
        )
        externalCurve.coordinateLength shouldBe builtInCurve.coordinateLength
        val algorithm = EcdsaAlgorithm(Digest.SHA256, externalCurve)
        val verifier = algorithm.verifierFor(publicKey) {
            SupremeKotlinVerifierProvider.verifierFor(algorithm, publicKey, this) shouldBe null
        }
        val message = byteArrayOf(1, 2, 3)
        val signature = EcdsaAlgorithm.withSHA256.signerFor(builtInPrivateKey).sign(message).signature
        verifier.publicKey shouldBe publicKey
        verifier.verify(message, signature) shouldBe SignatureVerifier.Success

        shouldThrow<UnsupportedCryptoException> { publicKey.publicPoint.double() }
        shouldThrow<UnsupportedCryptoException> { externalCurve.iosEncodedPublicKeyLength }
        shouldThrow<UnsupportedCryptoException> { Signer.Ephemeral { ec { curve = externalCurve } } }
    }

    "built-in ECDSA operations enforce the requested curve identity" {
        for (wrongCurve in listOf(externalCurve, ECCurve.SECP_384_R_1)) {
            val mismatched = EcdsaAlgorithm(Digest.SHA256, wrongCurve)
            shouldThrow<UnsupportedCryptoException> { mismatched.verifierFor(builtInPrivateKey.publicKey) }
            shouldThrow<UnsupportedCryptoException> { mismatched.signerFor(builtInPrivateKey) }
        }
    }
}
