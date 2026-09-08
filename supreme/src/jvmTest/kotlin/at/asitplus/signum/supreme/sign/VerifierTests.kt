package at.asitplus.signum.supreme.sign

import at.asitplus.signum.dsl.JCAProviderRef
import at.asitplus.signum.dsl.VerifierConfiguration
import at.asitplus.signum.dsl.jvm
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.digest.WellKnownDigest
import at.asitplus.signum.indispensable.sign.SignatureVerifier
import at.asitplus.signum.indispensable.sign.verify
import at.asitplus.signum.indispensable.sign.EcdsaVerifier
import at.asitplus.signum.indispensable.sign.EcdsaAlgorithm
import at.asitplus.signum.indispensable.sign.EcdsaPublicKey
import at.asitplus.signum.indispensable.sign.EcdsaSignature
import at.asitplus.testballoon.matrix.*
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.KeyPairGenerator
import java.security.Security
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import kotlin.random.Random

private fun component(digest: WellKnownDigest?) = when(digest) {
    WellKnownDigest.SHA1 -> "SHA1"
    WellKnownDigest.SHA256 -> "SHA256"
    WellKnownDigest.SHA384 -> "SHA384"
    WellKnownDigest.SHA512 -> "SHA512"
    null -> "NONE"
}
val VerifierTests by matrixSuite {
    Security.addProvider(BouncyCastleProvider())

    mapOf<String, (EcdsaAlgorithm, EcdsaPublicKey) -> EcdsaVerifier>(
        "BC -> PlatformVerifier" to { a, k ->
            val config = VerifierConfiguration::class.java.getDeclaredConstructor().newInstance()
            config.jvm { provider = JCAProviderRef.Of("BC") }
            SupremeJVMVerifierProvider.verifierFor(a, k, config)
                .shouldBeInstanceOf<SupremeJVMVerifier.Ecdsa>()
        },
        "BC -> KotlinVerifier" to { a, k ->
            // hack past the internal
            val emptyConfig = VerifierConfiguration::class.java.getDeclaredConstructor().newInstance()
            SupremeKotlinVerifierProvider.verifierFor(a, k, emptyConfig)
                .shouldBeInstanceOf<KotlinEcdsaVerifier>()
        }
    ).asData(nameFn = { it.first }) - { (_, factory) ->
        data(ECCurve.entries) - { curve ->
            data(listOf<WellKnownDigest?>(null) + WellKnownDigest.entries, nameFn = { it.toString() }) - { digest ->
                data(generateSequence {
                    val keypair = KeyPairGenerator.getInstance("EC", "BC").also {
                        it.initialize(ECGenParameterSpec(curve.jcaName))
                    }.genKeyPair()
                    val publicKey = keypair.public.toCryptoPublicKey() as EcdsaPublicKey
                    val data = Random.nextBytes(256)
                    val sig = Signature.getInstance("${component(digest)}withECDSA", "BC").run {
                        initSign(keypair.private)
                        update(data)
                        sign()
                    }.let(EcdsaSignature.Companion::fromRawSignatureValue)
                    Triple(publicKey, data, sig)
                }.take(5), nameFn = { (key, _, _) -> key.publicPoint.toString() }) test { (key, data, sig) ->
                    val verifier = factory(EcdsaAlgorithm(digest, null), key)
                    shouldThrowAny { verifier.verify(byteArrayOf(), sig) }
                    if (digest != null) {
                        shouldThrowAny { verifier.verify(data.copyOfRange(0, 128), sig) }
                        shouldThrowAny { verifier.verify(data + Random.nextBytes(8), sig) }
                    }
                    verifier.verify(data, sig) shouldBe SignatureVerifier.Success
                    Random.of(WellKnownDigest.entries.filter { it != digest }).let { dig ->
                        shouldThrowAny {
                            factory(EcdsaAlgorithm(dig, null), key)
                                .verify(data, sig)
                        }
                    }
                }
            }
        }
    }
}