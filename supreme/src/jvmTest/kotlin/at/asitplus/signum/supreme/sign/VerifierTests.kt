package at.asitplus.signum.supreme.sign

import at.asitplus.catching
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.digest.WellKnownDigest
import at.asitplus.signum.indispensable.integrity.verify
import at.asitplus.signum.indispensable.sign.ECDSAAlgorithm
import at.asitplus.signum.indispensable.sign.ECDSAPublicKey
import at.asitplus.signum.supreme.succeed
import at.asitplus.testballoon.matrix.*
import io.kotest.matchers.should
import io.kotest.matchers.shouldNot
import io.kotest.matchers.types.shouldBeInstanceOf
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.KeyPairGenerator
import java.security.Security
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import kotlin.random.Random

val VerifierTests by matrixSuite {
    Security.addProvider(BouncyCastleProvider())

    mapOf<String, (ECDSAAlgorithm, ECDSAPublicKey) -> SupremeVerifier.EC>(
        "BC -> PlatformVerifier" to { a, k ->
            SupremePlatformVerifierProvider.verifierFor(a, k) { provider = "BC" }
                .shouldBeInstanceOf<PlatformECDSAVerifier>()
        },
        "BC -> KotlinVerifier" to { a, k ->
            SupremeKotlinVerifierProvider.verifierFor(a, k)
                .shouldBeInstanceOf<KotlinECDSAVerifier>()
        }
    ).asData(nameFn = { it.first }) - { (_, factory) ->
        data(ECCurve.entries) - { curve ->
            data(listOf<WellKnownDigest?>(null) + WellKnownDigest.entries, nameFn = { it.jcaAlgorithmComponent }) - { digest ->
                data(generateSequence {
                    val keypair = KeyPairGenerator.getInstance("EC", "BC").also {
                        it.initialize(ECGenParameterSpec(curve.jcaName))
                    }.genKeyPair()
                    val publicKey = keypair.public.toCryptoPublicKey() as ECDSAPublicKey
                    val data = Random.nextBytes(256)
                    val sig = Signature.getInstance("${digest.jcaAlgorithmComponent}withECDSA", "BC").run {
                        initSign(keypair.private)
                        update(data)
                        sign()
                    }.let(CryptoSignature::parseFromJca)
                    Triple(publicKey, data, sig)
                }.take(5), nameFn = { (key, _, _) -> key.publicPoint.toString() }) test { (key, data, sig) ->
                    val verifier = factory(ECDSAAlgorithm(digest, null), key)
                    verifier.verify(byteArrayOf(), sig) shouldNot succeed
                    if (digest != null) {
                        verifier.verify(data.copyOfRange(0, 128), sig) shouldNot succeed
                        verifier.verify(data + Random.nextBytes(8), sig) shouldNot succeed
                    }
                    verifier.verify(data, sig) should succeed
                    Random.of(Digest.entries.filter { it != digest }).let { dig ->
                        catching { factory(ECDSAAlgorithm(dig, null), key) }
                            .transform { it.verify(data, sig) } shouldNot succeed
                    }
                }
            }
        }
    }
}