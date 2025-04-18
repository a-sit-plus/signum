package at.asitplus.signum.supreme.sign

import at.asitplus.catching
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.supreme.succeed
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.should
import io.kotest.matchers.shouldNot
import io.kotest.matchers.types.shouldBeInstanceOf
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.KeyPairGenerator
import java.security.Security
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import kotlin.random.Random

class VerifierTests: FreeSpec({
    withData(mapOf<String, (SignatureAlgorithm.ECDSA, CryptoPublicKey.EC)-> Verifier.EC>(
        "BC -> PlatformVerifier" to { a,k ->
            a.verifierFor(k) { provider = "BC" }.getOrThrow().also { it.shouldBeInstanceOf<PlatformECDSAVerifier>() }
        },
        "BC -> KotlinVerifier" to ::KotlinECDSAVerifier)) { factory ->
        withData(ECCurve.entries) { curve ->
            withData(nameFn = SignatureInputFormat::jcaAlgorithmComponent, listOf<Digest?>(null) + Digest.entries) { digest ->
                withData(nameFn = { (key,_,_) -> key.publicPoint.toString() }, generateSequence {
                    val keypair = KeyPairGenerator.getInstance("EC", "BC").also {
                        it.initialize(ECGenParameterSpec(curve.jcaName))
                    }.genKeyPair()
                    val publicKey = keypair.public.toCryptoPublicKey().getOrThrow() as CryptoPublicKey.EC
                    val data = Random.nextBytes(256)
                    val sig = Signature.getInstance("${digest.jcaAlgorithmComponent}withECDSA", "BC").run {
                        initSign(keypair.private)
                        update(data)
                        sign()
                    }.let(CryptoSignature::decodeFromDer)
                    keypair.public.encoded
                    Triple(publicKey, data, sig)
                }.take(5)) { (key, data, sig) ->
                    val verifier = factory(SignatureAlgorithm.ECDSA(digest, null), key)
                    verifier.verify(byteArrayOf(), sig) shouldNot succeed
                    if (digest != null) {
                        verifier.verify(data.copyOfRange(0, 128), sig) shouldNot succeed
                        verifier.verify(data + Random.nextBytes(8), sig) shouldNot succeed
                    }
                    verifier.verify(data, sig) should succeed
                    Random.of(Digest.entries.filter { it != digest }).let { dig ->
                        catching { factory(SignatureAlgorithm.ECDSA(dig, null), key) }
                            .transform { it.verify(data, sig) } shouldNot succeed
                    }
                }
            }
        }
    }
}) { companion object { init { Security.addProvider(BouncyCastleProvider())}}}
