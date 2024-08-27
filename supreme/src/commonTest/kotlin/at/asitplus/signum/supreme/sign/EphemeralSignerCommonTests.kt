package at.asitplus.signum.supreme.sign

import at.asitplus.catching
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.RSAPadding
import at.asitplus.signum.supreme.succeed
import com.ionspin.kotlin.bignum.integer.Quadruple
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.should
import kotlinx.coroutines.cancel
import kotlin.random.Random

class EphemeralSignerCommonTests : FreeSpec({
    "RSA" - {
        withData(nameFn = { (pad,dig,bits,pre) -> "$dig/$pad/${bits}bit${if (pre) "/pre" else ""}" }, sequence {
            RSAPadding.entries.forEach { padding ->
                Digest.entries.forEach { digest ->
                    when {
                        digest == Digest.SHA512 && padding == RSAPadding.PSS -> listOf(2048, 3072, 4096)
                        digest == Digest.SHA384 || digest == Digest.SHA512 || padding == RSAPadding.PSS -> listOf(1024, 2048, 3072, 4096)
                        else -> listOf(512, 1024, 2048, 3072, 4096)
                    }.forEach { keySize ->
                        yield(Quadruple(padding, digest, keySize, false))
                        yield(Quadruple(padding, digest, keySize, true))
                    }
                }
            }
        }) { (padding, digest, keySize, preHashed) ->
            val data = Random.Default.nextBytes(64)
            val signer: Signer
            val signature = try {
                signer = Signer { rsa { digests = setOf(digest); paddings = setOf(padding); bits = keySize } }
                signer.sign(SignatureInput(data).let { if (preHashed) it.convertTo(digest).getOrThrow() else it }).getOrThrow()
            } catch (x: UnsupportedOperationException) {
                return@withData
            }

            val verifier = signer.makeVerifier().getOrThrow()
            verifier.verify(data, signature) should succeed
        }
    }
    "ECDSA" - {
         withData(nameFn = { (crv,dig,pre) -> "$crv/$dig${if (pre) "/pre" else ""}" }, sequence {
             ECCurve.entries.forEach { curve ->
                 Digest.entries.forEach { digest ->
                     yield(Triple(curve, digest, false))
                     yield(Triple(curve, digest, true))
                 }
             }
         }) { (crv, digest, preHashed) ->
            val signer = Signer { ec { curve = crv; digests = setOf(digest) } }
            val data = Random.Default.nextBytes(64)
            val signature = signer.sign(SignatureInput(data).let { if (preHashed) it.convertTo(digest).getOrThrow() else it }).getOrThrow()

            val verifier = signer.makeVerifier().getOrThrow()
            verifier.verify(data, signature) should succeed
        }
    }
})
