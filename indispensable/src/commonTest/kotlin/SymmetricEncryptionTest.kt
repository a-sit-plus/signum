package at.asitplus.signum

import at.asitplus.signum.indispensable.SecretExposure
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm
import at.asitplus.signum.indispensable.symmetric.SymmetricKey
import at.asitplus.signum.indispensable.symmetric.preferredMacKeyLength
import at.asitplus.signum.indispensable.symmetric.randomKey
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.testSuite
import io.kotest.matchers.shouldBe
import org.kotlincrypto.random.CryptoRand
import kotlin.random.Random

@OptIn(HazardousMaterials::class)
val SymmetricEncryptionTest by testSuite {

    withData(nameFn = { "Key generation: $it" }, SymmetricEncryptionAlgorithm.entries) { alg ->
        val key = alg.randomKey(random = object : CryptoRand() {
            override fun nextBytes(buf: ByteArray) = Random.nextBytes(buf)
        })

        key.algorithm shouldBe alg

        when (key) {
            is SymmetricKey.Integrated -> {
                @OptIn(SecretExposure::class)
                key.secretKey.getOrThrow().size shouldBe key.algorithm.keySize.bytes.toInt()
            }

            is SymmetricKey.WithDedicatedMac -> {
                @OptIn(SecretExposure::class)
                key.encryptionKey.getOrThrow().size shouldBe key.algorithm.keySize.bytes.toInt()
                @OptIn(SecretExposure::class)
                key.macKey.getOrThrow().size shouldBe key.algorithm.preferredMacKeyLength.bytes.toInt()
            }

            else -> error("unreachable")
        }
    }
}
