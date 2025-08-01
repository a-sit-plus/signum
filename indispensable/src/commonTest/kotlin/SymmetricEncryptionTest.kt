package at.asitplus.signum

import at.asitplus.signum.indispensable.SecretExposure
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm
import at.asitplus.signum.indispensable.symmetric.SymmetricKey
import at.asitplus.signum.indispensable.symmetric.preferredMacKeyLength
import at.asitplus.signum.indispensable.symmetric.randomKey

import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe

class SymmetricEncryptionTest: FreeSpec({
   
    withData(nameFn={ "Key generation: $it" }, SymmetricEncryptionAlgorithm.entries) { alg ->
        val key = alg.randomKey()

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
})
