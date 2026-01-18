package at.asitplus.signum

import at.asitplus.signum.indispensable.SecretExposure
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm
import at.asitplus.signum.indispensable.symmetric.encryptionKey
import at.asitplus.signum.indispensable.symmetric.hasDedicatedMacKey
import at.asitplus.signum.indispensable.symmetric.macKey
import at.asitplus.signum.indispensable.symmetric.preferredMacKeyLength
import at.asitplus.signum.indispensable.symmetric.randomKey
import at.asitplus.signum.indispensable.symmetric.secretKey
import at.asitplus.testballoon.matrix.*
import io.kotest.matchers.shouldBe
import org.kotlincrypto.random.CryptoRand
import kotlin.random.Random

@OptIn(HazardousMaterials::class)
val SymmetricEncryptionTest by matrixSuite {

    data(SymmetricEncryptionAlgorithm.entries, nameFn = { "Key generation: $it" }) test { alg ->
        val key = alg.randomKey(random = object : CryptoRand() {
            override fun nextBytes(buf: ByteArray) = Random.nextBytes(buf)
        })

        key.algorithm shouldBe alg

        if (!key.hasDedicatedMacKey()) {
            @OptIn(SecretExposure::class)
            key.secretKey.getOrThrow().size shouldBe key.algorithm.keySize.bytes.toInt()
        }
        else {
            @OptIn(SecretExposure::class)
            key.encryptionKey.getOrThrow().size shouldBe key.algorithm.keySize.bytes.toInt()
            @OptIn(SecretExposure::class)
            key.macKey.getOrThrow().size shouldBe key.algorithm.preferredMacKeyLength.bytes.toInt()
        }
    }
}
