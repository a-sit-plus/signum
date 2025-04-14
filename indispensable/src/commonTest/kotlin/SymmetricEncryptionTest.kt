import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm
import at.asitplus.signum.indispensable.symmetric.randomKey
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe

class SymmetricEncryptionTest: FreeSpec({
    "Key generation" - {
        withData(SymmetricEncryptionAlgorithm.entries) { alg ->
            alg.randomKey().algorithm shouldBe alg
        }
    }
})
