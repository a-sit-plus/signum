import at.asitplus.signum.indispensable.Ciphertext
import at.asitplus.signum.indispensable.EncryptionAlgorithm
import at.asitplus.signum.supreme.crypt.decrypt
import at.asitplus.signum.supreme.crypt.encryptorFor
import at.asitplus.signum.supreme.crypt.randomKey
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlin.random.Random

@ExperimentalStdlibApi
class JvmAESTest : FreeSpec({

    "Against JCA" - {
        //TODO
    }
})