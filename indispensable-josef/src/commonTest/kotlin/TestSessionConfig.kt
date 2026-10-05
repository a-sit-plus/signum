import at.asitplus.awesn1.serialization.DefaultDer
import at.asitplus.signum.indispensable.signumX509Serializers
import at.asitplus.testballoon.matrix.ExecutionMode
import at.asitplus.testballoon.matrix.MatrixTestDefaults
import de.infix.testBalloon.framework.core.TestSession
import org.kotlincrypto.random.CryptoRand
import org.kotlincrypto.random.DelicateCryptoRandApi
import kotlin.random.Random

//Supercharge tests with concurrency!
class ModuleTestSession : TestSession(
    testConfig = DefaultConfiguration.apply { MatrixTestDefaults { execution = ExecutionMode.Concurrent(64) } }
){
    init {
        DefaultDer.register(signumX509Serializers)
    }
}

// CryptRand != Random, see https://github.com/KotlinCrypto/random/issues/50
@OptIn(DelicateCryptoRandApi::class)
object InsecureRandom : CryptoRand() {
    override fun nextBytes(buf: ByteArray) = Random.nextBytes(buf)
    fun nextBytes(n: Int) = ByteArray(n).also { nextBytes(it) }
}
