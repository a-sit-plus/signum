package at.asitplus.signum.indispensable.pki

import at.asitplus.KmmResult
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.signum.indispensable.toX509SignatureAlgorithm
import at.asitplus.testballoon.matrix.*
import io.kotest.matchers.shouldBe
import de.infix.testBalloon.framework.core.TestConfig
import kotlin.time.Duration.Companion.minutes
import de.infix.testBalloon.framework.core.testScope

infix fun <T> KmmResult<T>.shouldSucceedWith(b: T): T =
    (this.getOrThrow() shouldBe b)

val X509ConversionTests by matrixSuite {
    compact("X509 -> Alg -> X509 is stable") - {
        data(X509SignatureAlgorithm.entries) test {
            it.toX509SignatureAlgorithm() shouldSucceedWith it
            it.algorithm.toX509SignatureAlgorithm() shouldSucceedWith it
        }
    }
}
