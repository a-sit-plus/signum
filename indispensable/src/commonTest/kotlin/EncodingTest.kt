package at.asitplus.signum
import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer

import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import de.infix.testBalloon.framework.core.TestConfig
import kotlin.time.Duration.Companion.minutes
import de.infix.testBalloon.framework.core.testScope

val  EncodingTest by testSuite {
   
    "Correct serialName is determined by encoders" {
        ByteArrayBase64UrlSerializer.descriptor.serialName shouldBe "ByteArrayBase64UrlSerializer"
    }
}
