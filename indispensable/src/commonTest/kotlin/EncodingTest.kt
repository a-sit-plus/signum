package at.asitplus.signum
import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer

import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.testSuite
import io.kotest.matchers.shouldBe

val  EncodingTest by testSuite{
   
    "Correct serialName is determined by encoders" {
        ByteArrayBase64UrlSerializer.descriptor.serialName shouldBe "ByteArrayBase64UrlSerializer"
    }
}
