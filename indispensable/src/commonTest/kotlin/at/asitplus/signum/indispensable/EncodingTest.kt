package at.asitplus.signum.indispensable
import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer

import at.asitplus.testballoon.matrix.*
import io.kotest.matchers.shouldBe

val  EncodingTest by matrixSuite {
   
    "Correct serialName is determined by encoders" {
        ByteArrayBase64UrlSerializer.descriptor.serialName shouldBe "ByteArrayBase64UrlSerializer"
    }
}
