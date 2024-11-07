import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe

class EncodingTest: FreeSpec({
    "Correct serialName is determined by encoders" {
        ByteArrayBase64UrlSerializer.descriptor.serialName shouldBe "ByteArrayBase64UrlSerializer"
    }
})
