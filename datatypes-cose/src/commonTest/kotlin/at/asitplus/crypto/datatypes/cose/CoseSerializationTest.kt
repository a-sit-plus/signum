package at.asitplus.crypto.datatypes.cose

import at.asitplus.crypto.datatypes.CryptoSignature
import at.asitplus.crypto.datatypes.JwsAlgorithm
import io.github.aakira.napier.DebugAntilog
import io.github.aakira.napier.Napier
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.cbor.ByteStringWrapper

class CoseSerializationTest : FreeSpec({

    Napier.base(DebugAntilog())

    "Serialization is correct" {
        val cose = CoseSigned(
            protectedHeader = ByteStringWrapper(CoseHeader(algorithm = CoseAlgorithm.ES256)),
            unprotectedHeader = CoseHeader(),
            payload = "This is the content.".encodeToByteArray(),
            signature = CryptoSignature.fromRawByteArray("bar".encodeToByteArray(), JwsAlgorithm.ES256)
        )
        val serialized = cose.serialize().encodeToString(Base16(strict = true)).uppercase()

        serialized shouldContain "546869732069732074686520636F6E74656E742E" // "This is the content."
        serialized shouldContain "43A10126"
    }

    "Serialize header" {
        val header = CoseHeader(algorithm = CoseAlgorithm.ES256, kid = "11".encodeToByteArray())
        val serialized = header.serialize().encodeToString(Base16(strict = true)).uppercase()
        println(serialized)

        val deserialized = CoseHeader.deserialize(header.serialize())
        deserialized.shouldNotBeNull()
        deserialized.algorithm shouldBe header.algorithm
        deserialized.kid shouldBe header.kid
    }

    "Deserialization is correct" {
        val input = "d28443a10126a10442313154546869732069732074686520636f6e74656e" +
                "742e58408eb33e4ca31d1c465ab05aac34cc6b23d58fef5c083106c4d25a" +
                "91aef0b0117e2af9a291aa32e14ab834dc56ed2a223444547e01f11d3b09" +
                "16e5a4c345cacb36"
        val cose = CoseSigned.deserialize(input.uppercase().decodeToByteArray(Base16(strict = true)))

        println(cose)
        cose.shouldNotBeNull()
    }

})
