package at.asitplus.signum.indispensable.cosef

import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.cosef.io.Base16Strict
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper

import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlin.random.Random

class CoseSerializationTest : FreeSpec({


    "Serialization is correct" {
        val cose = CoseSigned<ByteArray>(
            protectedHeader = CoseHeader(algorithm = CoseAlgorithm.ES256),
            unprotectedHeader = CoseHeader(),
            payload = "This is the content.".encodeToByteArray(),
            signature = CryptoSignature.RSAorHMAC("bar".encodeToByteArray()) //RSAorHMAC because EC expects tuple
        )
        val serialized = cose.serialize().encodeToString(Base16Strict).uppercase()

        serialized shouldContain "546869732069732074686520636F6E74656E742E" // "This is the content."
        serialized shouldContain "43A10126"
    }

    "Serialize header" {
        val header = CoseHeader(algorithm = CoseAlgorithm.ES256, kid = "11".encodeToByteArray())

        header.serialize().encodeToString(Base16Strict).uppercase()
            .also { println(it) }

        val deserialized = CoseHeader.deserialize(header.serialize()).getOrThrow().shouldNotBeNull()

        deserialized.algorithm shouldBe header.algorithm
        deserialized.kid shouldBe header.kid
    }

    "Serialize header with COSE_Key" {
        val header = CoseHeader(
            algorithm = CoseAlgorithm.ES256,
            coseKey = "foo".encodeToByteArray(),
        )

        val serialized = header.serialize().encodeToString(Base16Strict).uppercase()
            .also { println(it) }
        serialized shouldContain "COSE_Key".encodeToByteArray().encodeToString(Base16Strict)

        val deserialized = CoseHeader.deserialize(header.serialize()).getOrThrow().shouldNotBeNull()

        deserialized.algorithm shouldBe header.algorithm
        deserialized.kid shouldBe header.kid
    }

    "Deserialization is correct" {
        val input = "d28443a10126a10442313154546869732069732074686520636f6e74656e" +
                "742e58408eb33e4ca31d1c465ab05aac34cc6b23d58fef5c083106c4d25a" +
                "91aef0b0117e2af9a291aa32e14ab834dc56ed2a223444547e01f11d3b09" +
                "16e5a4c345cacb36"
        val cose = CoseSigned.deserialize(input.uppercase().decodeToByteArray(Base16Strict))
            .also { println(it) }

        cose.shouldNotBeNull()
    }


    "CoseSignatureInput is correct" {
        val payload = Random.nextBytes(32)
        val inputObject = CoseSignatureInput(
            contextString = "Signature1",
            protectedHeader = ByteStringWrapper(CoseHeader(algorithm = CoseAlgorithm.ES256)),
            externalAad = byteArrayOf(),
            payload = payload
        ).serialize().encodeToString(Base16())
            .also { println(it) }

        val inputMethod = CoseSigned.prepareCoseSignatureInput(
            protectedHeader = CoseHeader(algorithm = CoseAlgorithm.ES256),
            payload = payload,
            externalAad = byteArrayOf(),
        ).encodeToString(Base16())

        inputObject.shouldContain("Signature1".encodeToByteArray().encodeToString(Base16()))
        inputMethod shouldBe inputObject
    }


})
