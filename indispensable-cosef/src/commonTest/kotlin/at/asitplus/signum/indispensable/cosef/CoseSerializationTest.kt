package at.asitplus.signum.indispensable.cosef

import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.asn1.Asn1Integer
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper

import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeTypeOf
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlin.random.Random

val Base16Strict = Base16(strict = true)

@OptIn(ExperimentalStdlibApi::class)
class CoseSerializationTest : FreeSpec({


    "Serialization is correct" {
        val cose = CoseSigned(
            protectedHeader = ByteStringWrapper(CoseHeader(algorithm = CoseAlgorithm.ES256)),
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
        val signatureInput = CoseSignatureInput(
            contextString = "Signature1",
            protectedHeader = ByteStringWrapper(CoseHeader(algorithm = CoseAlgorithm.ES256)),
            externalAad = byteArrayOf(),
            payload = Random.nextBytes(32)
        ).serialize().encodeToString(Base16())
            .also { println(it) }

        signatureInput.shouldContain("Signature1".encodeToByteArray().encodeToString(Base16()))
    }

    "RSA Key should properly encode n and e (RFC 8230 sample)" {
        val key = CryptoPublicKey.RSA(
            n = Asn1Integer.fromUnsignedByteArray(("80".repeat(256)).hexToByteArray()), // high bit is set
            e = Asn1Integer(32768u) // explicit example from RFC8230 sec 4.
        ).also { it.coseKid = "key".encodeToByteArray() }.toCoseKey().getOrThrow()
        key.keyId shouldBe "key".encodeToByteArray()
        key.keyParams.shouldBeTypeOf<CoseKeyParams.RsaParams>().let {
            it.n!!.size shouldBe 256
            it.e!! shouldBe ubyteArrayOf(0x80u, 0x00u).toByteArray()
        }
    }

})
