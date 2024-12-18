package at.asitplus.signum.indispensable.cosef

import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.cosef.io.Base16Strict
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlin.random.Random

@OptIn(ExperimentalSerializationApi::class)
class CoseSerializationTest : FreeSpec({

    "CoseSigned can not be constructed with ByteStringWrapper" {
        val payload = ByteStringWrapper("StringType")
        shouldThrow<IllegalArgumentException> {
            CoseSigned.create(
                protectedHeader = CoseHeader(algorithm = CoseAlgorithm.ES256),
                unprotectedHeader = null,
                payload = payload,
                signature = CryptoSignature.RSAorHMAC(byteArrayOf()),
                payloadSerializer = ByteStringWrapper.serializer(String.serializer())
            )
        }
    }

    "Serialization is correct with JSON" {
        val payload = "This is the content.".encodeToByteArray()
        val cose = CoseSigned.create(
            protectedHeader = CoseHeader(algorithm = CoseAlgorithm.RS256),
            unprotectedHeader = null,
            payload = payload,
            signature = CryptoSignature.RSAorHMAC("bar".encodeToByteArray()),
            payloadSerializer = ByteArraySerializer(),
        )

        Json.decodeFromString<CoseSigned<ByteArray>>(Json.encodeToString(cose)) shouldBe cose
    }

    "Serialization is correct with JSON for data class" {
        val payload = DataClass("This is the content.")
        val cose = CoseSigned.create(
            protectedHeader = CoseHeader(algorithm = CoseAlgorithm.RS256),
            unprotectedHeader = null,
            payload = payload,
            signature = CryptoSignature.RSAorHMAC("bar".encodeToByteArray()),
            payloadSerializer = DataClass.serializer(),
        )

        Json.decodeFromString<CoseSigned<DataClass>>(Json.encodeToString(cose)) shouldBe cose
    }

    "Serialization is correct for byte array" {
        val payload = "This is the content.".encodeToByteArray()
        val cose = CoseSigned.create(
            protectedHeader = CoseHeader(algorithm = CoseAlgorithm.RS256),
            unprotectedHeader = null,
            payload = payload,
            signature = CryptoSignature.RSAorHMAC("bar".encodeToByteArray()), //RSAorHMAC because EC expects tuple
            payloadSerializer = ByteArraySerializer(),
        )
        val serialized = cose.serialize(ByteArraySerializer())

        val serializedString = serialized.encodeToString(Base16Strict).uppercase()
        serializedString shouldContain "546869732069732074686520636F6E74656E742E" // "This is the content."
        serializedString shouldContain "8445A101390100" // array of 5 bytes that is a map with -257 (the header for RS256)
        cose.payload shouldBe payload

        CoseSigned.deserialize(ByteArraySerializer(), serialized).getOrThrow() shouldBe cose
    }

    "Deserialization is correct for byte array" {
        val input = "8445A101390100A054546869732069732074686520636F6E74656E742E43626172"

        val cose = CoseSigned.deserialize(ByteArraySerializer(), input.decodeToByteArray(Base16())).getOrThrow()
        cose.payload shouldBe "This is the content.".encodeToByteArray()
        cose.wireFormat.payload shouldBe "546869732069732074686520636F6E74656E742E".decodeToByteArray(Base16())
    }

    "Serialization is correct for data class" {
        val payload = DataClass("This is the content.")
        val cose = CoseSigned.create(
            protectedHeader = CoseHeader(algorithm = CoseAlgorithm.RS256),
            unprotectedHeader = null,
            payload = payload,
            signature = CryptoSignature.RSAorHMAC("bar".encodeToByteArray()), //RSAorHMAC because EC expects tuple
            payloadSerializer = DataClass.serializer(),
        )
        val serialized = cose.serialize(DataClass.serializer())
        val serializedString = serialized.encodeToString(Base16Strict).uppercase()

        serializedString shouldContain "546869732069732074686520636F6E74656E742E" // "This is the content."
        serializedString shouldContain "8445A101390100" // array of 5 bytes that is a map with -257 (the header for RS256)
        cose.payload shouldBe payload

        CoseSigned.deserialize(DataClass.serializer(), serialized).getOrThrow() shouldBe cose
    }

    "Deserialization is correct for data class" {
        val input = "8445A101390100A05822D818581EA167636F6E74656E7474546869732069732074686520636F6E74656E742E43626172"

        val cose = CoseSigned.deserialize(DataClass.serializer(), input.decodeToByteArray(Base16())).getOrThrow()
        cose.payload shouldBe DataClass("This is the content.")
        cose.wireFormat.payload shouldBe "D818581EA167636F6E74656E7474546869732069732074686520636F6E74656E742E"
            .decodeToByteArray(Base16())
        // important part is the D818 as tag(24)
    }

    "Serialize header" {
        val header = CoseHeader(algorithm = CoseAlgorithm.ES256, kid = "11".encodeToByteArray())

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
        serialized shouldContain "COSE_Key".encodeToByteArray().encodeToString(Base16Strict)

        val deserialized = CoseHeader.deserialize(header.serialize()).getOrThrow().shouldNotBeNull()
        deserialized.algorithm shouldBe header.algorithm
        deserialized.kid shouldBe header.kid
    }

    "Deserialization is correct for unprotected header too" {
        val input = "d28443a10126a10442313154546869732069732074686520636f6e74656e" +
                "742e58408eb33e4ca31d1c465ab05aac34cc6b23d58fef5c083106c4d25a" +
                "91aef0b0117e2af9a291aa32e14ab834dc56ed2a223444547e01f11d3b09" +
                "16e5a4c345cacb36"

        val cose = CoseSigned.deserialize(ByteArraySerializer(), input.uppercase().decodeToByteArray(Base16Strict))
            .getOrThrow()

        cose.payload shouldBe "This is the content.".encodeToByteArray()
    }

    "CoseSignatureInput is correct for ByteArray" {
        val payload = Random.nextBytes(32)
        val header = CoseHeader(algorithm = CoseAlgorithm.ES256)
        val inputManual = CoseSignatureInput(
            contextString = "Signature1",
            protectedHeader = coseCompliantSerializer.encodeToByteArray(header),
            externalAad = byteArrayOf(),
            payload = payload
        ).serialize().encodeToString(Base16())

        val inputObject = CoseSigned.create(
            protectedHeader = header,
            payload = payload,
            signature = CryptoSignature.RSAorHMAC("bar".encodeToByteArray()),
            payloadSerializer = ByteArraySerializer(),
        ).prepareCoseSignatureInput(byteArrayOf())
            .encodeToString(Base16())

        inputManual.shouldContain("Signature1".encodeToByteArray().encodeToString(Base16()))
        inputObject shouldBe inputManual
    }

    "CoseSignatureInput is correct for custom types" {
        val payload = DataClass(Random.nextBytes(32).encodeToString(Base16Strict))
        val header = CoseHeader(algorithm = CoseAlgorithm.ES256)
        val inputManual = CoseSignatureInput(
            contextString = "Signature1",
            protectedHeader = coseCompliantSerializer.encodeToByteArray(header),
            externalAad = byteArrayOf(),
            payload = coseCompliantSerializer.encodeToByteArray(ByteStringWrapper(payload)).wrapInCborTag(24),
        ).serialize().encodeToString(Base16())

        val inputObject = CoseSigned.create(
            protectedHeader = header,
            payload = payload,
            signature = CryptoSignature.RSAorHMAC("bar".encodeToByteArray()),
            payloadSerializer = DataClass.serializer(),
        ).prepareCoseSignatureInput(byteArrayOf())
            .encodeToString(Base16())

        inputManual.shouldContain("Signature1".encodeToByteArray().encodeToString(Base16()))
        inputObject shouldBe inputManual
    }


})

private fun ByteArray.wrapInCborTag(tag: Byte) = byteArrayOf(0xd8.toByte()) + byteArrayOf(tag) + this