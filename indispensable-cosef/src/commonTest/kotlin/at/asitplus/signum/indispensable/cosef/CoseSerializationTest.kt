package at.asitplus.signum.indispensable.cosef

import at.asitplus.signum.indispensable.cosef.io.Base16Strict
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.sign.RsaSignature
import io.kotest.assertions.throwables.shouldThrow
import at.asitplus.testballoon.matrix.*
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerializationException
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.json.Json
import kotlin.random.Random

@OptIn(ExperimentalSerializationApi::class)
val CoseSerializationTest by matrixSuite {

    "CoseSigned can not be constructed with ByteStringWrapper" {
        val payload = ByteStringWrapper("StringType")
        shouldThrow<IllegalArgumentException> {
            CoseSigned.create(
                protectedHeader = CoseHeader(algorithm = CoseAlgorithm.Signature.ES256),
                unprotectedHeader = null,
                payload = payload,
                signature = RsaSignature(byteArrayOf()),
                payloadSerializer = ByteStringWrapper.serializer(String.serializer())
            )
        }
    }

    "CoseMac can not be constructed with ByteStringWrapper" {
        val payload = ByteStringWrapper("StringType")
        shouldThrow<IllegalArgumentException> {
            CoseMac.create(
                protectedHeader = CoseHeader(algorithm = CoseAlgorithm.MAC.HS256),
                unprotectedHeader = null,
                payload = payload,
                tag = byteArrayOf(),
                payloadSerializer = ByteStringWrapper.serializer(String.serializer())
            )
        }
    }

    "Serialization is correct with JSON CoseSigned" {
        val payload = "This is the content.".encodeToByteArray()
        val cose = CoseSigned.create(
            protectedHeader = CoseHeader(algorithm = CoseAlgorithm.Signature.RS256),
            unprotectedHeader = null,
            payload = payload,
            signature = RsaSignature("bar".encodeToByteArray()),
            payloadSerializer = ByteArraySerializer(),
        )

        Json.decodeFromString<CoseSigned<ByteArray>>(Json.encodeToString(cose)) shouldBe cose
    }

    "Serialization is correct with JSON CoseMac" {
        val payload = "This is the content.".encodeToByteArray()
        val cose = CoseMac.create(
            protectedHeader = CoseHeader(algorithm = CoseAlgorithm.MAC.HS256),
            unprotectedHeader = null,
            payload = payload,
            tag = byteArrayOf(),
            payloadSerializer = ByteArraySerializer(),
        )

        Json.decodeFromString<CoseMac<ByteArray>>(Json.encodeToString(cose)) shouldBe cose
    }

    "Serialization is correct with JSON for data class CoseSigned" {
        val payload = DataClass("This is the content.")
        val cose = CoseSigned.create(
            protectedHeader = CoseHeader(algorithm = CoseAlgorithm.Signature.RS256),
            unprotectedHeader = null,
            payload = payload,
            signature = RsaSignature("bar".encodeToByteArray()),
            payloadSerializer = DataClass.serializer(),
        )

        Json.decodeFromString<CoseSigned<DataClass>>(Json.encodeToString(cose)) shouldBe cose
    }

    "Serialization is correct with JSON for data class CoseMac" {
        val payload = DataClass("This is the content.")
        val cose = CoseMac.create(
            protectedHeader = CoseHeader(algorithm = CoseAlgorithm.MAC.HS256),
            unprotectedHeader = null,
            payload = payload,
            tag = byteArrayOf(),
            payloadSerializer = DataClass.serializer(),
        )

        Json.decodeFromString<CoseMac<DataClass>>(Json.encodeToString(cose)) shouldBe cose
    }

    "Serialization is correct for byte array CoseSigned" {
        val payload = "This is the content.".encodeToByteArray()
        val cose = CoseSigned.create(
            protectedHeader = CoseHeader(algorithm = CoseAlgorithm.Signature.RS256),
            unprotectedHeader = null,
            payload = payload,
            signature = RsaSignature("bar".encodeToByteArray()), //RSAorHMAC because EC expects tuple
            payloadSerializer = ByteArraySerializer(),
        )
        val serialized = cose.serialize(ByteArraySerializer())

        val serializedString = serialized.encodeToString(Base16Strict).uppercase()
        serializedString shouldContain "546869732069732074686520636F6E74656E742E" // "This is the content."
        serializedString shouldContain "8445A101390100" // array of 5 bytes that is a map with -257 (the header for RS256)
        cose.payload shouldBe payload

        CoseSigned.deserialize(ByteArraySerializer(), serialized).getOrThrow() shouldBe cose
    }

    "Serialization is correct for byte array with CoseMac" {
        val payload = "This is the content.".encodeToByteArray()
        val cose = CoseMac.create(
            protectedHeader = CoseHeader(algorithm = CoseAlgorithm.MAC.HS256),
            unprotectedHeader = null,
            payload = payload,
            tag = byteArrayOf(),
            payloadSerializer = ByteArraySerializer(),
        )
        val serialized = cose.serialize(ByteArraySerializer())

        val serializedString = serialized.encodeToString(Base16Strict).uppercase()
        serializedString shouldContain "546869732069732074686520636F6E74656E742E" // "This is the content."
        serializedString shouldContain "8443A10105" // array of 3 bytes that is a map with 4 (the header for HMAC256)

        cose.payload.contentEquals(payload) shouldBe true

        CoseMac.deserialize(ByteArraySerializer(), serialized).getOrThrow() shouldBe cose
    }

    "Serialization is correct for null CoseSigned" {
        val cose = CoseSigned.create(
            protectedHeader = CoseHeader(algorithm = CoseAlgorithm.Signature.RS256),
            unprotectedHeader = null,
            payload = null,
            signature = RsaSignature("bar".encodeToByteArray()), //RSAorHMAC because EC expects tuple
            payloadSerializer = ByteArraySerializer(),
        )
        val serialized = cose.serialize(ByteArraySerializer())

        val serializedString = serialized.encodeToString(Base16Strict).uppercase()
        serializedString shouldContain "A0F643" // Empty unprotected header; null; begin of signature
        serializedString shouldContain "8445A101390100" // array of 5 bytes that is a map with -257 (the header for RS256)
        cose.payload shouldBe null

        CoseSigned.deserialize(ByteArraySerializer(), serialized).getOrThrow() shouldBe cose
    }

    "Serialization is correct for null CoseMac" {
        val cose = CoseMac.create(
            protectedHeader = CoseHeader(algorithm = CoseAlgorithm.MAC.HS256),
            unprotectedHeader = null,
            payload = null,
            tag = byteArrayOf(),
            payloadSerializer = ByteArraySerializer(),
        )
        val serialized = cose.serialize(ByteArraySerializer())

        val serializedString = serialized.encodeToString(Base16Strict).uppercase()
        serializedString shouldContain "A0F640" // Empty unprotected header; null; begin of tag
        serializedString shouldContain "8443A10105" // array of 3 bytes that is a map with 4 (the header for HMAC256)
        cose.payload shouldBe null

        CoseMac.deserialize(ByteArraySerializer(), serialized).getOrThrow() shouldBe cose
    }

    "Deserialization is correct for byte array CoseSigned" {
        val input = "8445A101390100A054546869732069732074686520636F6E74656E742E43626172"

        val cose = CoseSigned.deserialize(ByteArraySerializer(), input.decodeToByteArray(Base16())).getOrThrow()
        cose.payload shouldBe "This is the content.".encodeToByteArray()
        cose.wireFormat.payload shouldBe "546869732069732074686520636F6E74656E742E".decodeToByteArray(Base16())
    }

    "Deserialization is correct for byte array CoseMac" {
        val input = "8443A10105A054546869732069732074686520636F6E74656E742E40"

        val cose = CoseMac.deserialize(ByteArraySerializer(), input.decodeToByteArray(Base16())).getOrThrow()
        cose.payload shouldBe "This is the content.".encodeToByteArray()
        cose.wireFormat.payload shouldBe "546869732069732074686520636F6E74656E742E".decodeToByteArray(Base16())
    }

    "Deserialization is correct for null payload CoseSigned" {
        val input = "8445A101390100A0F643626172"

        val cose = CoseSigned.deserialize(ByteArraySerializer(), input.decodeToByteArray(Base16())).getOrThrow()
        cose.payload shouldBe null
        cose.wireFormat.payload shouldBe null
    }

    "Deserialization is correct for null payload CoseMac" {
        val input = "8443A10105A0F640"

        val cose = CoseMac.deserialize(ByteArraySerializer(), input.decodeToByteArray(Base16())).getOrThrow()
        cose.payload shouldBe null
        cose.wireFormat.payload shouldBe null
    }

    "Deserialization fails when trying to parse byte array as data class CoseSigned" {
        val input = "8445A101390100A054546869732069732074686520636F6E74656E742E43626172"

        shouldThrow<SerializationException> {
            CoseSigned.deserialize(DataClass.serializer(), input.decodeToByteArray(Base16())).getOrThrow()
        }
    }

    "Deserialization fails when trying to parse byte array as data class CoseMac" {
        val input = "8443A10105A054546869732069732074686520636F6E74656E742E40"

        shouldThrow<SerializationException> {
            CoseMac.deserialize(DataClass.serializer(), input.decodeToByteArray(Base16())).getOrThrow()
        }
    }

    "Serialization is correct for data class CoseSigned" {
        val payload = DataClass("This is the content.")
        val cose = CoseSigned.create(
            protectedHeader = CoseHeader(algorithm = CoseAlgorithm.Signature.RS256),
            unprotectedHeader = null,
            payload = payload,
            signature = RsaSignature("bar".encodeToByteArray()), //RSAorHMAC because EC expects tuple
            payloadSerializer = DataClass.serializer(),
        )
        val serialized = cose.serialize(DataClass.serializer())
        val serializedString = serialized.encodeToString(Base16Strict).uppercase()

        serializedString shouldContain "546869732069732074686520636F6E74656E742E" // "This is the content."
        serializedString shouldContain "8445A101390100" // array of 5 bytes that is a map with -257 (the header for RS256)
        cose.payload shouldBe payload

        CoseSigned.deserialize(DataClass.serializer(), serialized).getOrThrow() shouldBe cose
    }

    "Serialization is correct for data class CoseMac" {
        val payload = DataClass("This is the content.")
        val cose = CoseMac.create(
            protectedHeader = CoseHeader(algorithm = CoseAlgorithm.MAC.HS256),
            unprotectedHeader = null,
            payload = payload,
            tag = byteArrayOf(),
            payloadSerializer = DataClass.serializer(),
        )
        val serialized = cose.serialize(DataClass.serializer())
        val serializedString = serialized.encodeToString(Base16Strict).uppercase()

        serializedString shouldContain "546869732069732074686520636F6E74656E742E" // "This is the content."
        serializedString shouldContain "8443A10105" // array of 3 bytes that is a map with 4 (the header for HMAC256)
        cose.payload shouldBe payload

        CoseMac.deserialize(DataClass.serializer(), serialized).getOrThrow() shouldBe cose
    }

    "Deserialization is correct for data class CoseSigned" {
        val input = "8445A101390100A05822D818581EA167636F6E74656E7474546869732069732074686520636F6E74656E742E43626172"

        val cose = CoseSigned.deserialize(DataClass.serializer(), input.decodeToByteArray(Base16())).getOrThrow()
        cose.payload shouldBe DataClass("This is the content.")
        cose.wireFormat.payload shouldBe "D818581EA167636F6E74656E7474546869732069732074686520636F6E74656E742E"
            .decodeToByteArray(Base16())
        // important part is the D818 as tag(24)
    }

    "Deserialization is correct for data class CoseMac" {
        val input = "8443A10105A05822D818581EA167636F6E74656E7474546869732069732074686520636F6E74656E742E43626172"

        val cose = CoseMac.deserialize(DataClass.serializer(), input.decodeToByteArray(Base16())).getOrThrow()
        cose.payload shouldBe DataClass("This is the content.")
        cose.wireFormat.payload shouldBe "D818581EA167636F6E74656E7474546869732069732074686520636F6E74656E742E"
            .decodeToByteArray(Base16())
        // important part is the D818 as tag(24)
    }

    "Deserialization is correct for data class read as byte array CoseSigned" {
        val input = "8445A101390100A05822D818581EA167636F6E74656E7474546869732069732074686520636F6E74656E742E43626172"

        val cose = CoseSigned.deserialize(ByteArraySerializer(), input.decodeToByteArray(Base16())).getOrThrow()
        cose.wireFormat.payload shouldBe "D818581EA167636F6E74656E7474546869732069732074686520636F6E74656E742E"
            .decodeToByteArray(Base16())
        // important part is the D818 as tag(24)
    }

    "Deserialization is correct for data class read as byte array CoseMac" {
        val input = "8443A10105A05822D818581EA167636F6E74656E7474546869732069732074686520636F6E74656E742E43626172"

        val cose = CoseMac.deserialize(ByteArraySerializer(), input.decodeToByteArray(Base16())).getOrThrow()
        cose.wireFormat.payload shouldBe "D818581EA167636F6E74656E7474546869732069732074686520636F6E74656E742E"
            .decodeToByteArray(Base16())
        // important part is the D818 as tag(24)
    }

    "Serialize header" {
        val header = CoseHeader(algorithm = CoseAlgorithm.Signature.ES256, kid = "11".encodeToByteArray())

        val deserialized = coseCompliantSerializer.decodeFromByteArray<CoseHeader>(
            coseCompliantSerializer.encodeToByteArray(header)
        )

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

    "CoseInput is correct for ByteArray" {
        val payload = Random.nextBytes(32)
        var header = CoseHeader(algorithm = CoseAlgorithm.Signature.ES256)
        val inputManualSignature = coseCompliantSerializer.encodeToByteArray(
            CoseInput(
                contextString = "Signature1",
                protectedHeader = header,
                externalAad = byteArrayOf(),
                payload = payload
            )
        ).encodeToString(Base16())

        val inputObjectSignature = CoseSigned.create(
            protectedHeader = header,
            payload = payload,
            signature = RsaSignature("bar".encodeToByteArray()),
            payloadSerializer = ByteArraySerializer(),
        ).prepareCoseSignatureInput(byteArrayOf())
            .encodeToString(Base16())

        inputManualSignature.shouldContain("Signature1".encodeToByteArray().encodeToString(Base16()))
        inputObjectSignature shouldBe inputManualSignature

        header = CoseHeader(algorithm = CoseAlgorithm.MAC.HS256)
        val inputManualMac = coseCompliantSerializer.encodeToByteArray(
            CoseInput(
                contextString = "MAC0",
                protectedHeader = header,
                externalAad = byteArrayOf(),
                payload = payload
            )
        ).encodeToString(Base16())

        val inputObjectMac = CoseMac.create(
            protectedHeader = header,
            payload = payload,
            tag = byteArrayOf(),
            payloadSerializer = ByteArraySerializer(),
        ).prepareCoseMacInput(byteArrayOf())
            .encodeToString(Base16())

        inputManualMac.shouldContain("MAC0".encodeToByteArray().encodeToString(Base16()))
        inputObjectMac shouldBe inputManualMac
    }

    "CoseInput is correct for custom types" {
        val payload = DataClass(Random.nextBytes(32).encodeToString(Base16Strict))
        var header = CoseHeader(algorithm = CoseAlgorithm.Signature.ES256)
        val inputManualSignature = coseCompliantSerializer.encodeToByteArray(
            CoseInput(
                contextString = "Signature1",
                protectedHeader = header,
                externalAad = byteArrayOf(),
                payload = coseCompliantSerializer.encodeToByteArray(ByteStringWrapper(payload)).wrapInCborTag(24),
            )
        ).encodeToString(Base16())

        val inputObjectSignature = CoseSigned.create(
            protectedHeader = header,
            payload = payload,
            signature = RsaSignature("bar".encodeToByteArray()),
            payloadSerializer = DataClass.serializer(),
        ).prepareCoseSignatureInput(byteArrayOf())
            .encodeToString(Base16())

        inputManualSignature.shouldContain("Signature1".encodeToByteArray().encodeToString(Base16()))
        inputObjectSignature shouldBe inputManualSignature

        header = CoseHeader(algorithm = CoseAlgorithm.MAC.HS256)
        val inputManualMac = coseCompliantSerializer.encodeToByteArray(
            CoseInput(
                contextString = "MAC0",
                protectedHeader = header,
                externalAad = byteArrayOf(),
                payload = coseCompliantSerializer.encodeToByteArray(ByteStringWrapper(payload)).wrapInCborTag(24),
            )
        ).encodeToString(Base16())

        val inputObjectMac = CoseMac.create(
            protectedHeader = header,
            payload = payload,
            tag = byteArrayOf(),
            payloadSerializer = DataClass.serializer(),
        ).prepareCoseMacInput(byteArrayOf())
            .encodeToString(Base16())

        inputManualMac.shouldContain("MAC0".encodeToByteArray().encodeToString(Base16()))
        inputObjectMac shouldBe inputManualMac
    }

    // protected header {16: "t", 1: -257 (RS256)}, i.e. not in the order Signum would encode it
    val protectedHeaderOtherOrder = "A210617401390100"
    val payloadHex = "546869732069732074686520636F6E74656E742E"

    "Protected header bytes are retained for CoseSigned" {
        val input = "8448${protectedHeaderOtherOrder}A054${payloadHex}43626172".decodeToByteArray(Base16())

        val cose = CoseSigned.deserialize(ByteArraySerializer(), input).getOrThrow()
        cose.protectedHeader shouldBe CoseHeader(algorithm = CoseAlgorithm.Signature.RS256, type = "t")
        cose.wireFormat.rawProtectedHeader shouldBe protectedHeaderOtherOrder.decodeToByteArray(Base16())
        // [ "Signature1", protected as received, external_aad, payload ]
        cose.prepareCoseSignatureInput().encodeToString(Base16Strict).uppercase() shouldBe
                "846A5369676E61747572653148${protectedHeaderOtherOrder}4054${payloadHex}"
        cose.serialize(ByteArraySerializer()) shouldBe input
        CoseSigned.deserialize(ByteArraySerializer(), cose.serialize(ByteArraySerializer())).getOrThrow() shouldBe cose
        Json.decodeFromString<CoseSigned<ByteArray>>(Json.encodeToString(cose)) shouldBe cose

        val recreated = CoseSigned.create(
            protectedHeader = cose.protectedHeader,
            payload = cose.payload,
            signature = cose.signature,
            payloadSerializer = ByteArraySerializer(),
        )
        // same parsed header, but different bytes on the wire
        recreated.protectedHeader shouldBe cose.protectedHeader
        (recreated == cose) shouldBe false
        recreated.wireFormat.rawProtectedHeader.encodeToString(Base16Strict).uppercase() shouldBe "A201390100106174"
    }

    "Protected header bytes are retained for CoseSigned with detached payload" {
        val input = "8448${protectedHeaderOtherOrder}A0F643626172".decodeToByteArray(Base16())

        val cose = CoseSigned.deserialize(ByteArraySerializer(), input).getOrThrow()
        cose.payload shouldBe null
        cose.prepareCoseSignatureInput(detachedPayload = payloadHex.decodeToByteArray(Base16()))
            .encodeToString(Base16Strict).uppercase() shouldBe
                "846A5369676E61747572653148${protectedHeaderOtherOrder}4054${payloadHex}"
        cose.serialize(ByteArraySerializer()) shouldBe input
    }

    "Protected header bytes are retained for CoseMac" {
        // protected header {16: "t", 1: 5 (HS256)}
        val protectedHeader = "A21061740105"
        val input = "8446${protectedHeader}A054${payloadHex}40".decodeToByteArray(Base16())

        val cose = CoseMac.deserialize(ByteArraySerializer(), input).getOrThrow()
        cose.protectedHeader shouldBe CoseHeader(algorithm = CoseAlgorithm.MAC.HS256, type = "t")
        // [ "MAC0", protected as received, external_aad, payload ]
        cose.prepareCoseMacInput().encodeToString(Base16Strict).uppercase() shouldBe
                "84644D41433046${protectedHeader}4054${payloadHex}"
        cose.serialize(ByteArraySerializer()) shouldBe input
        CoseMac.deserialize(ByteArraySerializer(), cose.serialize(ByteArraySerializer())).getOrThrow() shouldBe cose
    }

    "Empty protected header encoded as map is retained" {
        // protected header h'A0' instead of h''
        val input = "8441A0A10139010054${payloadHex}43626172".decodeToByteArray(Base16())

        val cose = CoseSigned.deserialize(ByteArraySerializer(), input).getOrThrow()
        cose.protectedHeader shouldBe CoseHeader()
        cose.wireFormat.rawProtectedHeader shouldBe byteArrayOf(0xA0.toByte())
        cose.prepareCoseSignatureInput().encodeToString(Base16Strict).uppercase() shouldBe
                "846A5369676E61747572653141A04054${payloadHex}"
        cose.serialize(ByteArraySerializer()) shouldBe input
    }

    "Empty protected header is encoded as zero-length byte string on creation" {
        val cose = CoseSigned.create(
            protectedHeader = CoseHeader(),
            unprotectedHeader = CoseHeader(algorithm = CoseAlgorithm.Signature.RS256),
            payload = payloadHex.decodeToByteArray(Base16()),
            signature = RsaSignature("bar".encodeToByteArray()),
            payloadSerializer = ByteArraySerializer(),
        )
        cose.wireFormat.rawProtectedHeader shouldBe byteArrayOf()
        cose.prepareCoseSignatureInput().encodeToString(Base16Strict).uppercase() shouldBe
                "846A5369676E617475726531404054${payloadHex}"
        CoseSigned.deserialize(ByteArraySerializer(), cose.serialize(ByteArraySerializer())).getOrThrow() shouldBe cose
    }
}

private fun ByteArray.wrapInCborTag(tag: Byte) = byteArrayOf(0xd8.toByte()) + byteArrayOf(tag) + this
