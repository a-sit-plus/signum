@file:OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)

package at.asitplus.signum.indispensable.cosef

import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.cosef.legacy.CoseHeader as FixtureHeader
import at.asitplus.signum.indispensable.sign.RsaSignature
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.shouldBe
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.encodeToByteArray

val CoseStructureSerializationTest by matrixSuite {
    "Raw decoding needs neither the protected model nor the payload serializer" {
        // Protected bytes deliberately are not a CBOR map; raw decoding leaves them uninterpreted.
        val input = "844101A04040".hexBytes()
        val raw = CoseSign1.Raw<EmptyCoseHeader>(input)
        raw.plainProtectedHeader.hex() shouldBe "01"
        coseCompliantSerializer.encodeToByteArray(raw) shouldBe input
        shouldThrowAny { raw.typed<EmptyCoseHeader, ByteArray>() }
    }

    "Both empty protected encodings survive typed serialization" {
        for (protected in listOf("40", "41A0")) {
            val input = "84${protected}A04040".hexBytes()
            val typed = CoseSign1<EmptyCoseHeader, EmptyCoseHeader, ByteArray>(input)
            typed.payload shouldBe byteArrayOf()
            typed.isDetached shouldBe false
            coseCompliantSerializer.encodeToByteArray(typed) shouldBe input
            val mac = CoseMac0<EmptyCoseHeader, EmptyCoseHeader, ByteArray>(input)
            coseCompliantSerializer.encodeToByteArray(mac) shouldBe input
        }
    }

    "Detached payloads remain null and require externally supplied bytes" {
        val bytes = "8440A0F640".hexBytes()
        val sign = CoseSign1<EmptyCoseHeader, EmptyCoseHeader, ByteArray>(bytes)
        val mac = CoseMac0<EmptyCoseHeader, EmptyCoseHeader, ByteArray>(bytes)
        sign.isDetached shouldBe true
        sign.payload shouldBe null
        shouldThrowAny { sign.signatureInput() }
        shouldThrowAny { mac.macInput() }
        sign.signatureInput(detachedPayload = byteArrayOf()).hex() shouldBe "846A5369676E617475726531404040"
        mac.macInput(detachedPayload = byteArrayOf()).hex() shouldBe "84644D414330404040"
        coseCompliantSerializer.encodeToByteArray(sign) shouldBe bytes
        shouldThrowAny { CoseSign1.Raw<EmptyCoseHeader>("8440A04040".hexBytes()).signatureInput(detachedPayload = byteArrayOf()) }
    }

    "Reordered and nonpreferred protected representations stay authoritative" {
        for (protected in listOf("A210617401390100", "A2181061781801390100")) {
            val header = protected.hexBytes()
            val input = byteArrayOf(0x84.toByte(), (0x40 + header.size).toByte()) + header + "A04301020343626172".hexBytes()
            val typed = CoseSign1<FixtureHeader, EmptyCoseHeader, ByteArray>(input)
            typed.raw.plainProtectedHeader shouldBe header
            typed.signatureInput() shouldBe COSE.sign1StructureInput(header, payload = byteArrayOf(1, 2, 3))
            coseCompliantSerializer.encodeToByteArray(typed) shouldBe input
        }
    }

    "Typed serializers compose when nested" {
        val input = "8443A10126A04040".hexBytes()
        val sign = CoseSign1<FixtureHeader, EmptyCoseHeader, ByteArray>(input)
        val nested = NestedCose(sign)
        val bytes = coseCompliantSerializer.encodeToByteArray(nested)
        val decoded = coseCompliantSerializer.decodeFromByteArray(NestedCose.serializer(), bytes)
        coseCompliantSerializer.encodeToByteArray(decoded.sign) shouldBe input
    }

    "Raw unprotected models deliberately discard ignored fields on re-encoding" {
        val raw = CoseSign1.Raw<EmptyCoseHeader>("8443A10126A1616B014040".hexBytes())
        raw.plainProtectedHeader.hex() shouldBe "A10126"
        coseCompliantSerializer.encodeToByteArray(raw).hex() shouldBe "8443A10126A04040"
    }

    "COSE_Sign has a list of three-element signatures and a distinct signing structure" {
        val bytes = "8440A040818340A040".hexBytes()
        val typed = CoseSign.Raw<EmptyCoseHeader, EmptyCoseHeader>(bytes).typed<EmptyCoseHeader, EmptyCoseHeader, ByteArray>()
        typed.signatures.size shouldBe 1
        typed.signatureInput(0).hex() shouldBe "85695369676E617475726540404040"
        coseCompliantSerializer.encodeToByteArray(typed) shouldBe bytes
        shouldThrowAny { CoseSign1.Raw<EmptyCoseHeader>(bytes) }
        shouldThrowAny { CoseSign.Raw<EmptyCoseHeader, EmptyCoseHeader>("8440A04080".hexBytes()) }
        val detached = CoseSign.Raw<EmptyCoseHeader, EmptyCoseHeader>("8440A0F6818340A040".hexBytes())
        shouldThrowAny { detached.signatureInput(0) }
        detached.signatureInput(0, detachedPayload = byteArrayOf()) shouldBe typed.signatureInput(0)
        for (wire in listOf(
            "8445A101390100A040818340A043626172",
            "8440A10139010040818340A043626172",
            "8440A040818345A101390100A043626172",
            "8440A040818340A10139010043626172",
        )) {
            val decoded = CoseSign.Raw<FixtureHeader, FixtureHeader>(wire.hexBytes()).typed<FixtureHeader, FixtureHeader, ByteArray>()
            decoded.signature(0) shouldBe RsaSignature("bar".encodeToByteArray())
        }
    }

    "Legacy tag 24 payload policy and direct payload decoding stay compatible" {
        val payload = DataClass("alice")
        val bytes = encodePayload(payload, DataClass.serializer())
        bytes.take(2).toByteArray().hex() shouldBe "D818"
        bytes.toTypedPayload(DataClass.serializer()) shouldBe payload
        coseCompliantSerializer.encodeToByteArray(payload).toTypedPayload(DataClass.serializer()) shouldBe payload
    }
}

@Serializable
private data class NestedCose(val sign: CoseSign1<FixtureHeader, EmptyCoseHeader, ByteArray>)
