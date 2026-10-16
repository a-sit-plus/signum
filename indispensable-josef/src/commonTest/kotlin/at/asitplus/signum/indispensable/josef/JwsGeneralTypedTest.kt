package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.result.shouldBeFailure
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonTransformingSerializer

val JwsGeneralTypedTest by matrixSuite {
    "general typed views retain duplicate headers and duplicate signature elements in order" {
        val first = joseCompliantSerializer.decodeFromString<JwsFlattened>(
            flattenedJson(headerJson = """{"kid":"shared"}"""),
        )
        val second = first.copy(plainSignature = byteArrayOf(2))
        val flattened = listOf(first, second, first)
        val wire = flattened.toJwsGeneral()
        val typed = wire.typed<JsonObject, JwsHeader>()

        (typed.jws === wire) shouldBe true
        typed.signatureViews.size shouldBe 3
        typed.headers.map { it.keyId } shouldBe listOf("shared", "shared", "shared")
        typed.unprotectedHeaderMembers shouldBe List(3) { setOf(JwsHeader.SerialNames.KEY_ID) }
        typed.signatures.map { it.joseBytes } shouldBe flattened.map { it.plainSignature }
        val typedFlattened = typed.toJwsFlattenedTyped()
        typedFlattened.map { it.jws } shouldBe flattened
        typedFlattened shouldBe flattened.map { it.typed<JsonObject, JwsHeader>() }
        joseCompliantSerializer.decodeFromString<JwsGeneral>(
            joseCompliantSerializer.encodeToString(typed.jws),
        ).typed<JsonObject, JwsHeader>() shouldBe typed
    }

    "changing the input wire signature list cannot invalidate a general typed view" {
        val original = joseCompliantSerializer.decodeFromString<JwsGeneral>(generalVectorJson)
        val signatureElements = original.signatureElements.toMutableList()
        val wire = JwsGeneral(original.plainPayload, signatureElements)
        val typed = wire.typed<JsonObject, JwsHeader>()
        val expectedViews = typed.toJwsFlattenedTyped()
        val expectedHashCode = typed.hashCode()

        signatureElements.reverse()
        signatureElements.clear()

        wire shouldBe original
        wire.signatureInputs shouldBe original.signatureInputs
        typed.toJwsFlattenedTyped() shouldBe expectedViews
        typed.hashCode() shouldBe expectedHashCode
        typed shouldBe original.typed<JsonObject, JwsHeader>()
        joseCompliantSerializer.encodeToString(wire) shouldBe joseCompliantSerializer.encodeToString(original)
    }

    "changing the input signature view list cannot alter headers placement or conversions" {
        val wire = joseCompliantSerializer.decodeFromString<JwsGeneral>(generalVectorJson)
        val expected = wire.typed<JsonObject, JwsHeader>()
        val views = expected.signatureViews.toMutableList()
        val typed = JwsGeneralTyped(wire, expected.payload, views)

        views.reverse()
        views.clear()

        typed shouldBe expected
        typed.hashCode() shouldBe expected.hashCode()
        typed.headers shouldBe expected.headers
        typed.unprotectedHeaderMembers shouldBe expected.unprotectedHeaderMembers
        typed.signatures shouldBe expected.signatures
        typed.toJwsFlattenedTyped() shouldBe expected.toJwsFlattenedTyped()
    }

    "general typed views reject missing extra or reordered signature views" {
        val wire = joseCompliantSerializer.decodeFromString<JwsGeneral>(generalVectorJson)
        val typed = wire.typed<JsonObject, JwsHeader>()
        val views = typed.signatureViews
        val payload = typed.payload

        listOf(emptyList(), views.dropLast(1), views + views.first()).forEach { mismatched ->
            runCatching { JwsGeneralTyped(wire, payload, mismatched) }
                .shouldBeFailure().message.shouldContain("number of wire signature elements")
        }
        runCatching { JwsGeneralTyped(wire, payload, views.reversed()) }
            .shouldBeFailure().message.shouldContain("wire signature bytes in order")
    }

    "general typed views decode the shared payload only once" {
        val wire = joseCompliantSerializer.decodeFromString<JwsGeneral>(generalVectorJson)
        var payloadDecodes = 0
        val payloadSerializer = object : JsonTransformingSerializer<JsonObject>(JsonObject.serializer()) {
            override fun transformDeserialize(element: JsonElement): JsonElement {
                payloadDecodes++
                return element
            }
        }
        val typed = wire.typed(payloadSerializer, JwsHeader.serializer())

        typed.signatureViews.size shouldBe 2
        payloadDecodes shouldBe 1
        typed.toJwsFlattenedTyped().forEach { (it.payload === typed.payload) shouldBe true }
    }
}
