package at.asitplus.signum.indispensable.cosef

import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.withClue
import io.kotest.matchers.shouldBe
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

@Serializable
private data class Payload(val first: String, val second: Int)

@Serializable
private data class ReversedPayload(val second: Int, val first: String)

@Serializable
private data class Holder(val payload: ByteStringWrapper<Payload>)

val ByteStringWrapperTest by matrixSuite {

    "encoding keeps the serialized bytes of a decoded wrapper" {
        val payload = Payload("hello", 42)
        val canonical = coseCompliantSerializer.encodeToByteArray(payload)
        //same properties, declared in the opposite order, so the same value serialized with its keys swapped
        val reordered = coseCompliantSerializer.encodeToByteArray(ReversedPayload(payload.second, payload.first))

        //kotlinx.serialization writes properties in declaration order; coseCompliantSerializer does not sort keys
        withClue("precondition: both serializations have their keys in exactly opposite order") {
            val canonicalText = canonical.decodeToString()
            val reorderedText = reordered.decodeToString()
            (canonicalText.indexOf("first") < canonicalText.indexOf("second")) shouldBe true
            (reorderedText.indexOf("second") < reorderedText.indexOf("first")) shouldBe true
        }

        val encoded = coseCompliantSerializer.encodeToByteArray(Holder(ByteStringWrapper(payload, reordered)))
        val decoded = coseCompliantSerializer.decodeFromByteArray<Holder>(encoded)

        decoded.payload.value shouldBe payload
        decoded.payload.serialized shouldBe reordered
        coseCompliantSerializer.encodeToByteArray(decoded) shouldBe encoded
    }

    "encoding serializes the value of a wrapper without serialized bytes" {
        val payload = Payload("hello", 42)

        val encoded = coseCompliantSerializer.encodeToByteArray(Holder(ByteStringWrapper(payload)))
        val decoded = coseCompliantSerializer.decodeFromByteArray<Holder>(encoded)

        decoded.payload.value shouldBe payload
        decoded.payload.serialized shouldBe coseCompliantSerializer.encodeToByteArray(payload)
        coseCompliantSerializer.encodeToByteArray(decoded) shouldBe encoded
    }
}
