package at.asitplus.signum.indispensable.josef

import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

private val typedPayload = JsonObject(
    mapOf(
        "issuer" to JsonPrimitive("https://issuer.example"),
        "subject" to JsonPrimitive("alice"),
        "admin" to JsonPrimitive(true),
    )
)
private val typedPayloadJson = """{"issuer":"https://issuer.example","subject":"alice","admin":true}"""

val JwsRawTypedTest by matrixSuite {
    "compact facade decodes values and conversions retain the payload view" {
        val compactString = "eyJhbGciOiJSUzI1NiJ9.e30.AQ"
        val typedCompact = JwsTyped<JwsHeaderMonolith, JsonObject>(compactString)

        typedCompact.header.algorithm shouldBe JwsAlgorithm.Signature.RS256
        typedCompact.payload shouldBe JsonObject(emptyMap())
        typedCompact.signature.joseBytes shouldBe byteArrayOf(1)
        typedCompact.toString() shouldBe compactString

        val typedFlattened = typedCompact.toFlattened()
        val convertedCompact = typedFlattened.toCompact()

        (typedFlattened.payload === typedCompact.payload) shouldBe true
        (convertedCompact.payload === typedCompact.payload) shouldBe true
        convertedCompact shouldBe typedCompact
    }

    "flattened typed views decode split headers and expose their placement" {
        val unprotectedMembers = setOf(
            JwsHeaderMonolith.SerialNames.KEY_ID,
            JwsHeaderMonolith.SerialNames.CONTENT_TYPE,
        )
        val header = JwsHeaderMonolith(
            algorithm = JwsAlgorithm.Signature.RS256,
            type = "application/example+jws",
            keyId = "kid-flattened",
            contentType = "application/example+json",
        )
        val wire = flattenedSample(
            JwsHeaderWrapped(header, unprotectedMembers), typedPayloadJson.encodeToByteArray(), byteArrayOf(4, 3, 2, 1),
        )
        val typed = wire.typed<JwsHeaderMonolith, JsonObject>()

        (typed.jws === wire) shouldBe true
        typed.payload shouldBe typedPayload
        typed.header shouldBe header
        typed.unprotectedHeaderMembers shouldBe unprotectedMembers
        typed.signature.joseBytes shouldBe byteArrayOf(4, 3, 2, 1)
    }

    "general facade accepts distinct arrays with equal payloads and retains signature order" {
        val headers = listOf(
            JwsHeaderWrapped(
                JwsHeaderMonolith(algorithm = JwsAlgorithm.Signature.RS256, keyId = "kid-1"),
                setOf(JwsHeaderMonolith.SerialNames.KEY_ID),
            ),
            JwsHeaderWrapped(
                JwsHeaderMonolith(algorithm = JwsAlgorithm.Signature.RS256, type = "application/example+jws", keyId = "kid-2"),
                setOf(JwsHeaderMonolith.SerialNames.TYPE),
            ),
        )
        val flattened = headers.mapIndexed { index, header ->
            // Each signature gets a separate array with the same payload bytes.
            flattenedSample(header, typedPayloadJson.encodeToByteArray(), byteArrayOf((index + 1).toByte()))
        }
        val typed = JwsTyped<JwsHeaderMonolith, JsonObject>(flattened)

        typed.payload shouldBe typedPayload
        typed.headers shouldBe headers.map { it.header }
        typed.unprotectedHeaderMembers shouldBe headers.map { it.unprotectedHeaderMembers }
        typed.signatures.map { it.joseBytes } shouldBe listOf(byteArrayOf(1), byteArrayOf(2))
        val expanded = typed.toFlattened()
        expanded.map { it.jws } shouldBe flattened
        expanded.forEach { (it.payload === typed.payload) shouldBe true }
    }
}
