package at.asitplus.signum.indispensable.josef

import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe

private val typedPayload = SigningPayload("alice")
private val typedPayloadJson = """{"sub":"alice"}"""

val JwsRawTypedTest by matrixSuite {
    "compact facade decodes values and conversions retain the payload view" {
        val compactString = "eyJhbGciOiJSUzI1NiJ9.e30.AQ"
        val typedCompact = JwsTyped<SigningHeader, SigningPayload>(compactString)

        typedCompact.header.algorithm shouldBe JwsAlgorithm.Signature.RS256
        typedCompact.payload shouldBe SigningPayload()
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
            JwsHeader.SerialNames.KEY_ID,
            JwsHeader.SerialNames.CONTENT_TYPE,
        )
        val header = SigningHeader(
            algorithm = JwsAlgorithm.Signature.RS256,
            type = "application/example+jws",
            keyId = "kid-flattened",
            contentType = "application/example+json",
        )
        val wire = flattenedSample(
            JwsHeaderWrapped(header, unprotectedMembers), typedPayloadJson.encodeToByteArray(), byteArrayOf(4, 3, 2, 1),
        )
        val typed = wire.typed<SigningHeader, SigningPayload>()

        (typed.raw === wire) shouldBe true
        typed.payload shouldBe typedPayload
        typed.header shouldBe header
        typed.unprotectedHeaderMembers shouldBe unprotectedMembers
        typed.signature.joseBytes shouldBe byteArrayOf(4, 3, 2, 1)
    }

    "general facade accepts distinct arrays with equal payloads and retains signature order" {
        val headers = listOf(
            JwsHeaderWrapped(
                SigningHeader(algorithm = JwsAlgorithm.Signature.RS256, keyId = "kid-1"),
                setOf(JwsHeader.SerialNames.KEY_ID),
            ),
            JwsHeaderWrapped(
                SigningHeader(algorithm = JwsAlgorithm.Signature.RS256, type = "application/example+jws", keyId = "kid-2"),
                setOf(JwsHeader.SerialNames.TYPE),
            ),
        )
        val flattened = headers.mapIndexed { index, header ->
            // Each signature gets a separate array with the same payload bytes.
            flattenedSample(header, typedPayloadJson.encodeToByteArray(), byteArrayOf((index + 1).toByte()))
        }
        val typed = JwsTyped<SigningHeader, SigningPayload>(flattened)

        typed.payload shouldBe typedPayload
        typed.headers shouldBe headers.map { it.header }
        typed.unprotectedHeaderMembers shouldBe headers.map { it.unprotectedHeaderMembers }
        typed.signatures.map { it.joseBytes } shouldBe listOf(byteArrayOf(1), byteArrayOf(2))
        val expanded = typed.toFlattened()
        expanded.map { it.raw } shouldBe flattened
        expanded.forEach { (it.payload === typed.payload) shouldBe true }
    }
}
