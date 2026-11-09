package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.dsl.ec
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.sign.SignatureVerifier
import at.asitplus.signum.indispensable.sign.Signer
import at.asitplus.signum.indispensable.sign.makeVerifier
import at.asitplus.signum.indispensable.sign.sign
import at.asitplus.signum.indispensable.sign.signature
import at.asitplus.signum.indispensable.sign.verify
import at.asitplus.signum.supreme.Supreme
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlin.time.Instant

val NumericDateVerificationTest by matrixSuite {
    Supreme.init()

    "compact JWS with non-integer NumericDates decodes, verifies and round-trips" {
        val signer = Signer.Ephemeral { ec {} }
        // Encoded differently than Signum would encode it, so verification must use the bytes as received
        val header = """{"alg":"ES256"}""".encodeToByteArray()
        val payload = """{"sub":"alice","nbf":17e8,"iat":1.7e9,"exp":1700000000.5}""".encodeToByteArray()
        val signatureInput = JwsRaw.getSignatureInput(header, payload)
        val signature = signer.sign(signatureInput).signature
        val compact = signatureInput.decodeToString() + "." + signature.joseBytes.encodeToString(Base64UrlStrict)

        val jws = JwsCompact<SigningHeader, NumericDatePayload>(compact)

        jws.payload.subject shouldBe "alice"
        jws.payload.notBefore shouldBe Instant.fromEpochSeconds(1700000000)
        jws.payload.issuedAt shouldBe Instant.fromEpochSeconds(1700000000)
        jws.payload.expiration shouldBe Instant.fromEpochSeconds(1700000000, 500_000_000)
        signer.makeVerifier().verify(jws.signatureInput, jws.signature) shouldBe SignatureVerifier.Success
        jws.raw.toString() shouldBe compact
    }
}
