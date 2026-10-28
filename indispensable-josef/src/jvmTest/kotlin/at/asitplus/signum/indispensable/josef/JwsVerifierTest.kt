package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.dsl.ec
import at.asitplus.signum.dsl.rsa
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.sign.RsaAlgorithm
import at.asitplus.signum.indispensable.sign.SignatureVerifier
import at.asitplus.signum.indispensable.sign.Signer
import at.asitplus.signum.indispensable.sign.makeVerifier
import at.asitplus.signum.indispensable.sign.verify
import at.asitplus.signum.supreme.sign.InvalidSignature
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

private val verificationPayload = SigningPayload("alice")

private fun JwsFlattened.Raw.decodeForVerification() =
    joseCompliantSerializer.decodeFromString<JwsFlattened.Raw>(joseCompliantSerializer.encodeToString(this))
        .typed<SigningHeader, SigningPayload>()

private fun JwsGeneral.Raw.decodeForVerification() =
    joseCompliantSerializer.decodeFromString<JwsGeneral.Raw>(joseCompliantSerializer.encodeToString(this))
        .typed<SigningHeader, SigningPayload>()

private fun ByteArray.withChangedLastBit() = copyOf().also {
    it[it.lastIndex] = (it.last().toInt() xor 1).toByte()
}

val JwsVerifierTest by matrixSuite {
    "flattened verification preserves signed bytes and ignores unprotected header changes" {
        val signer = Signer.Ephemeral { ec {} }
        val header = SigningHeader(algorithm = JwsAlgorithm.Signature.ES256, keyId = "original-key")
        val wire = JwsSigner(listOf(signer)).signFlattened(header, verificationPayload, setOf("kid")).raw
        val verifier = signer.makeVerifier()
        val decoded = wire.decodeForVerification()

        verifier.verify(decoded.raw.signatureInput, decoded.signature) shouldBe SignatureVerifier.Success

        val changedUnprotected = wire.copy(
            unprotectedHeader = JsonObject(mapOf("kid" to JsonPrimitive("changed-key"))),
        ).decodeForVerification()
        changedUnprotected.header.keyId shouldBe "changed-key"
        verifier.verify(changedUnprotected.raw.signatureInput, changedUnprotected.signature) shouldBe
                SignatureVerifier.Success

        // Whitespace leaves the decoded values unchanged but changes the signed bytes.
        val changedHeader = wire.copy(
            plainProtectedHeader = (wire.plainProtectedHeader!!.decodeToString() + " ").encodeToByteArray(),
        ).decodeForVerification()
        changedHeader.header shouldBe decoded.header
        shouldThrow<InvalidSignature> { verifier.verify(changedHeader.raw.signatureInput, changedHeader.signature) }

        val changedPayload = wire.copy(
            plainPayload = (wire.plainPayload.decodeToString() + " ").encodeToByteArray(),
        ).decodeForVerification()
        changedPayload.payload shouldBe decoded.payload
        shouldThrow<InvalidSignature> { verifier.verify(changedPayload.raw.signatureInput, changedPayload.signature) }
    }

    "flattened verification rejects a changed signature and a different key" {
        val signer = Signer.Ephemeral { ec {} }
        val otherSigner = Signer.Ephemeral { ec {} }
        val wire = JwsSigner(listOf(signer)).signFlattened(
            SigningHeader(algorithm = JwsAlgorithm.Signature.ES256), verificationPayload,
        ).raw
        val decoded = wire.decodeForVerification()
        val verifier = signer.makeVerifier()

        verifier.verify(decoded.raw.signatureInput, decoded.signature) shouldBe SignatureVerifier.Success
        val otherVerifier = otherSigner.makeVerifier()
        shouldThrow<InvalidSignature> { otherVerifier.verify(decoded.raw.signatureInput, decoded.signature) }

        val changedSignature = wire.copy(plainSignature = wire.plainSignature.withChangedLastBit())
            .decodeForVerification()
        shouldThrow<InvalidSignature> {
            verifier.verify(changedSignature.raw.signatureInput, changedSignature.signature)
        }
    }

    "general verification uses each signature's algorithm and optional protected header" {
        val signers = listOf(
            Signer.Ephemeral { ec {} },
            Signer.Ephemeral {
                rsa {
                    bits = 2048
                    digest = Digest.SHA256
                    padding = RsaAlgorithm.Padding.PSS
                }
            },
        )
        val headers = signers.mapIndexed { index, signer ->
            JwsHeaderWrapped(
                SigningHeader(
                    algorithm = signer.signatureAlgorithm.toJwsAlgorithm().getOrThrow(), keyId = "key-$index",
                ),
                if (index == 0) setOf("kid") else setOf("alg", "kid"),
            )
        }
        val wire = JwsSigner(signers).signGeneral(verificationPayload, headers).raw
        val decoded = wire.decodeForVerification()

        decoded.raw.signatureElements[1].plainProtectedHeader shouldBe null
        signers.forEachIndexed { index, signer ->
            signer.makeVerifier().verify(decoded.raw.signatureInputs[index], decoded.signatures[index]) shouldBe
                    SignatureVerifier.Success
        }
        val flattened = decoded.toFlattened()[1]
        signers[1].makeVerifier().verify(flattened.raw.signatureInput, flattened.signature) shouldBe
                SignatureVerifier.Success
    }

    "general verification preserves duplicate headers and rejects signatures assigned to different keys" {
        val signers = List(2) { Signer.Ephemeral { ec {} } }
        val header = SigningHeader(algorithm = JwsAlgorithm.Signature.ES256, keyId = "shared-header")
        val wire = signers.map { signer ->
            JwsSigner(listOf(signer)).signFlattened(header, verificationPayload, setOf("kid")).raw
        }.toGeneral()
        val decoded = wire.decodeForVerification()
        val verifiers = signers.map { it.makeVerifier() }

        decoded.headers shouldBe listOf(header, header)
        verifiers.forEachIndexed { index, verifier ->
            verifier.verify(decoded.raw.signatureInputs[index], decoded.signatures[index]) shouldBe
                    SignatureVerifier.Success
            shouldThrow<InvalidSignature> {
                verifier.verify(decoded.raw.signatureInputs[index], decoded.signatures[1 - index])
            }
        }
    }

    "general verification detects shared payload tampering and isolates per-signature changes" {
        val signer = Signer.Ephemeral { ec {} }
        val verifier = signer.makeVerifier()
        val headers = List(2) { index ->
            JwsHeaderWrapped(
                SigningHeader(
                    algorithm = JwsAlgorithm.Signature.ES256, type = "type-$index", keyId = "key-$index",
                ),
                setOf("kid"),
            )
        }
        val wire = JwsSigner(listOf(signer)).signGeneral(verificationPayload, headers).raw
        val decoded = wire.decodeForVerification()
        decoded.signatures.forEachIndexed { index, signature ->
            verifier.verify(decoded.raw.signatureInputs[index], signature) shouldBe SignatureVerifier.Success
        }

        val changedPayload = JwsGeneral.Raw(
            (wire.plainPayload.decodeToString() + " ").encodeToByteArray(), wire.signatureElements,
        ).decodeForVerification()
        changedPayload.payload shouldBe decoded.payload
        changedPayload.signatures.forEachIndexed { index, signature ->
            shouldThrow<InvalidSignature> { verifier.verify(changedPayload.raw.signatureInputs[index], signature) }
        }

        val first = wire.signatureElements[0]
        val changes = listOf(
            first.copy(plainProtectedHeader = (first.plainProtectedHeader!!.decodeToString() + " ").encodeToByteArray()),
            first.copy(plainSignature = first.plainSignature.withChangedLastBit()),
        )
        changes.forEach { changedElement ->
            val changed = JwsGeneral.Raw(wire.plainPayload, listOf(changedElement, wire.signatureElements[1]))
                .decodeForVerification()
            shouldThrow<InvalidSignature> { verifier.verify(changed.raw.signatureInputs[0], changed.signatures[0]) }
            verifier.verify(changed.raw.signatureInputs[1], changed.signatures[1]) shouldBe SignatureVerifier.Success
        }

        val changedUnprotected = JwsGeneral.Raw(
            wire.plainPayload,
            listOf(
                first.copy(unprotectedHeader = JsonObject(mapOf("kid" to JsonPrimitive("changed-key")))),
                wire.signatureElements[1],
            ),
        ).decodeForVerification()
        changedUnprotected.headers[0].keyId shouldBe "changed-key"
        changedUnprotected.signatures.forEachIndexed { index, signature ->
            verifier.verify(changedUnprotected.raw.signatureInputs[index], signature) shouldBe SignatureVerifier.Success
        }
    }
}
