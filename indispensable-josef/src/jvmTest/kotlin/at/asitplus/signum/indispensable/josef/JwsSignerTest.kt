package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.dsl.ec
import at.asitplus.signum.dsl.rsa
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.sign.*
import at.asitplus.signum.supreme.Supreme
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject

@Serializable
internal data class SigningHeader(
    @SerialName("alg") override val algorithm: JwsAlgorithm,
    @SerialName("kid") override val keyId: String? = null,
    val extension: String? = null,
    @SerialName("jwk") override val jsonWebKey: JsonWebKey? = null,
) : JwsHeaderBase {
    @Transient
    override val type: String? = null

    @Transient
    override val contentType: String? = null

    @Transient
    override val certificateChain: CertificateChain? = null

    @Transient
    override val jsonWebKeySetUrl: String? = null

    @Transient
    override val certificateUrl: String? = null

    @Transient
    override val certificateSha1Thumbprint: ByteArray? = null

    @Transient
    override val certificateSha256Thumbprint: ByteArray? = null

    @Transient
    override val crit: List<String>? = null
}

@Serializable
internal data class SigningPayload(val sub: String)

private suspend fun newEcSigner(): Signer.WithExportableKey = Signer.Ephemeral { ec {} }

private suspend fun newRsaSigner(): Signer.WithExportableKey = Signer.Ephemeral {
    rsa {
        bits = 2048
        digest = Digest.SHA256
        padding = RsaAlgorithm.Padding.PSS
    }
}

private class CountingSigner(private val delegate: Signer) : Signer by delegate {
    var calls = 0
        private set

    override suspend fun sign(data: SignatureInput): SignatureResult<*> {
        calls++
        return delegate.sign(data)
    }
}

val JwsSignerTest by matrixSuite {
    Supreme.init()

    "compact signing happy path" {
        val signer = newEcSigner()
        val header = SigningHeader(JwsAlgorithm.Signature.ES256, "key", "custom")
        val jwsSigner = JwsSigner(listOf(signer))
        val typed = jwsSigner.signCompact(header, SigningPayload("alice"))
        typed.shouldBeInstanceOf<JwsCompact<SigningPayload, SigningHeader>>()

        val wireJson = typed.toString()
        val roundtrip = JwsCompact<SigningPayload, SigningHeader>(wireJson)
        roundtrip shouldBe typed

        val verifier = signer.signatureAlgorithm.verifierFor(signer.publicKey)
        verifier.verify(typed.jws.signatureInput, typed.signature) shouldBe SignatureVerifier.Success
        verifier.verify(roundtrip.jws.signatureInput, roundtrip.signature) shouldBe SignatureVerifier.Success
    }

    "flattened signing omits empty header fragments" {
        val signer = newEcSigner()
        val header = SigningHeader(JwsAlgorithm.Signature.ES256, "key", "custom")
        val jwsSigner = JwsSigner(listOf(signer))
        for (placement in listOf(emptySet(), setOf("alg", "kid", "extension"))) {
            val typed = jwsSigner.signFlattened(header, SigningPayload("alice"), placement)
            typed.jws.unprotectedHeader?.keys.orEmpty() shouldBe placement

            val wireJson =
                joseCompliantSerializer.encodeToJsonElement(JwsFlattened.Raw.serializer(), typed.jws).jsonObject
            (JwsRaw.SerialNames.HEADER in wireJson) shouldBe placement.isNotEmpty()
            (JwsRaw.SerialNames.PROTECTED in wireJson) shouldBe placement.isEmpty()
            signer.makeVerifier().verify(typed.jws.signatureInput, typed.signature) shouldBe SignatureVerifier.Success
        }
    }

    "general signing serializes one shared payload and preserves signature order" {
        val signers = listOf(newEcSigner(), newRsaSigner())
        // Registration order differs from signature order so positional signer selection fails.
        val jwsSigner = JwsSigner(
            listOf(
                signers[1], signers[0]
            )
        )
        val parameters = signers.mapIndexed { index, signer ->
            JwsHeaderWrapped(
                SigningHeader(signer.signatureAlgorithm.toJwsAlgorithm().getOrThrow(), "key-$index"),
                if (index == 0) setOf("kid") else emptySet(),
            )
        }
        var encodings = 0
        val serializer = object : KSerializer<SigningPayload> by SigningPayload.serializer() {
            override fun serialize(encoder: Encoder, value: SigningPayload) {
                encodings++
                SigningPayload.serializer().serialize(encoder, value)
            }
        }
        val typed = jwsSigner.signGeneral(SigningPayload("alice"), parameters, serializer)
        encodings shouldBe 1
        typed.jws.signatureElements.size shouldBe 2
        typed.toFlattened().forEachIndexed { index, flattened ->
            flattened.jws.plainPayload shouldBe """{"sub":"alice"}""".encodeToByteArray()
            JwsHeaderWrapped.fromParts<SigningHeader>(
                flattened.jws.plainProtectedHeader, flattened.jws.unprotectedHeader,
            ).header.keyId shouldBe "key-$index"
            signers[index].makeVerifier().verify(flattened.jws.signatureInput, flattened.signature) shouldBe
                    SignatureVerifier.Success
        }
    }

    "signing preserves typed values while signing their custom serialized representation" {
        val signer = newEcSigner()
        val jwsSigner = JwsSigner(listOf(signer))
        var payloadEncodings = 0
        val payloadSerializer = object : KSerializer<SigningPayload> by SigningPayload.serializer() {
            override fun serialize(encoder: Encoder, value: SigningPayload) {
                payloadEncodings++
                SigningPayload.serializer().serialize(encoder, value.copy(sub = value.sub.uppercase()))
            }

            override fun deserialize(decoder: Decoder): SigningPayload =
                error("Signing must not deserialize the payload")
        }
        var headerEncodings = 0
        val headerSerializer = object : KSerializer<SigningHeader> by SigningHeader.serializer() {
            override fun serialize(encoder: Encoder, value: SigningHeader) {
                headerEncodings++
                SigningHeader.serializer().serialize(encoder, value.copy(extension = value.extension?.uppercase()))
            }

            override fun deserialize(decoder: Decoder): SigningHeader = error("Signing must not deserialize the header")
        }
        val header = SigningHeader(JwsAlgorithm.Signature.ES256, "key", "custom")
        val payload = SigningPayload("alice")
        val compact = jwsSigner.signCompact(header, payload, payloadSerializer, headerSerializer)
        val flattened = jwsSigner.signFlattened(header, payload, payloadSerializer, headerSerializer, setOf("kid"))
        val general = jwsSigner.signGeneral(
            payload, listOf(JwsHeaderWrapped(header, headerSerializer, emptySet())), payloadSerializer,
        )
        payloadEncodings shouldBe 3
        headerEncodings shouldBe 3
        val views = listOf(compact.toFlattened(), flattened) + general.toFlattened()
        views.forEach { typed ->
            typed.payload shouldBe payload
            typed.header shouldBe header
            typed.jws.getPayload(SigningPayload.serializer()).getOrThrow().sub shouldBe "ALICE"
            JwsHeaderWrapped.fromParts<SigningHeader>(
                typed.jws.plainProtectedHeader, typed.jws.unprotectedHeader,
            ).header.extension shouldBe "CUSTOM"
            signer.makeVerifier().verify(typed.jws.signatureInput, typed.signature) shouldBe SignatureVerifier.Success
        }
    }

    "matching key metadata is preserved on the wire and omitted metadata is not filled in" {
        val signer = newEcSigner()
        signer.publicKey.jwkId = "actual-key"
        val algorithm = JwsAlgorithm.Signature.ES256
        val jwsSigner = JwsSigner(listOf(signer))
        val embeddedKey = signer.publicKey.toJsonWebKey().copy(
            algorithm = algorithm,
            publicKeyUse = "sig",
            keyOperations = setOf("verify"),
        )
        val matching = jwsSigner.signCompact(
            SigningHeader(algorithm, "actual-key", jsonWebKey = embeddedKey), SigningPayload("alice"),
        ).jws.plainProtectedHeader.toProtectedHeaderJsonObject()
        matching.keys shouldBe setOf("alg", "kid", "jwk")
        matching["kid"] shouldBe JsonPrimitive("actual-key")
        matching["jwk"] shouldBe joseCompliantSerializer.encodeToJsonElement(JsonWebKey.serializer(), embeddedKey)

        val omitted = jwsSigner.signCompact(SigningHeader(algorithm), SigningPayload("alice"))
        omitted.jws.plainProtectedHeader.toProtectedHeaderJsonObject().keys shouldBe setOf("alg")
    }

    "general signing rejects invalid later headers before invoking any signer" {
        val signer = CountingSigner(newEcSigner())
        signer.publicKey.jwkId = "actual-key"
        val jwsSigner = JwsSigner(listOf(signer))
        val matching =
            SigningHeader(JwsAlgorithm.Signature.ES256, "actual-key", jsonWebKey = signer.publicKey.toJsonWebKey())
        val otherKey = newEcSigner().publicKey.toJsonWebKey(keyId = "actual-key")
        for (header in listOf(
            matching.copy(keyId = "old-key"),
            matching.copy(jsonWebKey = otherKey),
            matching.copy(jsonWebKey = JsonWebKey()),
            matching.copy(algorithm = JwsAlgorithm.Signature.PS256),
        )) {
            shouldThrow<IllegalArgumentException> {
                jwsSigner.signGeneral(
                    SigningPayload("alice"), listOf(
                        JwsHeaderWrapped(matching),
                        JwsHeaderWrapped(header, setOf("alg", "kid", "jwk")),
                    )
                )
            }
            signer.calls shouldBe 0
        }
    }

//    "unsupported signer configurations are rejected before invoking any signer" {
//        val signer = CountingSigner(newEcSigner())
//        val header = SigningHeader(JwsAlgorithm.Signature.ES256)
//        shouldThrow<IllegalArgumentException> { JwsSigner(emptyMap()) }
//        shouldThrow<IllegalArgumentException> { JwsSigner(mapOf(JwsAlgorithm.Signature.RS256 to signer)) }
//        val otherKey = Signer.Ephemeral { ec { curve = ECCurve.SECP_384_R_1 } }.publicKey
//        val wrongCurve = object : Signer by signer {
//            override val publicKey = otherKey
//        }
//        val jwsSigner = JwsSigner(mapOf(header.algorithm to wrongCurve))
//        shouldThrow<IllegalArgumentException> {
//            jwsSigner.signCompact(header, SigningPayload("alice"))
//        }
//        signer.calls shouldBe 0
//    }

    "registered signers survive later changes to the supplied map" {
        val original = newEcSigner()
        val signers = mutableListOf(original)
        val jwsSigner = JwsSigner(signers)
        signers.clear()
        val typed = jwsSigner.signCompact(SigningHeader(JwsAlgorithm.Signature.ES256), SigningPayload("alice"))
        original.makeVerifier().verify(typed.jws.signatureInput, typed.signature) shouldBe SignatureVerifier.Success
    }

    "signer cancellation propagates unchanged" {
        val delegate = newEcSigner()
        val problem = UserInitiatedCancellation("cancelled", null)
        val signer = object : Signer by delegate {
            override suspend fun sign(data: SignatureInput): SignatureResult<*> = SignatureResult.Failure(problem)
        }
        val jwsSigner = JwsSigner(listOf(signer))
        shouldThrow<UserInitiatedCancellation> {
            jwsSigner.signCompact(SigningHeader(JwsAlgorithm.Signature.ES256), SigningPayload("alice"))
        } shouldBe problem
    }
}
