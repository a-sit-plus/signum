package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.dsl.ec
import at.asitplus.signum.dsl.rsa
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.sign.EcdsaAlgorithm
import at.asitplus.signum.indispensable.sign.RsaAlgorithm
import at.asitplus.signum.indispensable.sign.SignatureInput
import at.asitplus.signum.indispensable.sign.SignatureResult
import at.asitplus.signum.indispensable.sign.SignatureVerifier
import at.asitplus.signum.indispensable.sign.Signer
import at.asitplus.signum.indispensable.sign.UserInitiatedCancellation
import at.asitplus.signum.indispensable.sign.makeVerifier
import at.asitplus.signum.indispensable.sign.verify
import at.asitplus.signum.supreme.Supreme
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.Transient
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.JsonTransformingSerializer
import kotlinx.serialization.json.jsonObject

@Serializable
internal data class SigningHeader(
    @SerialName("alg") override val algorithm: JwsAlgorithm,
    @SerialName("kid") override val keyId: String? = null,
    val extension: String? = null,
    @SerialName("jwk") override val jsonWebKey: JsonWebKey? = null,
) : JwsHeaderBase {
    @Transient override val type: String? = null
    @Transient override val contentType: String? = null
    @Transient override val certificateChain: CertificateChain? = null
    @Transient override val jsonWebKeySetUrl: String? = null
    @Transient override val certificateUrl: String? = null
    @Transient override val certificateSha1Thumbprint: ByteArray? = null
    @Transient override val certificateSha256Thumbprint: ByteArray? = null
    @Transient override val crit: List<String>? = null
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

    "compact signing supports typed payloads with EC and RSA keys" {
        for (signer in listOf(newEcSigner(), newRsaSigner())) {
            val header = SigningHeader(signer.signatureAlgorithm.toJwsAlgorithm().getOrThrow(), "key")
            val jwsSigner = JwsSigner(mapOf(header.algorithm to signer))
            val typed = jwsSigner.signCompact(header, SigningPayload("alice"))
            typed.payload shouldBe SigningPayload("alice")
            typed.header shouldBe header
            typed.unprotectedHeaderMembers shouldBe emptySet()
            typed.jws.typed<SigningPayload, SigningHeader>() shouldBe typed
            signer.makeVerifier().verify(typed.jws.signatureInput, typed.signature) shouldBe SignatureVerifier.Success
            val explicit = jwsSigner.signCompact(
                header, SigningPayload("alice"), SigningPayload.serializer(), SigningHeader.serializer(),
            )
            explicit.payload shouldBe typed.payload
            explicit.header shouldBe header
            signer.makeVerifier().verify(explicit.jws.signatureInput, explicit.signature) shouldBe SignatureVerifier.Success
        }
    }

    "flattened signing preserves protected, split and wholly unprotected headers" {
        val signer = newEcSigner()
        val header = SigningHeader(JwsAlgorithm.Signature.ES256, "key", "custom")
        val jwsSigner = JwsSigner(mapOf(header.algorithm to signer))
        for (placement in listOf(emptySet(), setOf("kid"), setOf("alg", "kid", "extension"))) {
            val typed = jwsSigner.signFlattened(header, SigningPayload("alice"), placement)
            typed.header shouldBe header
            typed.unprotectedHeaderMembers shouldBe placement
            typed.jws.unprotectedHeader?.keys.orEmpty() shouldBe placement
            val wireJson = joseCompliantSerializer.encodeToJsonElement(JwsFlattened.Raw.serializer(), typed.jws).jsonObject
            (JwsRaw.SerialNames.HEADER in wireJson) shouldBe placement.isNotEmpty()
            if ("alg" in placement) typed.jws.plainProtectedHeader shouldBe null
            signer.makeVerifier().verify(typed.jws.signatureInput, typed.signature) shouldBe SignatureVerifier.Success
            joseCompliantSerializer.decodeFromString<JwsFlattened.Raw>(
                joseCompliantSerializer.encodeToString(typed.jws)
            ).typed<SigningPayload, SigningHeader>() shouldBe typed
        }
    }

    "general signing serializes one shared payload and preserves signature order" {
        val signers = listOf(newEcSigner(), newRsaSigner())
        val jwsSigner = JwsSigner(signers.associateBy { it.signatureAlgorithm.toJwsAlgorithm().getOrThrow() })
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
        val typed = jwsSigner.signGeneral(SigningPayload("alice"), parameters, serializer, SigningHeader.serializer())
        encodings shouldBe 1
        typed.headers.map { it.keyId } shouldBe listOf("key-0", "key-1")
        typed.unprotectedHeaderMembers shouldBe listOf(setOf("kid"), emptySet())
        typed.payload shouldBe SigningPayload("alice")
        typed.toFlattened().forEachIndexed { index, flattened ->
            flattened.jws.plainPayload shouldBe typed.jws.plainPayload
            signers[index].makeVerifier().verify(flattened.jws.signatureInput, flattened.signature) shouldBe
                    SignatureVerifier.Success
        }
        val reified = jwsSigner.signGeneral(SigningPayload("alice"), parameters)
        reified.headers shouldBe typed.headers
        reified.payload shouldBe typed.payload
    }

    "general signing reuses cached headers and decodes with the supplied serializer" {
        val signers = listOf(newEcSigner(), newRsaSigner())
        val jwsSigner = JwsSigner(signers.associateBy { it.signatureAlgorithm.toJwsAlgorithm().getOrThrow() })
        val encodings = IntArray(signers.size)
        val headers = signers.mapIndexed { index, signer ->
            val serializer = object : KSerializer<SigningHeader> by SigningHeader.serializer() {
                override fun serialize(encoder: Encoder, value: SigningHeader) {
                    encodings[index]++
                    SigningHeader.serializer().serialize(encoder, value.copy(extension = "wire-$index"))
                }
            }
            JwsHeaderWrapped(
                SigningHeader(signer.signatureAlgorithm.toJwsAlgorithm().getOrThrow(), "key-$index"),
                serializer,
                if (index == 0) setOf("kid") else emptySet(),
            )
        }
        encodings.toList() shouldBe listOf(1, 1)
        var decodings = 0
        val viewSerializer = object : KSerializer<SigningHeader> by SigningHeader.serializer() {
            override fun deserialize(decoder: Decoder): SigningHeader {
                decodings++
                return SigningHeader.serializer().deserialize(decoder).let {
                    it.copy(keyId = "${it.keyId}-view")
                }
            }
        }

        val typed = jwsSigner.signGeneral(SigningPayload("alice"), headers, SigningPayload.serializer(), viewSerializer)

        encodings.toList() shouldBe listOf(1, 1)
        decodings shouldBe 2
        typed.headers.map { it.keyId } shouldBe listOf("key-0-view", "key-1-view")
        typed.headers.map { it.extension } shouldBe listOf("wire-0", "wire-1")
        typed.unprotectedHeaderMembers shouldBe listOf(setOf("kid"), emptySet())
        typed.toFlattened().forEachIndexed { index, flattened ->
            signers[index].makeVerifier().verify(flattened.jws.signatureInput, flattened.signature) shouldBe
                    SignatureVerifier.Success
            JwsHeaderWrapped.fromParts<SigningHeader>(
                flattened.jws.plainProtectedHeader, flattened.jws.unprotectedHeader,
            ).header.keyId shouldBe "key-$index"
        }
    }

    "signing derives normalized views from the bytes they sign" {
        val signer = newEcSigner()
        val jwsSigner = JwsSigner(mapOf(JwsAlgorithm.Signature.ES256 to signer))
        val payloadSerializer = object : KSerializer<SigningPayload> by SigningPayload.serializer() {
            override fun deserialize(decoder: Decoder) =
                SigningPayload.serializer().deserialize(decoder).let { it.copy(sub = it.sub.lowercase()) }
        }
        val headerSerializer = object : KSerializer<SigningHeader> by SigningHeader.serializer() {
            override fun serialize(encoder: Encoder, value: SigningHeader) =
                SigningHeader.serializer().serialize(encoder, value.copy(keyId = value.keyId?.uppercase()))

            override fun deserialize(decoder: Decoder) =
                SigningHeader.serializer().deserialize(decoder).let { it.copy(keyId = it.keyId?.lowercase()) }
        }
        val header = SigningHeader(JwsAlgorithm.Signature.ES256, "key")
        val payload = SigningPayload("ALICE")
        val compact = jwsSigner.signCompact(header, payload, payloadSerializer, headerSerializer)
        val flattened = jwsSigner.signFlattened(header, payload, payloadSerializer, headerSerializer, setOf("kid"))
        val general = jwsSigner.signGeneral(
            payload, listOf(JwsHeaderWrapped(header, headerSerializer, emptySet())), payloadSerializer, headerSerializer,
        )
        (listOf(compact.toFlattened(), flattened) + general.toFlattened()).forEach { typed ->
            typed.payload.sub shouldBe "alice"
            typed.header.keyId shouldBe "key"
            typed.jws.getPayload(SigningPayload.serializer()).getOrThrow().sub shouldBe "ALICE"
            JwsHeaderWrapped.fromParts<SigningHeader>(
                typed.jws.plainProtectedHeader, typed.jws.unprotectedHeader,
            ).header.keyId shouldBe "KEY"
            signer.makeVerifier().verify(typed.jws.signatureInput, typed.signature) shouldBe SignatureVerifier.Success
        }
    }

    "serialized algorithms select their registered signers independently for every JWS form" {
        val ec = CountingSigner(newEcSigner())
        val rsa = CountingSigner(newRsaSigner())
        val jwsSigner = JwsSigner(mapOf(
            JwsAlgorithm.Signature.PS256 to rsa,
            JwsAlgorithm.Signature.ES256 to ec,
        ))
        val header = SigningHeader(JwsAlgorithm.Signature.ES256, "key")
        val compact = jwsSigner.signCompact(header, SigningPayload("alice"))
        val changedAlgorithm = object : JsonTransformingSerializer<SigningHeader>(SigningHeader.serializer()) {
            override fun transformSerialize(element: JsonElement): JsonElement =
                JsonObject(element.jsonObject + ("alg" to JsonPrimitive("PS256")))
        }
        val transformed = jwsSigner.signCompact(
            header, SigningPayload("alice"), SigningPayload.serializer(), changedAlgorithm,
        )
        val flattened = jwsSigner.signFlattened(
            header.copy(algorithm = JwsAlgorithm.Signature.PS256), SigningPayload("alice"), setOf("alg"),
        )
        val general = jwsSigner.signGeneral(SigningPayload("alice"), listOf(
            JwsHeaderWrapped(header.copy(algorithm = JwsAlgorithm.Signature.PS256), setOf("alg")),
            JwsHeaderWrapped(header),
            JwsHeaderWrapped(header.copy(algorithm = JwsAlgorithm.Signature.PS256)),
        ))
        val views = listOf(compact.toFlattened(), transformed.toFlattened(), flattened) +
                general.toFlattened()
        val expectedSigners = listOf(ec, rsa, rsa, rsa, ec, rsa)
        views.zip(expectedSigners).forEach { (typed, signer) ->
            val algorithm = signer.signatureAlgorithm.toJwsAlgorithm().getOrThrow()
            typed.header.algorithm shouldBe algorithm
            JwsHeaderWrapped.fromParts<SigningHeader>(
                typed.jws.plainProtectedHeader, typed.jws.unprotectedHeader,
            ).header.algorithm shouldBe algorithm
            signer.makeVerifier().verify(typed.jws.signatureInput, typed.signature) shouldBe SignatureVerifier.Success
        }
        flattened.unprotectedHeaderMembers shouldBe setOf("alg")
        general.unprotectedHeaderMembers shouldBe listOf(setOf("alg"), emptySet(), emptySet())
        ec.calls shouldBe 2
        rsa.calls shouldBe 4
    }

    "signer key metadata overrides stale header values without changing custom members or placement" {
        val oldKey = newEcSigner().publicKey.toJsonWebKey()
        for (signer in listOf(newEcSigner(), newRsaSigner())) {
            signer.publicKey.jwkId = "actual-key"
            val algorithm = signer.signatureAlgorithm.toJwsAlgorithm().getOrThrow()
            val jwsSigner = JwsSigner(mapOf(algorithm to signer))
            val header = SigningHeader(algorithm, "old-key", "custom", oldKey)
            val expectedHeader = header.copy(
                algorithm = signer.signatureAlgorithm.toJwsAlgorithm().getOrThrow(),
                keyId = "actual-key",
                jsonWebKey = signer.publicKey.toJsonWebKey(),
            )
            val placement = setOf("alg", "kid", "jwk")
            val compact = jwsSigner.signCompact(header, SigningPayload("alice"))
            val flattened = jwsSigner.signFlattened(header, SigningPayload("alice"), placement)
            val general = jwsSigner.signGeneral(SigningPayload("alice"), listOf(
                JwsHeaderWrapped(header, placement),
            ))
            (listOf(compact.toFlattened(), flattened) + general.toFlattened()).forEach { typed ->
                typed.header shouldBe expectedHeader
                signer.makeVerifier().verify(typed.jws.signatureInput, typed.signature) shouldBe SignatureVerifier.Success
            }
            flattened.unprotectedHeaderMembers shouldBe placement
            general.unprotectedHeaderMembers shouldBe listOf(placement)
            header.keyId shouldBe "old-key"
            header.jsonWebKey shouldBe oldKey

            val withoutEmbeddedKey = jwsSigner.signCompact(header.copy(jsonWebKey = null), SigningPayload("alice"))
            withoutEmbeddedKey.header.keyId shouldBe "actual-key"
            withoutEmbeddedKey.header.jsonWebKey shouldBe null
        }
    }

    "unsupported signer configurations are rejected before invoking any signer" {
        val signer = CountingSigner(newEcSigner())
        val header = SigningHeader(JwsAlgorithm.Signature.ES256)
        shouldThrow<IllegalArgumentException> { JwsSigner(emptyMap()) }
        shouldThrow<IllegalArgumentException> { JwsSigner(mapOf(JwsAlgorithm.Signature.RS256 to signer)) }
        val unsupported = object : Signer by signer {
            override val signatureAlgorithm = EcdsaAlgorithm(Digest.SHA1)
        }
        shouldThrow<IllegalArgumentException> { JwsSigner(mapOf(header.algorithm to unsupported)) }
        val otherKey = Signer.Ephemeral { ec { curve = ECCurve.SECP_384_R_1 } }.publicKey
        val wrongCurve = object : Signer by signer {
            override val publicKey = otherKey
        }
        val jwsSigner = JwsSigner(mapOf(header.algorithm to wrongCurve))
        shouldThrow<IllegalArgumentException> {
            jwsSigner.signCompact(header, SigningPayload("alice"))
        }
        shouldThrow<IllegalArgumentException> {
            jwsSigner.signGeneral(SigningPayload("alice"), listOf(JwsHeaderWrapped(header)))
        }
        shouldThrow<IllegalArgumentException> {
            jwsSigner.signGeneral(SigningPayload("alice"), emptyList<JwsHeaderWrapped<SigningHeader>>())
        }
        signer.calls shouldBe 0
    }

    "unregistered algorithms throw before invoking any signer" {
        val signer = CountingSigner(newEcSigner())
        val jwsSigner = JwsSigner(mapOf(JwsAlgorithm.Signature.ES256 to signer))
        val registered = SigningHeader(JwsAlgorithm.Signature.ES256)
        val unregistered = SigningHeader(JwsAlgorithm.Signature.PS256)
        shouldThrow<IllegalArgumentException> {
            jwsSigner.signCompact(unregistered, SigningPayload("alice"))
        }
        shouldThrow<IllegalArgumentException> {
            jwsSigner.signFlattened(unregistered, SigningPayload("alice"))
        }
        shouldThrow<IllegalArgumentException> {
            jwsSigner.signGeneral(SigningPayload("alice"), listOf(
                JwsHeaderWrapped(registered),
                JwsHeaderWrapped(unregistered),
            ))
        }
        signer.calls shouldBe 0
    }

    "missing serialized algorithms are rejected and header parsing still requires an algorithm" {
        val signer = CountingSigner(newEcSigner())
        val jwsSigner = JwsSigner(mapOf(JwsAlgorithm.Signature.ES256 to signer))
        for (includeNull in listOf(false, true)) {
            val serializer = object : JsonTransformingSerializer<SigningHeader>(SigningHeader.serializer()) {
                override fun transformSerialize(element: JsonElement): JsonElement =
                    JsonObject(element.jsonObject - "alg" + if (includeNull) mapOf("alg" to JsonNull) else emptyMap())
            }
            shouldThrow<IllegalArgumentException> {
                jwsSigner.signCompact(
                    SigningHeader(JwsAlgorithm.Signature.ES256), SigningPayload("alice"),
                    SigningPayload.serializer(), serializer,
                )
            }
        }
        shouldThrow<SerializationException> {
            joseCompliantSerializer.decodeFromString<SigningHeader>("""{"kid":"key"}""")
        }
        shouldThrow<SerializationException> {
            joseCompliantSerializer.decodeFromString<SigningHeader>("""{"alg":null}""")
        }
        signer.calls shouldBe 0
    }

    "later mutations to the supplied map cannot replace or remove registered signers" {
        val original = CountingSigner(newEcSigner())
        val replacement = CountingSigner(newEcSigner())
        val signers = mutableMapOf<JwsAlgorithm, Signer>(JwsAlgorithm.Signature.ES256 to original)
        val jwsSigner = JwsSigner(signers)
        signers[JwsAlgorithm.Signature.ES256] = replacement
        signers.clear()
        val typed = jwsSigner.signCompact(SigningHeader(JwsAlgorithm.Signature.ES256), SigningPayload("alice"))
        original.makeVerifier().verify(typed.jws.signatureInput, typed.signature) shouldBe SignatureVerifier.Success
        original.calls shouldBe 1
        replacement.calls shouldBe 0
    }

    "signing snapshots mutable payloads and signature parameters" {
        val delegate = newEcSigner()
        val claims = mutableMapOf("sub" to JsonPrimitive("alice"))
        val payload = JsonObject(claims)
        val parameters = mutableListOf<JwsHeaderWrapped<SigningHeader>>()
        val signer = object : Signer by delegate {
            override suspend fun sign(data: SignatureInput): SignatureResult<*> {
                claims["sub"] = JsonPrimitive("changed")
                parameters.clear()
                return delegate.sign(data)
            }
        }
        val jwsSigner = JwsSigner(mapOf(JwsAlgorithm.Signature.ES256 to signer))
        parameters += JwsHeaderWrapped(SigningHeader(JwsAlgorithm.Signature.ES256))
        parameters += JwsHeaderWrapped(SigningHeader(JwsAlgorithm.Signature.ES256))
        val typed = jwsSigner.signGeneral(payload, parameters)
        typed.payload["sub"] shouldBe JsonPrimitive("alice")
        val wire = typed.jws
        wire.getPayload<JsonObject>().getOrThrow() shouldBe typed.payload
        wire.signatureElements.size shouldBe 2
        wire.signatureElements.forEachIndexed { index, signature ->
            delegate.makeVerifier().verify(
                wire.signatureInputs[index], JwsRaw.getSignature(JwsAlgorithm.Signature.ES256, signature.plainSignature),
            ) shouldBe SignatureVerifier.Success
        }
    }

    "signer failures propagate through signing" {
        val delegate = newEcSigner()
        val problem = UserInitiatedCancellation("cancelled", null)
        val signer = object : Signer by delegate {
            override suspend fun sign(data: SignatureInput): SignatureResult<*> = SignatureResult.Failure(problem)
        }
        val jwsSigner = JwsSigner(mapOf(JwsAlgorithm.Signature.ES256 to signer))
        shouldThrow<UserInitiatedCancellation> {
            jwsSigner.signCompact(SigningHeader(JwsAlgorithm.Signature.ES256), SigningPayload("alice"))
        } shouldBe problem
        shouldThrow<UserInitiatedCancellation> {
            jwsSigner.signFlattened(SigningHeader(JwsAlgorithm.Signature.ES256), SigningPayload("alice"))
        } shouldBe problem
        shouldThrow<UserInitiatedCancellation> {
            jwsSigner.signGeneral(SigningPayload("alice"), listOf(
                JwsHeaderWrapped(SigningHeader(JwsAlgorithm.Signature.ES256)),
            ))
        } shouldBe problem
    }
}
