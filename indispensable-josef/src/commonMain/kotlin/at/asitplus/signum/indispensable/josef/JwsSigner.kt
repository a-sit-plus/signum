package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.sign.EcdsaPublicKey
import at.asitplus.signum.indispensable.sign.Signer
import at.asitplus.signum.indispensable.sign.sign
import at.asitplus.signum.indispensable.sign.signature
import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.*
import kotlinx.serialization.serializer

/**
 * Creates signed JWS wire objects and derives their typed views from the signed bytes.
 *
 * Copies the [signers] map and selects a signer by the serialized header's required `alg`.
 * Each registration must match the signer's actual signature algorithm. An unregistered algorithm
 * fails before signing; general JWS resolves every header before invoking any signer.
 *
 * The selected signer supplies `alg` and its public key's `jwkId` when available. An embedded `jwk` is
 * updated from its actual public key only when requested by the supplied header. Application members
 * and their placement are retained. Overrides are applied after header serialization.
 *
 * General JWS selects signers and prepares all headers before invoking any signer, serializes the shared
 * payload once, and preserves signature order. Signer failures propagate to the caller.
 */
class JwsSigner(signers: Map<JwsAlgorithm, Signer>) {
    private val signers = signers.toMap()

    init {
        require(this.signers.isNotEmpty()) { "At least one signer is required" }
        this.signers.forEach { (algorithm, signer) ->
            require(algorithm == signer.signatureAlgorithm.toJwsAlgorithm().getOrThrow()) {
                "Registered JWS algorithm does not match the signer"
            }
        }
    }

    /** Signs a payload with a fully protected header and returns its compact typed view. */
    suspend fun <P, H : JwsHeaderBase> signCompact(
        protectedHeader: H,
        payload: P,
        payloadSerializer: KSerializer<P>,
        headerSerializer: KSerializer<H>,
    ): JwsCompactTyped<P, H> = signFlattened(
        protectedHeader, payload, payloadSerializer, headerSerializer,
    ).toJwsCompactTyped()

    suspend inline fun <reified P, reified H : JwsHeaderBase> signCompact(
        protectedHeader: H,
        payload: P,
    ): JwsCompactTyped<P, H> = signCompact(
        protectedHeader, payload,
        joseCompliantSerializer.serializersModule.serializer<P>(),
        joseCompliantSerializer.serializersModule.serializer<H>(),
    )

    /** Signs a payload with the requested header-member placement and returns its flattened typed view. */
    suspend fun <P, H : JwsHeaderBase> signFlattened(
        header: H,
        payload: P,
        payloadSerializer: KSerializer<P>,
        headerSerializer: KSerializer<H>,
        unprotectedHeaderMembers: Set<String> = emptySet(),
    ): JwsFlattenedTyped<P, H> {
        val serializedHeader = joseCompliantSerializer.encodeToJsonElement(headerSerializer, header).jsonObject
        return with(selectSigner(serializedHeader)) {
            signFlattened(
                prepareHeader(serializedHeader, unprotectedHeaderMembers),
                joseCompliantSerializer.encodeToString(payloadSerializer, payload).encodeToByteArray(),
            ).typed(payloadSerializer, headerSerializer)
        }
    }

    suspend inline fun <reified P, reified H : JwsHeaderBase> signFlattened(
        header: H,
        payload: P,
        unprotectedHeaderMembers: Set<String> = emptySet(),
    ): JwsFlattenedTyped<P, H> = signFlattened(
        header, payload,
        joseCompliantSerializer.serializersModule.serializer<P>(),
        joseCompliantSerializer.serializersModule.serializer<H>(),
        unprotectedHeaderMembers,
    )

    /** Signs one shared serialized payload, reusing each wrapped header's cached JSON and member placement. */
    suspend fun <P, H : JwsHeaderBase> signGeneral(
        payload: P,
        signatures: List<JwsHeaderWrapped<H>>,
        payloadSerializer: KSerializer<P>,
        headerSerializer: KSerializer<H>,
    ): JwsGeneralTyped<P, H> {
        val parameters = signatures.toList()
        require(parameters.isNotEmpty()) { "General JWS requires at least one signature" }
        val prepared = parameters.map {
            val serializedHeader = it.protectedHeaderJson.strictUnion(it.unprotectedHeader)
            val signer = selectSigner(serializedHeader)
            PreparedSignature(signer, with(signer) { prepareHeader(serializedHeader, it.unprotectedHeaderMembers) })
        }
        val payloadBytes = joseCompliantSerializer.encodeToString(payloadSerializer, payload).encodeToByteArray()
        return prepared.map { with(it.signer) { signFlattened(it.header, payloadBytes) } }
            .toJwsGeneral().typed(payloadSerializer, headerSerializer)
    }

    suspend inline fun <reified P, reified H : JwsHeaderBase> signGeneral(
        payload: P,
        signatures: List<JwsHeaderWrapped<H>>,
    ): JwsGeneralTyped<P, H> = signGeneral(
        payload, signatures,
        joseCompliantSerializer.serializersModule.serializer<P>(),
        joseCompliantSerializer.serializersModule.serializer<H>(),
    )

    context(signer: Signer)
    private suspend fun signFlattened(
        header: HeaderParts,
        payload: ByteArray,
    ): JwsFlattened {
        val signature = signer.sign(JWS.getSignatureInput(header.protectedHeader, payload)).signature
        return JwsFlattened(header.protectedHeader, header.unprotectedHeader, payload, signature.joseBytes.copyOf())
    }

    context(signer: Signer)
    private fun prepareHeader(
        serializedHeader: JsonObject,
        unprotectedHeaderMembers: Set<String>,
    ): HeaderParts {
        val algorithm = signer.signatureAlgorithm.toJwsAlgorithm().getOrThrow()
        val publicKey = signer.publicKey
        if (algorithm is JwsAlgorithm.Signature.EC) {
            require((publicKey as? EcdsaPublicKey)?.curve == algorithm.ecCurve) {
                "Signer curve does not match the JWS header algorithm"
            }
        }
        val effectiveHeader = JsonObject(serializedHeader.toMutableMap().apply {
            put("alg", joseCompliantSerializer.encodeToJsonElement(JwsAlgorithmSerializer, algorithm))
            publicKey.jwkId?.let { put("kid", JsonPrimitive(it)) }
            if (get("jwk")?.let { it != JsonNull } == true) {
                val keyId = get("kid")?.jsonPrimitive?.contentOrNull
                put(
                    "jwk",
                    joseCompliantSerializer.encodeToJsonElement(JsonWebKey.serializer(), publicKey.toJsonWebKey(keyId))
                )
            }
        })
        return HeaderParts(
            protectedHeader = JsonObject(effectiveHeader.filterKeys { it !in unprotectedHeaderMembers }).takeUnless { it.isEmpty() }
                ?.toProtectedHeaderBytes(),
            unprotectedHeader = JsonObject(effectiveHeader.filterKeys { it in unprotectedHeaderMembers }).takeUnless { it.isEmpty() },
        )
    }

    private fun selectSigner(header: JsonObject): Signer {
        val encodedAlgorithm = requireNotNull(header["alg"]?.takeUnless { it == JsonNull }) {
            "JWS header must contain an algorithm"
        }
        val algorithm = joseCompliantSerializer.decodeFromJsonElement(JwsAlgorithmSerializer, encodedAlgorithm)
        return requireNotNull(signers[algorithm]) { "No signer registered for JWS algorithm ${algorithm.identifier}" }
    }

    private class PreparedSignature(val signer: Signer, val header: HeaderParts)
    private class HeaderParts(val protectedHeader: ByteArray?, val unprotectedHeader: JsonObject?)
}
