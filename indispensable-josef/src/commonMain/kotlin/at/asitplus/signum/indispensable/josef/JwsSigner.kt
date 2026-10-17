package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.sign.EcdsaPublicKey
import at.asitplus.signum.indispensable.sign.Signer
import at.asitplus.signum.indispensable.sign.sign
import at.asitplus.signum.indispensable.sign.signature
import kotlinx.serialization.KSerializer
import kotlinx.serialization.serializer

/**
 * Signs JWS and retains the supplied typed payload, headers, and signer-produced signatures in the returned views.
 *
 * Copies [signers]; each registration must match its signer's algorithm. The supplied header's algorithm selects a signer.
 * Validates `alg`, a supplied `kid` against the public key's `jwkId` when available, and any embedded `jwk` against the public key.
 * Header members and placement are preserved without mutating the supplied model or filling in optional members.
 * Header serializers must preserve the supplied algorithm, key ID, and public key.
 *
 * Serializes the payload once. General signing validates all headers before signing and preserves signature order.
 * Missing registrations and mismatched headers fail before signing; signer failures propagate.
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
        val wrappedHeader = JwsHeaderWrapped(header, headerSerializer, unprotectedHeaderMembers)
        return with(selectSigner(header)) {
            signFlattened(
                wrappedHeader,
                payload,
                joseCompliantSerializer.encodeToString(payloadSerializer, payload).encodeToByteArray(),
            )
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
    ): JwsGeneralTyped<P, H> {
        val parameters = signatures.toList()
        require(parameters.isNotEmpty()) { "General JWS requires at least one signature" }
        val selectedSigners = parameters.map { selectSigner(it.header) }
        val payloadBytes = joseCompliantSerializer.encodeToString(payloadSerializer, payload).encodeToByteArray()
        val signed = parameters.zip(selectedSigners) { header, signer ->
            with(signer) { signFlattened(header, payload, payloadBytes) }
        }
        return JwsGeneralTyped(
            jws = signed.map { it.jws }.toJwsGeneral(),
            payload = payload,
            signatureViews = signed.map { it.wrappedHeader to it.signature },
        )
    }

    suspend inline fun <reified P, H : JwsHeaderBase> signGeneral(
        payload: P,
        signatures: List<JwsHeaderWrapped<H>>,
    ): JwsGeneralTyped<P, H> = signGeneral(
        payload, signatures,
        joseCompliantSerializer.serializersModule.serializer<P>(),
    )

    context(signer: Signer)
    private suspend fun <P, H : JwsHeaderBase> signFlattened(
        header: JwsHeaderWrapped<H>,
        payload: P,
        payloadBytes: ByteArray,
    ): JwsFlattenedTyped<P, H> {
        val protectedHeader = header.protectedHeader.takeUnless { header.protectedHeaderJson.isEmpty() }
        val unprotectedHeader = header.unprotectedHeader.takeUnless { it.isEmpty() }
        val signature = signer.sign(JWS.getSignatureInput(protectedHeader, payloadBytes)).signature
        return JwsFlattenedTyped(
            jws = JwsFlattened(protectedHeader, unprotectedHeader, payloadBytes, signature.joseBytes.copyOf()),
            payload = payload,
            wrappedHeader = header,
            signature = signature,
        )
    }

    private fun selectSigner(header: JwsHeaderBase): Signer {
        val algorithm = header.algorithm
        val signer = requireNotNull(signers[algorithm]) { "No signer registered for JWS algorithm ${algorithm.identifier}" }
        require(algorithm == signer.signatureAlgorithm.toJwsAlgorithm().getOrThrow()) {
            "Signer algorithm does not match the JWS header algorithm"
        }
        val publicKey = signer.publicKey
        if (algorithm is JwsAlgorithm.Signature.EC) {
            require((publicKey as? EcdsaPublicKey)?.curve == algorithm.ecCurve) {
                "Signer curve does not match the JWS header algorithm"
            }
        }
        header.keyId?.let { keyId ->
            require(publicKey.jwkId == null || keyId == publicKey.jwkId) {
                "Signer key ID does not match the JWS header key ID"
            }
        }
        header.jsonWebKey?.let { key ->
            require(key.toCryptoPublicKey().getOrThrow() == publicKey) {
                "Signer public key does not match the JWS header JWK"
            }
        }
        return signer
    }
}
