package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.sign.EcdsaPublicKey
import at.asitplus.signum.indispensable.sign.RsaPublicKey
import at.asitplus.signum.indispensable.sign.Signer
import at.asitplus.signum.indispensable.sign.sign
import at.asitplus.signum.indispensable.sign.signature
import kotlinx.serialization.KSerializer
import kotlinx.serialization.serializer
import kotlinx.serialization.json.*

/**
 * Signs JWS and retains the supplied typed payload, headers, and signer-produced signatures in the returned views.
 *
 * Copies [signers]; the header's algorithm, curve, and key ID must select exactly one signer. Exact IDs take precedence.
 * Validates `alg`, a supplied `kid` against the public key's `jwkId` when available, and any embedded `jwk` against the public key.
 * Header members and placement are preserved without mutating the supplied model or filling in optional members.
 * Header serializers must preserve the supplied algorithm, key ID, public key, and critical parameters.
 * Critical parameters require explicit processing; custom header deserializers are not invoked during signing.
 *
 * Serializes the payload once. General signing validates all headers before signing and preserves signature order.
 * Missing registrations and mismatched headers fail before signing; signer failures propagate.
 */
class JwsSigner(signers: List<Signer>) {
    private val signers = signers.toList()

    init {
        require(this.signers.isNotEmpty()) { "At least one signer is required" }
        this.signers.forEach { it.signatureAlgorithm.toJwsAlgorithm().getOrThrow() }
    }

    /** Signs a payload with a fully protected header and returns its compact typed view. */
    suspend fun <H : JwsHeader, P> signCompact(
        protectedHeader: H,
        payload: P,
        payloadSerializer: KSerializer<P>,
        headerSerializer: KSerializer<H>,
        processCritical: (String) -> Boolean = { false },
    ): JwsCompact<H, P> = signFlattened(
        protectedHeader, payload, payloadSerializer, headerSerializer, processCritical = processCritical,
    ).toCompact()

    suspend inline fun <reified H : JwsHeader, reified P> signCompact(
        protectedHeader: H,
        payload: P,
        noinline processCritical: (String) -> Boolean = { false },
    ): JwsCompact<H, P> = signCompact(
        protectedHeader, payload,
        joseCompliantSerializer.serializersModule.serializer<P>(),
        joseCompliantSerializer.serializersModule.serializer<H>(),
        processCritical,
    )

    /** Signs a payload with the requested header-member placement and returns its flattened typed view. */
    suspend fun <H : JwsHeader, P> signFlattened(
        header: H,
        payload: P,
        payloadSerializer: KSerializer<P>,
        headerSerializer: KSerializer<H>,
        unprotectedHeaderMembers: Set<String> = emptySet(),
        processCritical: (String) -> Boolean = { false },
    ): JwsFlattened<H, P> {
        val wrappedHeader = JwsHeaderWrapped(header, headerSerializer, unprotectedHeaderMembers)
        return with(selectSigner(wrappedHeader, processCritical)) {
            signFlattened(
                wrappedHeader,
                payload,
                joseCompliantSerializer.encodeToString(payloadSerializer, payload).encodeToByteArray(),
            )
        }
    }

    suspend inline fun <reified H : JwsHeader, reified P> signFlattened(
        header: H,
        payload: P,
        unprotectedHeaderMembers: Set<String> = emptySet(),
        noinline processCritical: (String) -> Boolean = { false },
    ): JwsFlattened<H, P> = signFlattened(
        header, payload,
        joseCompliantSerializer.serializersModule.serializer<P>(),
        joseCompliantSerializer.serializersModule.serializer<H>(),
        unprotectedHeaderMembers,
        processCritical,
    )

    /** Signs one shared serialized payload, reusing each wrapped header's cached JSON and member placement. */
    suspend fun <H : JwsHeader, P> signGeneral(
        payload: P,
        signatures: List<JwsHeaderWrapped<H>>,
        payloadSerializer: KSerializer<P>,
        processCritical: (String) -> Boolean = { false },
    ): JwsGeneral<H, P> {
        val parameters = signatures.toList()
        require(parameters.isNotEmpty()) { "General JWS requires at least one signature" }
        val selectedSigners = parameters.map { selectSigner(it, processCritical) }
        val payloadBytes = joseCompliantSerializer.encodeToString(payloadSerializer, payload).encodeToByteArray()
        val signed = parameters.zip(selectedSigners) { header, signer ->
            with(signer) { signFlattened(header, payload, payloadBytes) }
        }
        return JwsGeneral(
            jws = signed.map { it.raw }.toGeneral(),
            payload = payload,
            signatureViews = signed.map { it.wrappedHeader to it.signature },
        )
    }

    suspend inline fun <H : JwsHeader, reified P> signGeneral(
        payload: P,
        signatures: List<JwsHeaderWrapped<H>>,
        noinline processCritical: (String) -> Boolean = { false },
    ): JwsGeneral<H, P> = signGeneral(
        payload, signatures,
        joseCompliantSerializer.serializersModule.serializer<P>(),
        processCritical,
    )

    context(signer: Signer)
    private suspend fun <H : JwsHeader, P> signFlattened(
        header: JwsHeaderWrapped<H>,
        payload: P,
        payloadBytes: ByteArray,
    ): JwsFlattened<H, P> {
        val protectedHeader = header.protectedHeader.takeUnless { header.protectedHeaderJson.isEmpty() }
        val unprotectedHeader = header.unprotectedHeader.takeUnless { it.isEmpty() }
        val signature = signer.sign(JwsRaw.getSignatureInput(protectedHeader, payloadBytes)).signature
        return JwsFlattened(
            raw = JwsFlattened.Raw(protectedHeader, unprotectedHeader, payloadBytes, signature.joseBytes.copyOf()),
            payload = payload,
            wrappedHeader = header,
            signature = signature,
        )
    }

    private fun selectSigner(wrapped: JwsHeaderWrapped<*>, processCritical: (String) -> Boolean): Signer {
        val header = wrapped.header
        val wire = wrapped.protectedHeaderJson.strictUnion(wrapped.unprotectedHeader)
        require(wire["alg"] == JsonPrimitive(header.algorithm.identifier)) { "Header serializer changed the algorithm" }
        require(wire["kid"].takeUnless { it == JsonNull } == header.keyId?.let(::JsonPrimitive)) { "Header serializer changed the key ID" }
        val wireKey = wire["jwk"].takeUnless { it == JsonNull }?.let {
            joseCompliantSerializer.decodeFromJsonElement(JsonWebKey.serializer(), it)
        }
        require(wireKey == header.jsonWebKey) { "Header serializer changed the JWK" }
        val critical = validateJwsCriticalHeaders(wrapped.protectedHeaderJson, wrapped.unprotectedHeader)
        require(critical == header.crit) { "Header serializer changed critical parameters" }
        critical?.forEach { require(processCritical(it)) { "Unprocessed critical parameter $it" } }

        val algorithm = header.algorithm
        val compatible = signers.filter { signer ->
            algorithm == signer.signatureAlgorithm.toJwsAlgorithm().getOrThrow() &&
                    when (algorithm) {
                        is JwsAlgorithm.Signature.EC -> (signer.publicKey as? EcdsaPublicKey)?.curve == algorithm.ecCurve
                        is JwsAlgorithm.Signature.RSA -> (signer.publicKey as? RsaPublicKey)?.let {
                            it.bits.number >= algorithm.algorithm.minimumKeySize.toUInt() * 8u
                        } == true
                        else -> false
                    }
        }
        val exact = if (header.keyId == null) emptyList() else compatible.filter { it.publicKey.jwkId == header.keyId }
        val candidates = when {
            exact.isNotEmpty() -> exact
            compatible.size == 1 && (header.keyId == null || compatible.single().publicKey.jwkId == null) -> compatible
            header.keyId == null -> compatible
            else -> emptyList()
        }
        require(candidates.size == 1) { "Expected one signer matching the JWS algorithm, curve, and key ID" }
        val signer = candidates.single()
        wireKey?.let { key ->
            require(key.toCryptoPublicKey() == signer.publicKey) {
                "Signer public key does not match the JWS header JWK"
            }
        }
        return signer
    }
}
