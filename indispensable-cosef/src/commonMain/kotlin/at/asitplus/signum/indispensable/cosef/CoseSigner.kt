package at.asitplus.signum.indispensable.cosef

import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.sign.*
import kotlinx.serialization.KSerializer
import kotlinx.serialization.serializer

/** Explicit signer-level buckets for COSE_Sign. Serializes and validates each bucket once. */
class CoseSignatureParameters<ProtectedHeader : CoseHeader, UnprotectedHeader : CoseHeader>(
    protectedHeader: ProtectedHeader, unprotectedHeader: UnprotectedHeader,
    protectedHeaderSerializer: KSerializer<ProtectedHeader>, unprotectedHeaderSerializer: KSerializer<UnprotectedHeader>,
) {
    internal val protected = encodeHeader(protectedHeader, protectedHeaderSerializer, true)
    internal val unprotected = encodeHeader(unprotectedHeader, unprotectedHeaderSerializer, false)
    init { validateBuckets(protected.header, unprotected.header, protected.labels, unprotected.labels) }
    companion object {
        inline operator fun <reified ProtectedHeader : CoseHeader, reified UnprotectedHeader : CoseHeader> invoke(protectedHeader: ProtectedHeader, unprotectedHeader: UnprotectedHeader) =
            CoseSignatureParameters(protectedHeader, unprotectedHeader, coseCompliantSerializer.serializersModule.serializer<ProtectedHeader>(), coseCompliantSerializer.serializersModule.serializer<UnprotectedHeader>())
        inline operator fun <reified ProtectedHeader : CoseHeader> invoke(protectedHeader: ProtectedHeader) = invoke(protectedHeader, EmptyCoseHeader)
    }
}

/**
 * Signs using existing Signum primitives. Validates every header/key pair before signing, and serializes payloads once.
 * A supplied kid is compared to the key's coseKid when available. Application critical semantics require an explicit callback.
 * Signer exceptions and cancellation propagate without wrapping.
 */
class CoseSigner(signers: List<Signer>) {
    private val signers = signers.toList()
    constructor(signer: Signer) : this(listOf(signer))
    init { require(this.signers.isNotEmpty()) { "At least one signer is required" } }

    suspend fun <ProtectedHeader : CoseHeader, UnprotectedHeader : CoseHeader, Payload> sign1(
        protectedHeader: ProtectedHeader, unprotectedHeader: UnprotectedHeader, payload: Payload,
        payloadSerializer: KSerializer<Payload>, protectedHeaderSerializer: KSerializer<ProtectedHeader>, unprotectedHeaderSerializer: KSerializer<UnprotectedHeader>,
        externalAad: ByteArray = byteArrayOf(), detached: Boolean = false,
        processCritical: (CoseHeaderLabel) -> Boolean = { false },
    ): CoseSign1<ProtectedHeader, UnprotectedHeader, Payload> {
        val parameters = CoseSignatureParameters(protectedHeader, unprotectedHeader, protectedHeaderSerializer, unprotectedHeaderSerializer)
        val protected = parameters.protected
        val unprotected = parameters.unprotected
        processCritical(protected.header, processCritical)
        val signer = selectSigner(listOf(protected.header, unprotected.header))
        val bytes = encodePayload(payload, payloadSerializer)
        val signature = signer.sign(COSE.sign1StructureInput(protected.bytes, externalAad, bytes)).signature
        return CoseSign1(CoseSign1.Raw(protected.bytes, unprotected.header, if (detached) null else bytes, signature.coseBytes.copyOf(), unprotected.labels), protected.header, payload, if (detached) bytes else null)
    }

    suspend inline fun <reified ProtectedHeader : CoseHeader, reified UnprotectedHeader : CoseHeader, reified Payload> sign1(
        protectedHeader: ProtectedHeader, unprotectedHeader: UnprotectedHeader, payload: Payload,
        externalAad: ByteArray = byteArrayOf(), detached: Boolean = false, noinline processCritical: (CoseHeaderLabel) -> Boolean = { false },
    ) = sign1(protectedHeader, unprotectedHeader, payload, coseCompliantSerializer.serializersModule.serializer<Payload>(), coseCompliantSerializer.serializersModule.serializer<ProtectedHeader>(), coseCompliantSerializer.serializersModule.serializer<UnprotectedHeader>(), externalAad, detached, processCritical)

    suspend fun <ProtectedHeader : CoseHeader, Payload> sign1(
        protectedHeader: ProtectedHeader, payload: Payload, payloadSerializer: KSerializer<Payload>, protectedHeaderSerializer: KSerializer<ProtectedHeader>,
        externalAad: ByteArray = byteArrayOf(), detached: Boolean = false, processCritical: (CoseHeaderLabel) -> Boolean = { false },
    ) = sign1(protectedHeader, EmptyCoseHeader, payload, payloadSerializer, protectedHeaderSerializer, EmptyCoseHeader.serializer(), externalAad, detached, processCritical)

    suspend inline fun <reified ProtectedHeader : CoseHeader, reified Payload> sign1(
        protectedHeader: ProtectedHeader, payload: Payload, externalAad: ByteArray = byteArrayOf(), detached: Boolean = false, noinline processCritical: (CoseHeaderLabel) -> Boolean = { false },
    ) = sign1(protectedHeader, EmptyCoseHeader, payload, externalAad, detached, processCritical)

    suspend fun <BodyProtectedHeader : CoseHeader, BodyUnprotectedHeader : CoseHeader, SignerProtectedHeader : CoseHeader, SignerUnprotectedHeader : CoseHeader, Payload> sign(
        protectedHeader: BodyProtectedHeader, unprotectedHeader: BodyUnprotectedHeader, payload: Payload,
        signatures: List<CoseSignatureParameters<SignerProtectedHeader, SignerUnprotectedHeader>>,
        payloadSerializer: KSerializer<Payload>, bodyProtectedHeaderSerializer: KSerializer<BodyProtectedHeader>, bodyUnprotectedHeaderSerializer: KSerializer<BodyUnprotectedHeader>,
        externalAad: ByteArray = byteArrayOf(), detached: Boolean = false, processCritical: (CoseHeaderLabel) -> Boolean = { false },
    ): CoseSign<BodyProtectedHeader, BodyUnprotectedHeader, SignerProtectedHeader, SignerUnprotectedHeader, Payload> {
        val parameters = signatures.toList()
        require(parameters.isNotEmpty()) { "COSE_Sign requires at least one signature" }
        val body = CoseSignatureParameters(protectedHeader, unprotectedHeader, bodyProtectedHeaderSerializer, bodyUnprotectedHeaderSerializer)
        processCritical(body.protected.header, processCritical)
        val selected = parameters.map {
            require(((body.protected.labels + body.unprotected.labels) intersect (it.protected.labels + it.unprotected.labels)).isEmpty()) { "Body and signer parameters conflict" }
            processCritical(it.protected.header, processCritical)
            selectSigner(listOf(it.protected.header, it.unprotected.header, body.protected.header, body.unprotected.header))
        }
        val bytes = encodePayload(payload, payloadSerializer)
        val signed = parameters.zip(selected).map { (headers, signer) ->
            val signature = signer.sign(COSE.signStructureInput(body.protected.bytes, headers.protected.bytes, externalAad, bytes)).signature
            CoseSign.SignatureRaw(headers.protected.bytes, headers.unprotected.header, signature.coseBytes.copyOf(), headers.unprotected.labels)
        }
        val raw = CoseSign.Raw(body.protected.bytes, body.unprotected.header, if (detached) null else bytes, signed, body.unprotected.labels)
        return CoseSign(raw, body.protected.header, signed.zip(parameters).map { (rawSignature, headers) -> CoseSign.Signature(rawSignature, headers.protected.header) }, payload, if (detached) bytes else null)
    }

    suspend inline fun <reified BodyProtectedHeader : CoseHeader, reified BodyUnprotectedHeader : CoseHeader, SignerProtectedHeader : CoseHeader, SignerUnprotectedHeader : CoseHeader, reified Payload> sign(
        protectedHeader: BodyProtectedHeader, unprotectedHeader: BodyUnprotectedHeader, payload: Payload, signatures: List<CoseSignatureParameters<SignerProtectedHeader, SignerUnprotectedHeader>>,
        externalAad: ByteArray = byteArrayOf(), detached: Boolean = false, noinline processCritical: (CoseHeaderLabel) -> Boolean = { false },
    ) = sign(protectedHeader, unprotectedHeader, payload, signatures, coseCompliantSerializer.serializersModule.serializer<Payload>(), coseCompliantSerializer.serializersModule.serializer<BodyProtectedHeader>(), coseCompliantSerializer.serializersModule.serializer<BodyUnprotectedHeader>(), externalAad, detached, processCritical)

    private fun selectSigner(headers: List<CoseHeader>): Signer {
        val algorithm = headers.firstNotNullOfOrNull { it.algorithm } as? CoseAlgorithm.Signature
            ?: throw IllegalArgumentException("An explicit signature algorithm is required")
        val kid = headers.firstNotNullOfOrNull { it.kid }
        val candidates = signers.filter { signer ->
            matches(algorithm, signer) && (kid == null || signer.publicKey.coseKid == null || kid.contentEquals(signer.publicKey.coseKid))
        }
        require(candidates.size == 1) { "Expected one signer matching the COSE algorithm, curve, and key ID" }
        return candidates.single()
    }

    private fun matches(algorithm: CoseAlgorithm.Signature, signer: Signer): Boolean {
        val expected = algorithm.algorithm
        val actual = signer.signatureAlgorithm
        return if (expected is EcdsaAlgorithm && actual is EcdsaAlgorithm) {
            val curve = when (algorithm) {
                CoseAlgorithm.Signature.ES256, CoseAlgorithm.Signature.ESP256 -> ECCurve.SECP_256_R_1
                CoseAlgorithm.Signature.ES384, CoseAlgorithm.Signature.ESP384 -> ECCurve.SECP_384_R_1
                CoseAlgorithm.Signature.ES512, CoseAlgorithm.Signature.ESP512 -> ECCurve.SECP_521_R_1
                else -> return false
            }
            actual.digest == expected.digest && (signer.publicKey as? EcdsaPublicKey)?.curve == curve &&
                    (actual.requiredCurve == null || actual.requiredCurve == curve)
        } else expected is RsaAlgorithm && expected == actual && (signer.publicKey as? RsaPublicKey)?.let {
            it.bits.number >= expected.minimumKeySize.toUInt() * 8u
        } == true
    }
}
