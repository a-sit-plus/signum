package at.asitplus.signum.indispensable.cosef

import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.mac.mac
import kotlinx.serialization.KSerializer
import kotlinx.serialization.serializer

/** Creates COSE_Mac0 using the selected MAC primitive and explicit buckets. Owns a copy of the key and optional kid. */
class CoseMacCreator(val algorithm: CoseAlgorithm.MAC, key: ByteArray, kid: ByteArray? = null) {
    private val key = key.copyOf()
    private val kid = kid?.copyOf()
    init {
        val minimumBytes = when (algorithm) {
            CoseAlgorithm.MAC.HS256, CoseAlgorithm.MAC.HS256_64 -> 32
            CoseAlgorithm.MAC.HS384 -> 48
            CoseAlgorithm.MAC.HS512 -> 64
            CoseAlgorithm.MAC.UNOFFICIAL_HS1 -> 20
        }
        require(this.key.size >= minimumBytes) { "MAC key must contain at least $minimumBytes bytes" }
    }

    suspend fun <ProtectedHeader : CoseHeader, UnprotectedHeader : CoseHeader, Payload> mac0(
        protectedHeader: ProtectedHeader, unprotectedHeader: UnprotectedHeader, payload: Payload,
        payloadSerializer: KSerializer<Payload>, protectedHeaderSerializer: KSerializer<ProtectedHeader>, unprotectedHeaderSerializer: KSerializer<UnprotectedHeader>,
        externalAad: ByteArray = byteArrayOf(), detached: Boolean = false, processCritical: (CoseHeaderLabel) -> Boolean = { false },
    ): CoseMac0<ProtectedHeader, UnprotectedHeader, Payload> {
        val headers = CoseSignatureParameters(protectedHeader, unprotectedHeader, protectedHeaderSerializer, unprotectedHeaderSerializer)
        require((headers.protected.header.algorithm ?: headers.unprotected.header.algorithm) == algorithm) { "MAC algorithm does not match the headers" }
        val headerKid = headers.protected.header.kid ?: headers.unprotected.header.kid
        require(kid == null || headerKid == null || kid.contentEquals(headerKid)) { "MAC key ID does not match the headers" }
        processCritical(headers.protected.header, processCritical)
        val bytes = encodePayload(payload, payloadSerializer)
        val tag = algorithm.mac(key, COSE.mac0StructureInput(headers.protected.bytes, externalAad, bytes))
        return CoseMac0(CoseMac0.Raw(headers.protected.bytes, headers.unprotected.header, if (detached) null else bytes, tag.copyOf(), headers.unprotected.labels), headers.protected.header, payload, if (detached) bytes else null)
    }

    suspend inline fun <reified ProtectedHeader : CoseHeader, reified UnprotectedHeader : CoseHeader, reified Payload> mac0(
        protectedHeader: ProtectedHeader, unprotectedHeader: UnprotectedHeader, payload: Payload,
        externalAad: ByteArray = byteArrayOf(), detached: Boolean = false, noinline processCritical: (CoseHeaderLabel) -> Boolean = { false },
    ) = mac0(protectedHeader, unprotectedHeader, payload, coseCompliantSerializer.serializersModule.serializer<Payload>(), coseCompliantSerializer.serializersModule.serializer<ProtectedHeader>(), coseCompliantSerializer.serializersModule.serializer<UnprotectedHeader>(), externalAad, detached, processCritical)

    suspend fun <ProtectedHeader : CoseHeader, Payload> mac0(
        protectedHeader: ProtectedHeader, payload: Payload, payloadSerializer: KSerializer<Payload>, protectedHeaderSerializer: KSerializer<ProtectedHeader>,
        externalAad: ByteArray = byteArrayOf(), detached: Boolean = false, processCritical: (CoseHeaderLabel) -> Boolean = { false },
    ) = mac0(protectedHeader, EmptyCoseHeader, payload, payloadSerializer, protectedHeaderSerializer, EmptyCoseHeader.serializer(), externalAad, detached, processCritical)

    suspend inline fun <reified ProtectedHeader : CoseHeader, reified Payload> mac0(
        protectedHeader: ProtectedHeader, payload: Payload, externalAad: ByteArray = byteArrayOf(), detached: Boolean = false, noinline processCritical: (CoseHeaderLabel) -> Boolean = { false },
    ) = mac0(protectedHeader, EmptyCoseHeader, payload, externalAad, detached, processCritical)
}
