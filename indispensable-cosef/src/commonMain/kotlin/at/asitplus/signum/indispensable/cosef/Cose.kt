@file:OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)

package at.asitplus.signum.indispensable.cosef

import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapperSerializer
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.sign.EcdsaAlgorithm
import at.asitplus.signum.indispensable.sign.EcdsaSignature
import at.asitplus.signum.indispensable.sign.RsaAlgorithm
import at.asitplus.signum.indispensable.sign.RsaSignature
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.Cbor
import kotlinx.serialization.cbor.CborArray
import kotlinx.serialization.encodeToByteArray

/** Authentication structures use received protected and payload bytes, never re-encoded typed views. */
object COSE {
    fun sign1StructureInput(plainProtectedHeader: ByteArray, externalAad: ByteArray = byteArrayOf(), payload: ByteArray) =
        coseCompliantSerializer.encodeToByteArray(CoseStructure("Signature1", plainProtectedHeader, externalAad, payload))

    fun mac0StructureInput(plainProtectedHeader: ByteArray, externalAad: ByteArray = byteArrayOf(), payload: ByteArray) =
        coseCompliantSerializer.encodeToByteArray(CoseStructure("MAC0", plainProtectedHeader, externalAad, payload))

    fun signStructureInput(bodyProtected: ByteArray, signerProtected: ByteArray, externalAad: ByteArray = byteArrayOf(), payload: ByteArray) =
        coseCompliantSerializer.encodeToByteArray(CoseSignStructure("Signature", bodyProtected, signerProtected, externalAad, payload))

    fun getSignature(plainSignature: ByteArray, header: CoseHeader, fallbackHeader: CoseHeader? = null): CryptoSignature {
        val algorithm = (header.algorithm ?: fallbackHeader?.algorithm) as? CoseAlgorithm.Signature
            ?: throw IllegalArgumentException("An explicit signature algorithm is required")
        return when (algorithm.algorithm) {
            is EcdsaAlgorithm -> EcdsaSignature.fromP1363Bytes(plainSignature)
            is RsaAlgorithm -> RsaSignature(plainSignature)
            else -> throw IllegalArgumentException("Unsupported COSE signature algorithm")
        }
    }
}

@Serializable
@CborArray
internal data class CoseStructure(
    val context: String,
    @ByteString val plainProtectedHeader: ByteArray,
    @ByteString val externalAad: ByteArray,
    @ByteString val payload: ByteArray,
)

@Serializable
@CborArray
private data class CoseSignStructure(
    val context: String,
    @ByteString val bodyProtected: ByteArray,
    @ByteString val signerProtected: ByteArray,
    @ByteString val externalAad: ByteArray,
    @ByteString val payload: ByteArray,
)

internal fun authenticationPayload(attached: ByteArray?, detached: ByteArray?): ByteArray =
    if (attached != null) {
        require(detached == null) { "Payload is attached; detachedPayload must not be set" }
        attached
    } else requireNotNull(detached) { "Payload is detached; supply detachedPayload" }

internal fun <Payload> ByteArray.toTypedPayload(serializer: KSerializer<Payload>, serialFormat: Cbor = coseCompliantSerializer): Payload =
    if (serializer == ByteArraySerializer()) {
        @Suppress("UNCHECKED_CAST")
        (this as Payload)
    } else {
        runCatching { serialFormat.decodeFromByteArray(serializer, this) }
            .getOrElse { serialFormat.decodeFromByteArray(ByteStringWrapperSerializer(serializer), this).value }
    }

/** Legacy encoding policy: byte arrays are opaque; other payloads are tag 24 wrapping an encoded CBOR byte string. */
internal fun <Payload> encodePayload(payload: Payload, serializer: KSerializer<Payload>): ByteArray = when (payload) {
    is ByteArray -> payload.copyOf()
    is ByteStringWrapper<*> -> throw IllegalArgumentException("Payload must not be a ByteStringWrapper")
    else -> coseCompliantSerializer.encodeToByteArray(ByteStringWrapperSerializer(serializer), ByteStringWrapper(payload)).wrapInCborTag(24)
}
