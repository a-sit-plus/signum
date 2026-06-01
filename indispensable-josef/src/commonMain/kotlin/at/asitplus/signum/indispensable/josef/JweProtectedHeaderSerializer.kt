package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import kotlinx.serialization.json.JsonObject

private fun JweHeader.Part.toProtectedHeaderBytes(): ByteArray =
    joseCompliantSerializer.encodeToString(JweHeader.Part.serializer(), this)
        .encodeToByteArray()

private fun ByteArray.toProtectedHeaderPart(): JweHeader.Part =
    joseCompliantSerializer.decodeFromString(
        JweHeader.Part.serializer(),
        decodeToString(),
    )

private fun ByteArray.toProtectedHeaderJsonObject(): JsonObject =
    joseCompliantSerializer.decodeFromString(decodeToString())

object JweProtectedHeaderSerializer : TransformingSerializerTemplate<JweHeader.Part, ByteArray>(
    parent = ByteArrayBase64UrlSerializer,
    encodeAs = JweHeader.Part::toProtectedHeaderBytes,
    decodeAs = ByteArray::toProtectedHeaderPart,
    serialName = "JweProtectedHeader",
) {
    fun encodeToByteArray(header: JweHeader.Part): ByteArray = header.toProtectedHeaderBytes()

    /**
     * RFC 7516 requires empty protected header values to be absent rather than encoded as `{}`.
     */
    fun encodeToByteArrayOrNull(header: JweHeader.Part?): ByteArray? =
        header
            ?.takeUnless { it.toJsonObject().isEmpty() }
            ?.toProtectedHeaderBytes()

    /**
     * RFC 7516 requires empty protected header values to be absent rather than encoded as `{}`.
     */
    internal fun requireAbsentIfEmpty(encodedHeader: ByteArray?) {
        require(encodedHeader == null || decodeToJsonObject(encodedHeader).isNotEmpty()) {
            "JWE protected header must be absent when it would otherwise be empty"
        }
    }

    fun decodeFromByteArray(encodedHeader: ByteArray): JweHeader.Part = encodedHeader.toProtectedHeaderPart()

    fun decodeToJsonObject(encodedHeader: ByteArray): JsonObject = encodedHeader.toProtectedHeaderJsonObject()
}
