package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import kotlinx.serialization.json.JsonObject

private fun JwsHeader.Part.toProtectedHeaderBytes(): ByteArray =
    joseCompliantSerializer.encodeToString(JwsHeader.Part.serializer(), this)
        .encodeToByteArray()

private fun ByteArray.toProtectedHeaderPart(): JwsHeader.Part =
    joseCompliantSerializer.decodeFromString(
        JwsHeader.Part.serializer(),
        decodeToString(),
    )

private fun ByteArray.toProtectedHeaderJsonObject(): JsonObject =
    joseCompliantSerializer.decodeFromString(decodeToString())

object JwsProtectedHeaderSerializer : TransformingSerializerTemplate<JwsHeader.Part, ByteArray>(
    parent = ByteArrayBase64UrlSerializer,
    encodeAs = JwsHeader.Part::toProtectedHeaderBytes,
    decodeAs = ByteArray::toProtectedHeaderPart,
    serialName = "JwsProtectedHeader",
) {
    fun encodeToByteArray(header: JwsHeader.Part): ByteArray = header.toProtectedHeaderBytes()

    fun decodeFromByteArray(encodedHeader: ByteArray): JwsHeader.Part = encodedHeader.toProtectedHeaderPart()

    fun decodeToJsonObject(encodedHeader: ByteArray): JsonObject = encodedHeader.toProtectedHeaderJsonObject()
}
