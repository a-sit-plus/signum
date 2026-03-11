package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.io.ByteArrayUtf8Serializer
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.json.JsonObject

private fun JwsHeader.Part.toProtectedHeaderBytes(): ByteArray =
    joseCompliantSerializer.encodeToString(JwsHeader.Part.serializer(), this)
        .encodeToByteArray()
        .encodeToString(Base64UrlStrict)
        .encodeToByteArray()

private fun ByteArray.toProtectedHeaderJsonString(): String =
    decodeToString()
        .decodeToByteArray(Base64UrlStrict)
        .decodeToString()

private fun ByteArray.toProtectedHeaderPart(): JwsHeader.Part =
    joseCompliantSerializer.decodeFromString(
        JwsHeader.Part.serializer(),
        toProtectedHeaderJsonString(),
    )

private fun ByteArray.toProtectedHeaderJsonObject(): JsonObject =
    joseCompliantSerializer.decodeFromString(toProtectedHeaderJsonString())

object JwsProtectedHeaderSerializer : TransformingSerializerTemplate<JwsHeader.Part, ByteArray>(
    parent = ByteArrayUtf8Serializer,
    encodeAs = JwsHeader.Part::toProtectedHeaderBytes,
    decodeAs = ByteArray::toProtectedHeaderPart,
    serialName = "JwsProtectedHeader",
) {
    fun encodeToByteArray(header: JwsHeader.Part): ByteArray = header.toProtectedHeaderBytes()

    fun decodeFromByteArray(encodedHeader: ByteArray): JwsHeader.Part = encodedHeader.toProtectedHeaderPart()

    fun decodeToJsonObject(encodedHeader: ByteArray): JsonObject = encodedHeader.toProtectedHeaderJsonObject()
}
