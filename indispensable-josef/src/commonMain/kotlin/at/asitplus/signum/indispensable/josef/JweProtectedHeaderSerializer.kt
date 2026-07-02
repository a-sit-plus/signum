package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.josef.io.takeUnlessEmpty

private fun JweHeader.Part.toProtectedHeaderBytes(): ByteArray =
    joseCompliantSerializer.encodeToString(JweHeader.Part.serializer(), this)
        .encodeToByteArray()

private fun ByteArray.toProtectedHeaderPart(): JweHeader.Part =
    joseCompliantSerializer.decodeFromString(
        JweHeader.Part.serializer(),
        decodeToString(),
    )

object JweProtectedHeaderSerializer : TransformingSerializerTemplate<JweHeader.Part, ByteArray>(
    parent = ByteArrayBase64UrlSerializer,
    encodeAs = JweHeader.Part::toProtectedHeaderBytes,
    decodeAs = ByteArray::toProtectedHeaderPart,
) {
    /**
     * RFC 7516 requires empty protected header values to be absent rather than encoded as `{}`.
     */
    fun encodeToByteArrayOrNull(header: JweHeader.Part?): ByteArray? =
        header?.takeUnlessEmpty()?.toProtectedHeaderBytes()

    fun decodeFromByteArray(encodedHeader: ByteArray): JweHeader.Part = encodedHeader.toProtectedHeaderPart()
}
