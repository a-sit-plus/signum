package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.josef.io.takeUnlessEmpty

private fun JwsHeader.Part.toProtectedHeaderBytes(): ByteArray =
    joseCompliantSerializer.encodeToString(JwsHeader.Part.serializer(), this)
        .encodeToByteArray()

private fun ByteArray.toProtectedHeaderPart(): JwsHeader.Part =
    joseCompliantSerializer.decodeFromString(
        JwsHeader.Part.serializer(),
        decodeToString(),
    )

object JwsProtectedHeaderSerializer : TransformingSerializerTemplate<JwsHeader.Part, ByteArray>(
    parent = ByteArrayBase64UrlSerializer,
    encodeAs = JwsHeader.Part::toProtectedHeaderBytes,
    decodeAs = ByteArray::toProtectedHeaderPart,
    serialName = "JwsProtectedHeader",
) {
    /**
     * RFC 7515 requires empty protected header values to be absent rather than encoded as `{}`.
     */
    fun encodeToByteArrayOrNull(header: JwsHeader.Part?): ByteArray? =
        header?.takeUnlessEmpty()?.toProtectedHeaderBytes()

    fun decodeFromByteArray(encodedHeader: ByteArray): JwsHeader.Part = encodedHeader.toProtectedHeaderPart()

}
