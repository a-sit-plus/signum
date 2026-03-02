package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.builtins.serializer

object JwsProtectedHeaderSerializer : TransformingSerializerTemplate<JwsHeader, String>(
    parent = String.serializer(),
    encodeAs = { header ->
        joseCompliantSerializer.encodeToString(JwsHeader.serializer(), header)
            .encodeToByteArray()
            .encodeToString(Base64UrlStrict)
    },
    decodeAs = { encodedHeader ->
        joseCompliantSerializer.decodeFromString(
            JwsHeader.serializer(),
            encodedHeader.decodeToByteArray(Base64UrlStrict).decodeToString(),
        )
    },
    serialName = "JwsProtectedHeader",
)
