package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.serializer

/**
 * Typed effective [header] with unprotected member placement.
 * Factories cache serialized fragments; retain the original wire object for byte-preserving round trips.
 */
@ConsistentCopyVisibility
data class JwsHeaderWrapped<out H : JwsHeader> private constructor(
    val header: H,
    internal val protectedHeaderJson: JsonObject,
    internal val unprotectedHeader: JsonObject,
    internal val protectedHeader: ByteArray,
) {

    /** Unprotected wire names emitted by the header serializer. */
    val unprotectedHeaderMembers: Set<String> = unprotectedHeader.keys

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is JwsHeaderWrapped<*>) return false
        return header == other.header && unprotectedHeaderMembers == other.unprotectedHeaderMembers
    }

    override fun hashCode(): Int = 31 * header.hashCode() + unprotectedHeaderMembers.hashCode()

    companion object {
        /** Creates a wrapper when [H]'s serializer is available explicitly. */
        operator fun <H : JwsHeader> invoke(
            header: H,
            serializer: KSerializer<H>,
            unprotectedMembers: Set<String> = emptySet(),
            serialFormat: Json = joseCompliantSerializer,
        ): JwsHeaderWrapped<H> {
            val serializedHeader = serialFormat.encodeToJsonElement(serializer, header).jsonObject
            val protectedHeaderJson = JsonObject(serializedHeader.filterKeys { it !in unprotectedMembers })
            val unprotectedHeader = JsonObject(serializedHeader.filterKeys { it in unprotectedMembers })
            return JwsHeaderWrapped(
                header = header,
                protectedHeaderJson = protectedHeaderJson,
                unprotectedHeader = unprotectedHeader,
                protectedHeader = protectedHeaderJson.toProtectedHeaderBytes(),
            )
        }

        /** Creates a wrapper while [H] is still reified at the call site. */
        inline operator fun <reified H : JwsHeader> invoke(
            header: H,
            unprotectedMembers: Set<String> = emptySet(),
            serialFormat: Json = joseCompliantSerializer,
        ): JwsHeaderWrapped<H> = invoke(
            header = header,
            serializer = serialFormat.serializersModule.serializer(),
            unprotectedMembers = unprotectedMembers,
            serialFormat = serialFormat,
        )

        /** Decodes and combines protected and unprotected fragments using the supplied header serializer. */
        fun <H : JwsHeader> fromParts(
            serializer: KSerializer<H>,
            protectedHeader: ByteArray? = null,
            unprotectedHeader: JsonObject? = null,
            serialFormat: Json = joseCompliantSerializer,
        ): JwsHeaderWrapped<H> = fromJsonObjects(
            serializer = serializer,
            protectedHeader = protectedHeader?.toProtectedHeaderJsonObject(),
            unprotectedHeader = unprotectedHeader,
            serialFormat = serialFormat,
        )

        /** Decodes fragments while [H] is still reified at the call site. */
        inline fun <reified H : JwsHeader> fromParts(
            protectedHeader: ByteArray? = null,
            unprotectedHeader: JsonObject? = null,
            serialFormat: Json = joseCompliantSerializer,
        ): JwsHeaderWrapped<H> = fromParts(
            serializer = serialFormat.serializersModule.serializer(),
            protectedHeader = protectedHeader,
            unprotectedHeader = unprotectedHeader,
            serialFormat = serialFormat,
        )

        /** Decodes and combines JSON fragments using the supplied header serializer. */
        fun <H : JwsHeader> fromJsonObjects(
            serializer: KSerializer<H>,
            protectedHeader: JsonObject? = null,
            unprotectedHeader: JsonObject? = null,
            serialFormat: Json = joseCompliantSerializer,
        ): JwsHeaderWrapped<H> = protectedHeader.strictUnion(unprotectedHeader).let { combinedHeader ->
            invoke(
                header = serialFormat.decodeFromJsonElement(serializer, combinedHeader),
                serializer = serializer,
                unprotectedMembers = unprotectedHeader?.keys ?: emptySet(),
                serialFormat = serialFormat,
            )
        }

        /** Decodes JSON fragments while [H] is still reified at the call site. */
        inline fun <reified H : JwsHeader> fromJsonObjects(
            protectedHeader: JsonObject? = null,
            unprotectedHeader: JsonObject? = null,
            serialFormat: Json = joseCompliantSerializer,
        ): JwsHeaderWrapped<H> = fromJsonObjects(
            serializer = serialFormat.serializersModule.serializer(),
            protectedHeader = protectedHeader,
            unprotectedHeader = unprotectedHeader,
            serialFormat = serialFormat,
        )
    }
}

internal fun ByteArray.toProtectedHeaderJsonObject(): JsonObject =
    joseCompliantSerializer.decodeFromString(JsonObject.serializer(), decodeToString())
