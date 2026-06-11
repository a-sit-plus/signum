package at.asitplus.signum.indispensable.josef.io

import at.asitplus.signum.indispensable.josef.JweHeader
import at.asitplus.signum.indispensable.josef.JwsHeader
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject

/**
 * JSON Serializer, preconfigured with JOSE-compliant settings:
 * ```kotlin
 * prettyPrint = false
 * encodeDefaults = false
 * classDiscriminator = "type"
 * ignoreUnknownKeys = true
 * ```
 */
val joseCompliantSerializer by lazy {
    Json {
        prettyPrint = false
        encodeDefaults = false
        classDiscriminator = "type"
        ignoreUnknownKeys = true
    }
}


internal fun ByteArray?.takeUnlessEmpty(): ByteArray? = this?.takeUnless { it.isEmpty() }

internal fun JweHeader.Part?.takeUnlessEmpty(): JweHeader.Part? =
    this?.takeUnless {
        joseCompliantSerializer.encodeToJsonElement(JweHeader.Part.Companion.serializer(), this).jsonObject.isEmpty()
    }

internal fun JwsHeader.Part?.takeUnlessEmpty(): JwsHeader.Part? =
    this?.takeUnless {
        joseCompliantSerializer.encodeToJsonElement(JwsHeader.Part.Companion.serializer(), this).jsonObject.isEmpty()
    }

internal fun requireAbsentIfEmpty(value: ByteArray?, memberName: String) {
    require(value == null || value.isNotEmpty()) {
        "$memberName member must be absent when it would otherwise be empty"
    }
}

internal fun requireAbsentIfEmpty(header: JweHeader.Part?, memberName: String) {
    require(header == null || header.toJsonObject().isNotEmpty()) {
        "$memberName member must be absent when it would otherwise be empty"
    }
}

internal infix fun <P> P?.xor(other: P?): P? = if (this != null && other != null) {
    throw Exception("Collision")
} else this ?: other