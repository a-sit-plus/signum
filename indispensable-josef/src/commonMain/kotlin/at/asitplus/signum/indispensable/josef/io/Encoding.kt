package at.asitplus.signum.indispensable.josef.io

import kotlinx.serialization.json.Json

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
