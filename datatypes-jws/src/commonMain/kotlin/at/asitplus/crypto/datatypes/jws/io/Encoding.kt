package at.asitplus.crypto.datatypes.jws.io

import kotlinx.serialization.json.Json

/**
 * JSON Serializer, preconfigured with JWS-compliant settings:
 * ```kotlin
 * prettyPrint = false
 * encodeDefaults = false
 * classDiscriminator = "type"
 * ignoreUnknownKeys = true
 * ```
 */
val jsonSerializer by lazy {
    Json {
        prettyPrint = false
        encodeDefaults = false
        classDiscriminator = "type"
        ignoreUnknownKeys = true
    }
}
