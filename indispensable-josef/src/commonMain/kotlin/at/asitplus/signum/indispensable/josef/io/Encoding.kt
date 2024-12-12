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

        // TODO: unsure whether this is actually ok:
        //  When receiving a jwt one cannot just ignore unknown headers:
        /**
         * https://datatracker.ietf.org/doc/html/rfc7519
         *    5.   Verify that the resulting JOSE Header includes only parameters
         *         and values whose syntax and semantics are both understood and
         *         supported or that are specified as being ignored when not
         *         understood.
         */
        ignoreUnknownKeys = true
    }
}
