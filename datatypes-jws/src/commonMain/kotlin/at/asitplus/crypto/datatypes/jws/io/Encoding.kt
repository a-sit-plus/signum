package at.asitplus.crypto.datatypes.jws.io

import kotlinx.serialization.json.Json

val jsonSerializer by lazy {
    Json {
        prettyPrint = false
        encodeDefaults = false
        classDiscriminator = "type"
        ignoreUnknownKeys = true
    }
}
