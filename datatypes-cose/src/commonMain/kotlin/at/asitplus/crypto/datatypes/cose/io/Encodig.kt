package at.asitplus.crypto.datatypes.cose.io

import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.base16.Base16ConfigBuilder
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.cbor.Cbor

@OptIn(ExperimentalSerializationApi::class)
val cborSerializer by lazy {
    Cbor {
        ignoreUnknownKeys = true
        alwaysUseByteString = true
        encodeDefaults = false
        writeDefiniteLengths = true
    }
}


/**
 * Strict Base16 encoder
 */
val Base16Strict = Base16(config = Base16ConfigBuilder().apply {
    strict()
}.build())
