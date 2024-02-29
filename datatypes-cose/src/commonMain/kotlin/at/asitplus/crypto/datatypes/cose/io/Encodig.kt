package at.asitplus.crypto.datatypes.cose.io

import at.asitplus.crypto.datatypes.cose.CoseKey
import at.asitplus.crypto.datatypes.cose.CoseKeyCompressedSerializer
import at.asitplus.crypto.datatypes.cose.CoseKeyParams
import at.asitplus.crypto.datatypes.cose.CoseKeyUncompressedSerializer
import kotlinx.serialization.BinaryFormat
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerializationStrategy
import kotlinx.serialization.cbor.Cbor
import kotlinx.serialization.modules.EmptySerializersModule
import kotlinx.serialization.modules.SerializersModule

@OptIn(ExperimentalSerializationApi::class)
val cborSerializer by lazy { Cose() }

@OptIn(ExperimentalSerializationApi::class)
class Cose(override val serializersModule: SerializersModule = EmptySerializersModule()) :
    BinaryFormat {

    private val cbor = Cbor {
        ignoreUnknownKeys = true
        alwaysUseByteString = true
        encodeDefaults = false
        writeDefiniteLengths = true
        serializersModule = this@Cose.serializersModule
    }

    override fun <T> decodeFromByteArray(
        deserializer: DeserializationStrategy<T>,
        bytes: ByteArray
    ): T {
        if (deserializer.descriptor == CoseKeyUncompressedSerializer.descriptor)
            kotlin.runCatching { cbor.decodeFromByteArray(deserializer, bytes) }
                .fold(onSuccess = { return it },
                    onFailure = { ex ->
                        if (ex is CoseKeyUncompressedSerializer.RetrydecodeEcException) return cbor.decodeFromByteArray(
                            CoseKeyCompressedSerializer,
                            bytes
                        ) as T
                        else throw ex
                    })
        else return cbor.decodeFromByteArray(deserializer, bytes)
    }

    override fun <T> encodeToByteArray(
        serializer: SerializationStrategy<T>,
        value: T
    ): ByteArray =
        if( value is CoseKey && serializer.descriptor==CoseKeyUncompressedSerializer.descriptor){
            if (value.keyParams is CoseKeyParams.EcYBoolParams)
                cbor.encodeToByteArray(CoseKeyCompressedSerializer, value)
            else cbor.encodeToByteArray(CoseKeyUncompressedSerializer, value)
        }else{
            cbor.encodeToByteArray(serializer,value)
        }


}