package at.asitplus.signum.indispensable.cosef

import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapperSerializer
import kotlinx.serialization.InternalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.StructureKind
import kotlinx.serialization.descriptors.buildSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.encoding.decodeStructure
import kotlinx.serialization.encoding.encodeStructure

class CoseSignedSerializer<P : Any?> : KSerializer<CoseSigned<P>> {

    @OptIn(InternalSerializationApi::class)
    override val descriptor: SerialDescriptor = buildSerialDescriptor("CoseSigned", StructureKind.LIST) {
        element("protectedHeader", ByteStringWrapperSerializer(CoseHeader.serializer()).descriptor)
        element("unprotectedHeader", CoseHeader.serializer().descriptor)
        element("payload", ByteArraySerializer().descriptor)
        element("signature", ByteArraySerializer().descriptor)
    }

    override fun deserialize(decoder: Decoder): CoseSigned<P> {
        return decoder.decodeStructure(descriptor) {
            val protectedHeader = decodeSerializableElement(descriptor, 0, ByteStringWrapperSerializer(CoseHeader.serializer()))
            val unprotectedHeader = decodeNullableSerializableElement(descriptor, 1, CoseHeader.serializer())
            val payload = decodeNullableSerializableElement(descriptor, 2, ByteArraySerializer())
            val signature = decodeSerializableElement(descriptor, 3, ByteArraySerializer())
            CoseSigned(protectedHeader, unprotectedHeader, payload, signature)
        }
    }

    override fun serialize(encoder: Encoder, value: CoseSigned<P>) {
        encoder.encodeStructure(descriptor) {
            encodeSerializableElement(descriptor, 0, ByteStringWrapperSerializer(CoseHeader.serializer()), value.protectedHeader)
            encodeNullableSerializableElement(descriptor, 1, CoseHeader.serializer(), value.unprotectedHeader)
            encodeNullableSerializableElement(descriptor, 2, ByteArraySerializer(), value.payload)
            encodeSerializableElement(descriptor, 3, ByteArraySerializer(), value.rawSignature)
        }
    }

}
