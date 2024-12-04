package at.asitplus.signum.indispensable.cosef

import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapperSerializer
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.InternalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.cbor.ValueTags
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.SerialKind
import kotlinx.serialization.descriptors.StructureKind
import kotlinx.serialization.descriptors.buildSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.encoding.decodeStructure
import kotlinx.serialization.encoding.encodeStructure

/**
 * Serializes [CoseSigned] with a typed payload,
 * also adding Tag 24 to the payload, if it is a typed object, i.e. not a byte array.
 */
class CoseSignedSerializer<P : Any?>(
    private val parameterSerializer: KSerializer<P>,
) : KSerializer<CoseSigned<P>> {

    @OptIn(InternalSerializationApi::class)
    override val descriptor: SerialDescriptor = buildSerialDescriptor("CoseSigned", StructureKind.LIST) {
        element("protectedHeader", ByteStringWrapperSerializer(CoseHeader.serializer()).descriptor)
        element("unprotectedHeader", CoseHeader.serializer().descriptor)
        element("payload", ByteStringWrapperSerializer(parameterSerializer).descriptor)
        element("signature", ByteArraySerializer().descriptor)
    }

    override fun deserialize(decoder: Decoder): CoseSigned<P> = decoder.decodeStructure(descriptor) {
        val protectedHeader =
            decodeSerializableElement(descriptor, 0, ByteStringWrapperSerializer(CoseHeader.serializer()))
        val unprotectedHeader = decodeNullableSerializableElement(descriptor, 1, CoseHeader.serializer())
        val payload: ByteArray? = decodeNullableSerializableElement(descriptor, 2, ByteArraySerializer())
        val signature: ByteArray = decodeSerializableElement(descriptor, 3, ByteArraySerializer())
        runCatching {
            val typedPayload: P? = payload?.let {
                coseCompliantSerializer.decodeFromByteArray(parameterSerializer, it)
            }
            CoseSigned(protectedHeader, unprotectedHeader, typedPayload, signature)
        }.getOrElse {
            @Suppress("UNCHECKED_CAST")
            CoseSigned(protectedHeader, unprotectedHeader, payload as P, signature)
        }
    }

    override fun serialize(encoder: Encoder, value: CoseSigned<P>) {
        encoder.encodeStructure(descriptor) {
            encodeSerializableElement(
                descriptor,
                0,
                ByteStringWrapperSerializer(CoseHeader.serializer()),
                value.protectedHeader
            )
            encodeNullableSerializableElement(descriptor, 1, CoseHeader.serializer(), value.unprotectedHeader)
            if (value.payload != null && value.payload::class != ByteArray::class) {
                encodeNullableSerializableElement(
                    buildTag24SerialDescriptor(),
                    2,
                    ByteStringWrapperSerializer(parameterSerializer),
                    ByteStringWrapper(value.payload)
                )
            } else {
                encodeNullableSerializableElement(descriptor, 2, parameterSerializer, value.payload)
            }
            encodeSerializableElement(descriptor, 3, ByteArraySerializer(), value.rawSignature)
        }
    }

    private fun buildTag24SerialDescriptor(): SerialDescriptor = object : SerialDescriptor {
        @ExperimentalSerializationApi
        override val serialName: String = descriptor.serialName

        @ExperimentalSerializationApi
        override val kind: SerialKind = descriptor.kind

        @ExperimentalSerializationApi
        override val elementsCount: Int = descriptor.elementsCount

        @ExperimentalSerializationApi
        override fun getElementName(index: Int): String = descriptor.getElementName(index)

        @ExperimentalSerializationApi
        override fun getElementIndex(name: String): Int = descriptor.getElementIndex(name)

        @ExperimentalSerializationApi
        override fun getElementAnnotations(index: Int): List<Annotation> =
            if (index != 2) descriptor.getElementAnnotations(index) else listOf(ValueTags(24u))

        @ExperimentalSerializationApi
        override fun getElementDescriptor(index: Int): SerialDescriptor = descriptor.getElementDescriptor(index)

        @ExperimentalSerializationApi
        override fun isElementOptional(index: Int): Boolean = descriptor.isElementOptional(index)
    }
}
