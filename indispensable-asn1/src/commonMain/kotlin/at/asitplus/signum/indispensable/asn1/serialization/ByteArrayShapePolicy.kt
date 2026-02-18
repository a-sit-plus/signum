package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.Asn1BitString
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Primitive
import at.asitplus.signum.indispensable.asn1.Asn1PrimitiveOctetString
import at.asitplus.signum.indispensable.asn1.encoding.asAsn1BitString
import kotlinx.serialization.SerializationException
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.StructureKind

internal enum class ByteArrayShape {
    OCTET_STRING,
    BIT_STRING,
    NOT_APPLICABLE,
}

internal object ByteArrayShapePolicy {
    private val byteArrayDescriptor = ByteArraySerializer().descriptor

    private fun isBitStringRequested(
        inlineAsBitString: Boolean = false,
        propertyAsBitString: Boolean = false,
        descriptor: SerialDescriptor? = null,
    ): Boolean = inlineAsBitString || propertyAsBitString || (descriptor?.isAsn1BitString == true)

    private fun shapeForRuntimeValue(
        value: Any,
        bitStringRequested: Boolean,
    ): ByteArrayShape = when (value) {
        is ByteArray -> if (bitStringRequested) ByteArrayShape.BIT_STRING else ByteArrayShape.OCTET_STRING
        else -> ByteArrayShape.NOT_APPLICABLE
    }

    /**
     * Resolves byte-array shape from a runtime [value] and bit-string hints.
     *
     * @throws SerializationException if `@Asn1BitString` is requested for a non-ByteArray runtime value
     */
    @Throws(SerializationException::class)
    fun resolveRuntimeValueShape(
        value: Any,
        inlineAsBitString: Boolean = false,
        propertyAsBitString: Boolean = false,
    ): ByteArrayShape {
        val bitStringRequested = isBitStringRequested(
            inlineAsBitString = inlineAsBitString,
            propertyAsBitString = propertyAsBitString,
        )
        requireBitStringCompatibleValue(bitStringRequested, value)
        return shapeForRuntimeValue(
            value = value,
            bitStringRequested = bitStringRequested,
        )
    }

    fun shapeForDescriptor(
        descriptor: SerialDescriptor,
        bitStringRequested: Boolean,
    ): ByteArrayShape =
        if (descriptor == byteArrayDescriptor) {
            if (bitStringRequested) ByteArrayShape.BIT_STRING else ByteArrayShape.OCTET_STRING
        } else {
            ByteArrayShape.NOT_APPLICABLE
        }

    /**
     * Resolves byte-array shape from serializer [descriptor] and bit-string hints.
     *
     * @throws SerializationException if `@Asn1BitString` is requested for a serializer that is not byte-array compatible
     */
    @Throws(SerializationException::class)
    fun resolveSerializerShape(
        descriptor: SerialDescriptor,
        layoutPlan: DerLayoutPlanContext,
        inlineAsBitString: Boolean = false,
        propertyAsBitString: Boolean = false,
        includeDescriptorAsBitString: Boolean = false,
    ): ByteArrayShape {
        val bitStringRequested = if (includeDescriptorAsBitString) {
            isBitStringRequested(
                inlineAsBitString = inlineAsBitString,
                propertyAsBitString = propertyAsBitString,
                descriptor = descriptor,
            )
        } else {
            isBitStringRequested(
                inlineAsBitString = inlineAsBitString,
                propertyAsBitString = propertyAsBitString,
            )
        }
        requireBitStringCompatibleSerializer(
            bitStringRequested = bitStringRequested,
            descriptor = descriptor,
            layoutPlan = layoutPlan,
        )
        return shapeForDescriptor(
            descriptor = descriptor,
            bitStringRequested = bitStringRequested,
        )
    }

    /**
     * Ensures bit-string hint usage is compatible with runtime [value].
     *
     * @throws SerializationException if bit-string mode is requested for non-ByteArray runtime values
     */
    @Throws(SerializationException::class)
    fun requireBitStringCompatibleValue(
        bitStringRequested: Boolean,
        value: Any,
    ) {
        if (bitStringRequested && value !is ByteArray) {
            throw SerializationException(
                "@Asn1BitString can only be used with ByteArray-compatible values, but got ${value::class}"
            )
        }
    }

    /**
     * Ensures bit-string hint usage is compatible with serializer [descriptor].
     *
     * @throws SerializationException if bit-string mode is requested for a non-byte-array-compatible descriptor
     */
    @Throws(SerializationException::class)
    fun requireBitStringCompatibleSerializer(
        bitStringRequested: Boolean,
        descriptor: SerialDescriptor,
        layoutPlan: DerLayoutPlanContext,
    ) {
        if (bitStringRequested && !layoutPlan.isBitStringCompatible(descriptor)) {
            throw SerializationException(
                "@Asn1BitString can only be used with ByteArray-compatible serializers, but got ${descriptor.serialName}"
            )
        }
    }

    /**
     * Encodes [bytes] according to [shape].
     *
     * @throws IllegalStateException when [shape] is [ByteArrayShape.NOT_APPLICABLE]
     */
    @Throws(IllegalStateException::class)
    fun encodeByteArray(
        bytes: ByteArray,
        shape: ByteArrayShape,
    ): Asn1Element = when (shape) {
        ByteArrayShape.BIT_STRING -> Asn1BitString(bytes).encodeToTlv()
        ByteArrayShape.OCTET_STRING -> Asn1PrimitiveOctetString(bytes)
        ByteArrayShape.NOT_APPLICABLE -> error("Byte-array shape is not applicable")
    }

    /**
     * Decodes [primitive] into bytes according to [shape].
     *
     * @throws SerializationException when BIT STRING decoding fails for invalid ASN.1 payload/tag
     * @throws IllegalStateException when [shape] is [ByteArrayShape.NOT_APPLICABLE]
     */
    @Throws(SerializationException::class, IllegalStateException::class)
    fun decodeByteArray(
        primitive: Asn1Primitive,
        shape: ByteArrayShape,
        tagToValidate: Asn1Element.Tag?,
    ): ByteArray = when (shape) {
        ByteArrayShape.BIT_STRING ->
            primitive.asAsn1BitString(tagToValidate ?: Asn1Element.Tag.BIT_STRING).rawBytes

        ByteArrayShape.OCTET_STRING -> primitive.content
        ByteArrayShape.NOT_APPLICABLE -> error("Byte-array shape is not applicable")
    }

    fun defaultTagForDescriptor(
        descriptor: SerialDescriptor,
        byteArrayShape: ByteArrayShape,
    ): Asn1Element.Tag? =
        if (descriptor.isSetDescriptor) Asn1Element.Tag.SET
        else when (byteArrayShape) {
            ByteArrayShape.BIT_STRING -> Asn1Element.Tag.BIT_STRING
            ByteArrayShape.OCTET_STRING -> Asn1Element.Tag.OCTET_STRING
            ByteArrayShape.NOT_APPLICABLE -> when (descriptor.kind) {
                is StructureKind.CLASS, is StructureKind.OBJECT -> Asn1Element.Tag.SEQUENCE
                is StructureKind.LIST -> Asn1Element.Tag.SEQUENCE
                is StructureKind.MAP -> Asn1Element.Tag.SEQUENCE
                else -> null // primitive tags validated in decodeValue()
            }
        }
}
