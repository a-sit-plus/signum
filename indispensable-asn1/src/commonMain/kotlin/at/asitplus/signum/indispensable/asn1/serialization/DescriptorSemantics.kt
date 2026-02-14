package at.asitplus.signum.indispensable.asn1.serialization

import kotlinx.serialization.builtins.SetSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.descriptors.SerialDescriptor

private val setDescriptor: SerialDescriptor = SetSerializer(String.serializer()).descriptor

internal val SerialDescriptor.isSetDescriptor: Boolean
    get() = setDescriptor::class.isInstance(this)
