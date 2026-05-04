package at.asitplus.signum.indispensable.asn1

import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

interface Awesn1Backed<Backing> {
    val backing: Backing
}

abstract class Awesn1BackedSerializer<Backing, Wrapper : Awesn1Backed<Backing>>(
    private val backingSerializer: KSerializer<Backing>,
    private val wrap: (Backing) -> Wrapper,
) : KSerializer<Wrapper> {

    final override val descriptor: SerialDescriptor
        get() = backingSerializer.descriptor

    final override fun serialize(encoder: Encoder, value: Wrapper) {
        backingSerializer.serialize(encoder, value.backing)
    }

    final override fun deserialize(decoder: Decoder): Wrapper {
        return wrap(backingSerializer.deserialize(decoder))
    }
}