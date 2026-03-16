package at.asitplus.signum.indispensable

import at.asitplus.awesn1.Asn1Encodable
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import kotlinx.serialization.KSerializer

open class Awesn1BackedSerializer<ValueT, RawT : Asn1Encodable<*>>(
    rawSerializer: KSerializer<RawT>,
    encodeAs: (ValueT) -> RawT,
    decodeAs: (RawT) -> ValueT,
    serialName: String = "",
) : TransformingSerializerTemplate<ValueT, RawT>(
    parent = rawSerializer,
    encodeAs = encodeAs,
    decodeAs = decodeAs,
    serialName = serialName,
)
