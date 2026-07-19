package at.asitplus.signum.indispensable.pki.x500

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.signum.indispensable.pki.x500.GeneralName.X509Representable.Descriptor
import at.asitplus.signum.indispensable.pki.x500.GeneralName.NameType

/** RFC 5280 `registeredID` GeneralName CHOICE `[8]`. */
class RegisteredIDName private constructor(
    val value: ObjectIdentifier,
    encoded: Asn1Element,
) : AbstractX509GeneralName(NameType.OID, encoded) {

    constructor(value: ObjectIdentifier) : this(value, value.encodeToTlv() withImplicitTag contextTag(8u))

    /** Always valid: [ObjectIdentifier] is guaranteed valid by its own constructor. */
    override val isValid: Boolean get() = true

    override fun toString(): String = value.toString()

    companion object : Descriptor {
        override val type = NameType.OID
        override fun fromAsn1Representation(src: Asn1Element): RegisteredIDName =
            RegisteredIDName(ObjectIdentifier.decodeFromAsn1ContentBytes(src.asPrimitive().content), src)
    }
}
