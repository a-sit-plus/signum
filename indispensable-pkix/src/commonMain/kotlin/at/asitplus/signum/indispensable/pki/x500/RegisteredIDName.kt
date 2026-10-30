package at.asitplus.signum.indispensable.pki.x500

import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.pki.X509GeneralName
import at.asitplus.signum.indispensable.pki.GeneralName.X509Representable.Descriptor

/** RFC 5280 `registeredID` GeneralName CHOICE `[8]`. */
class RegisteredIDName private constructor(
    val value: ObjectIdentifier,
    asn1Representation: X509GeneralName,
) : AbstractX509GeneralName(asn1Representation) {

    constructor(value: ObjectIdentifier) : this(value, X509GeneralName.RegisteredId(value))

    /** Always valid: [ObjectIdentifier] is guaranteed valid by its own constructor. */
    override val isValid: Boolean get() = true

    override fun toString(): String = value.toString()

    companion object : Descriptor {
        override val tag = X509GeneralName.Tags.registeredID
        override fun fromAsn1Representation(src: X509GeneralName): RegisteredIDName =
            RegisteredIDName((src as X509GeneralName.RegisteredId).oid, src)
    }
}
