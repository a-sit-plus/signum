package at.asitplus.signum.indispensable.pki.x500

import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.pki.X509GeneralName

/** RFC 5280 `registeredID` GeneralName CHOICE `[8]`. */
class RegisteredIDName(
    val value: ObjectIdentifier,
) : AbstractGeneralName() {
    override val equalityValue get() = value

    /** Always valid: [ObjectIdentifier] is guaranteed valid by its own constructor. */

    override fun toString(): String = value.toString()

    companion object {
        val tag = X509GeneralName.Tags.registeredID
        internal fun fromAsn1Model(src: X509GeneralName): RegisteredIDName =
            RegisteredIDName((src as X509GeneralName.RegisteredId).oid)
    }
}
