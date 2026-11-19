package at.asitplus.signum.indispensable.pki.x500

import at.asitplus.awesn1.Asn1Sequence
import at.asitplus.awesn1.crypto.pki.X509GeneralName
import at.asitplus.signum.indispensable.pki.GeneralName

/** RFC 5280 `x400Address` GeneralName CHOICE `[3]`. Carries the awesn1 [X509GeneralName.X400Address] verbatim. */
class X400AddressName private constructor(
    val x400Address: X509GeneralName.X400Address,
) : AbstractGeneralName() {
    override val equalityValue get() = x400Address

    override fun toString(): String = x400Address.toString()

    companion object {
        operator fun invoke(value: X509GeneralName.X400Address): X400AddressName = X400AddressName(value)

        operator fun invoke(value: Asn1Sequence): X400AddressName = invoke(X509GeneralName.X400Address(value))

        val tag = X509GeneralName.Tags.x400Address
        internal fun fromAsn1Model(src: X509GeneralName): X400AddressName {
            return X400AddressName(src as X509GeneralName.X400Address)
        }
    }
}
