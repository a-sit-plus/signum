package at.asitplus.signum.indispensable.pki.x500

import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.crypto.pki.X509GeneralName
import at.asitplus.signum.indispensable.DerEncodable

/** An encoding-independent RFC 5280/C509 `GeneralName`. */
interface GeneralName {

    /** A [GeneralName] with an ASN.1/DER X.509 representation. */
    interface X509Representable : GeneralName, DerEncodable<X509GeneralName> {
        companion object /*for extension functions and properties*/
    }

    enum class ConstraintResult {
        DIFF_TYPE,     // Different type, no constraint
        MATCH,         // Exact match
        NARROWS,       // Input narrows this name
        WIDENS,        // Input widens this name
        SAME_TYPE;     // Same type, but no match/narrow/widen
    }

    /**
     * Returns whether this name is valid:
     * - `true`: validation succeeded
     * - `false`: validation failed
     * - `null`: no validation implemented (the generic [GeneralName] never validates)
     */
    val isValid: Boolean? get() = null

    /**
     * Returns a copy of this name with `isValid` set per [validate]. Intended for variants that do
     * not implement validation (`isValid == null`), to mark them before constraint checks.
     */
    fun createValidatedCopy(validate: (GeneralName) -> Boolean): GeneralName
}

internal fun GeneralName.requireX509(): GeneralName.X509Representable =
    this as? GeneralName.X509Representable
        ?: throw Asn1Exception("GeneralName has no X.509/DER representation")

private class GenericX509GeneralName(
    override val asn1Representation: X509GeneralName,
    override val isValid: Boolean? = null,
) : GeneralName.X509Representable {

    override fun equals(other: Any?): Boolean =
        other is GeneralName.X509Representable && asn1Representation == other.asn1Representation

    override fun hashCode(): Int = asn1Representation.hashCode()

    override fun toString(): String = "GeneralName($asn1Representation)"

    override fun createValidatedCopy(validate: (GeneralName) -> Boolean): GeneralName =
        GenericX509GeneralName(asn1Representation, validate(this))
}
