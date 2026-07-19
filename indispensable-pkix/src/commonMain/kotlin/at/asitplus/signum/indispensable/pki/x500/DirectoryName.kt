package at.asitplus.signum.indispensable.pki.x500

import at.asitplus.awesn1.Asn1Element
import at.asitplus.signum.indispensable.pki.ExperimentalPkiApi
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.signum.indispensable.pki.RelativeDistinguishedName
import at.asitplus.signum.indispensable.pki.x500.GeneralName.ConstraintResult
import at.asitplus.signum.indispensable.pki.x500.GeneralName.X509Representable.Descriptor
import at.asitplus.signum.indispensable.pki.x500.GeneralName.NameType

/**
 * RFC 5280 `directoryName` GeneralName CHOICE `[4] EXPLICIT`. Wraps a core [X500Name] so the
 * GeneralName CHOICE machinery (and the name-constraint subtree logic) stays out of the lean core.
 */
class DirectoryName(val name: X500Name) : AbstractX509GeneralName(
    NameType.DIRECTORY,
    Asn1.ExplicitlyTagged(4u) { +name.encodeToTlv(X500Name.serializer) },
) {
    override val isValid: Boolean get() = name.isValid

    override fun toString(): String = name.toString()

    @ExperimentalPkiApi
    override fun constrains(input: GeneralName?): ConstraintResult {
        return try {
            super.constrains(input)
        } catch (_: UnsupportedOperationException) {
            if (this == input) return ConstraintResult.MATCH

            val inputRDNs = (input as DirectoryName).name.relativeDistinguishedNames
            val thisRDNs = this.name.relativeDistinguishedNames

            when {
                inputRDNs.isEmpty() -> ConstraintResult.WIDENS
                thisRDNs.isEmpty() -> ConstraintResult.NARROWS
                isWithinSubtree(thisRDNs, inputRDNs) -> ConstraintResult.NARROWS
                isWithinSubtree(inputRDNs, thisRDNs) -> ConstraintResult.WIDENS
                else -> ConstraintResult.SAME_TYPE
            }
        }
    }

    companion object : Descriptor {
        override val type = NameType.DIRECTORY

        override fun fromAsn1Representation(src: Asn1Element): DirectoryName =
            DirectoryName(X500Name.decodeFromTlv(X500Name.serializer, src.asExplicitlyTagged().children.first().asSequence()))

        /** True iff [rdns] is within the subtree rooted at [subtree] (a prefix of the RDN sequence). */
        private fun isWithinSubtree(
            rdns: List<RelativeDistinguishedName>,
            subtree: List<RelativeDistinguishedName>,
        ): Boolean {
            if (rdns == subtree) return true
            if (subtree.isEmpty()) return true
            if (rdns.size < subtree.size) return false
            for (i in subtree.indices) if (rdns[i] != subtree[i]) return false
            return true
        }
    }
}
