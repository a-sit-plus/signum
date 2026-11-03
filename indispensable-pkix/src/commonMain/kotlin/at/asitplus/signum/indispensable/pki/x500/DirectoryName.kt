package at.asitplus.signum.indispensable.pki.x500

import at.asitplus.awesn1.crypto.pki.X509GeneralName
import at.asitplus.signum.indispensable.pki.ExperimentalPkiApi
import at.asitplus.signum.indispensable.fromAsn1
import at.asitplus.signum.indispensable.pki.GeneralName
import at.asitplus.signum.indispensable.pki.x500.ConstraintResult
import at.asitplus.signum.indispensable.pki.RelativeDistinguishedName
import at.asitplus.signum.indispensable.pki.Name

/**
 * RFC 5280 `directoryName` GeneralName CHOICE `[4] EXPLICIT`. Wraps a core [Name] so the
 * GeneralName CHOICE machinery (and the name-constraint subtree logic) stays out of the lean core.
 */
class DirectoryName(
    val name: Name,
) : AbstractGeneralName() {
    override val equalityValue get() = name

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

    companion object {
        val tag = X509GeneralName.Tags.directoryName

        internal fun fromAsn1Model(src: X509GeneralName): DirectoryName {
            val awesnName = (src as X509GeneralName.Directory).value
            return DirectoryName(Name.fromAsn1(awesnName))
        }

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
