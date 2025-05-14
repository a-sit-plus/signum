package at.asitplus.signum.indispensable.pki.pkiExtensions

import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.Asn1Set
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.runRethrowing
import at.asitplus.signum.indispensable.pki.RelativeDistinguishedName

class X500Name(
    val relativeDistinguishedNames: List<RelativeDistinguishedName>,
    override val type: GeneralNameOption.NameType = GeneralNameOption.NameType.DIRECTORY
) : Asn1Encodable<Asn1Sequence>, GeneralNameOption {

    override fun encodeToTlv() = Asn1.Sequence {
        relativeDistinguishedNames.forEach { +it }
    }

    companion object : Asn1Decodable<Asn1Sequence, X500Name> {
        override fun doDecode(src: Asn1Sequence): X500Name = runRethrowing {
            X500Name(src.children.map { RelativeDistinguishedName.decodeFromTlv(it as Asn1Set) })
        }

    }

    override fun toString() = "X500Name(RDNs=${relativeDistinguishedNames.joinToString()})"

    override fun constraints(input: GeneralNameOption?): GeneralNameOption.ConstraintResult {
        if (input !is X500Name) return GeneralNameOption.ConstraintResult.DIFF_TYPE

        if (this == input) return GeneralNameOption.ConstraintResult.MATCH

        val inputRDNs = input.relativeDistinguishedNames
        val thisRDNs = this.relativeDistinguishedNames

        return when {
            inputRDNs.isEmpty() -> GeneralNameOption.ConstraintResult.WIDENS
            thisRDNs.isEmpty() -> GeneralNameOption.ConstraintResult.NARROWS
            input.isWithinSubtree(thisRDNs) -> GeneralNameOption.ConstraintResult.NARROWS
            this.isWithinSubtree(inputRDNs) -> GeneralNameOption.ConstraintResult.WIDENS
            else -> GeneralNameOption.ConstraintResult.SAME_TYPE
        }
    }

    private fun isWithinSubtree(otherRDNs: List<RelativeDistinguishedName>): Boolean {
        if (this.relativeDistinguishedNames == otherRDNs) return true
        if (otherRDNs.isEmpty()) return true
        if (this.relativeDistinguishedNames.size < otherRDNs.size) return false

        for (i in otherRDNs.indices) {
            if (this.relativeDistinguishedNames[i] != otherRDNs[i]) return false
        }

        return true
    }
}