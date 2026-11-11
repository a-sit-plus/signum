package at.asitplus.signum.indispensable.pki.extn

import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.crypto.pki.X509GeneralName
import at.asitplus.awesn1.serialization.Asn1Tag
import kotlinx.serialization.Serializable
import com.ionspin.kotlin.bignum.integer.BigInteger
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.indispensable.SourceRepresentationStorage
import at.asitplus.signum.indispensable.WithSourceRepresentation
import at.asitplus.signum.indispensable.pki.GeneralName

/** A name subtree with semantic distance bounds, independent of its wire representation. */
data class GeneralSubtree(
    val base: GeneralName,
    val minimum: BigInteger = BigInteger.ZERO,
    val maximum: BigInteger? = null,
) : WithSourceRepresentation {
    @SignumInternals override val sourceRepresentation = SourceRepresentationStorage()
    companion object

    /** ASN.1 wire shape; semantic values and copies do not retain it as a constructor field. */
    @Serializable
    internal data class Asn1Representation(
        val base: X509GeneralName,
        @Asn1Tag(0u) val minimum: Asn1Integer? = null,
        @Asn1Tag(1u) val maximum: Asn1Integer? = null,
    )
}

/** An ordered collection of name subtrees, independent of constraint-processing algorithms. */
class GeneralSubtrees(
    trees: List<GeneralSubtree>
) {

    val trees: List<GeneralSubtree> = trees.toList()
    override fun equals(other: Any?): Boolean = other is GeneralSubtrees && trees == other.trees
    override fun hashCode(): Int = trees.hashCode()

    fun copy(): GeneralSubtrees = GeneralSubtrees(trees.toList())

}
