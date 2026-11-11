package at.asitplus.signum.indispensable.pki.extn

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
