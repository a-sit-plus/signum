package at.asitplus.signum.indispensable.pki.extn

import at.asitplus.cidre.IpAddress
import at.asitplus.signum.indispensable.pki.ExperimentalPkiApi
import at.asitplus.awesn1.Asn1Integer
import at.asitplus.signum.indispensable.Encodable
import at.asitplus.signum.indispensable.Decodable
import at.asitplus.awesn1.crypto.pki.X509GeneralName
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.signum.indispensable.pki.GeneralName
import at.asitplus.signum.indispensable.pki.X500Name
import at.asitplus.signum.indispensable.pki.x500.DNSName
import at.asitplus.signum.indispensable.pki.x500.DirectoryName
import at.asitplus.signum.indispensable.pki.x500.constrains
import at.asitplus.signum.indispensable.pki.x500.IPAddressName
import at.asitplus.signum.indispensable.pki.x500.RFC822Name
import at.asitplus.signum.indispensable.pki.x500.UriName
import at.asitplus.signum.indispensable.pki.x500.X400AddressName
import kotlinx.io.IOException


/** A name subtree with semantic distance bounds, independent of its wire representation. */
data class GeneralSubtree(
    val base: GeneralName,
    val minimum: Asn1Integer = Asn1Integer(0),
    val maximum: Asn1Integer? = null,
) : Encodable {
    override var sourceRepresentation: Pair<Encodable.Representation, Any>? = null
        private set

    internal constructor(
        base: GeneralName,
        minimum: Asn1Integer,
        maximum: Asn1Integer?,
        sourceRepresentation: Pair<Encodable.Representation, Any>,
    ) : this(base, minimum, maximum) {
        this.sourceRepresentation = sourceRepresentation
    }

    companion object : Decodable<GeneralSubtree>
}

/**
 * A `GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree` plus the RFC 5280 name-constraint
 * merge/minimize logic. (De)serialization is handled at the containing [NameConstraints] as a
 * format-specific subtree wire model under its `[0]`/`[1]` fields.
 */
class GeneralSubtrees(
    trees: List<GeneralSubtree>
) {

    var trees: List<GeneralSubtree> = trees.toMutableList()
    private set

    /**
     * Removes all redundant entries
     */
    @OptIn(ExperimentalPkiApi::class)
    private fun minimize(): GeneralSubtrees {
        val mutableTrees = trees.toMutableList()

        var i = 0
        while (i < mutableTrees.size - 1) {
            val current = mutableTrees[i].base
            var removeCurrent = false

            var j = i + 1
            while (j < mutableTrees.size) {
                val subsequent = mutableTrees[j].base
                when (current.constrains(subsequent)) {
                    GeneralName.ConstraintResult.DIFF_TYPE -> {
                        j++
                    }

                    GeneralName.ConstraintResult.MATCH -> {
                        removeCurrent = true
                        break
                    }

                    GeneralName.ConstraintResult.NARROWS -> {
                        removeCurrent = true
                        break
                    }

                    GeneralName.ConstraintResult.WIDENS -> {
                        mutableTrees.removeAt(j)
                    }

                    GeneralName.ConstraintResult.SAME_TYPE -> {
                        j++
                    }
                }
            }

            if (removeCurrent) {
                mutableTrees.removeAt(i)
            } else {
                i++
            }
        }

        trees = mutableTrees
        return GeneralSubtrees(mutableTrees)
    }

    @ExperimentalPkiApi
    fun unionWith(other: GeneralSubtrees) {
        (trees as MutableList).addAll(other.trees)
        val _ = minimize()
    }

    /**
     * Creates Subtree containing widest name of that type
     */
    private fun createWidestSubtree(name: GeneralName): GeneralSubtree {
        return try {
            val newName: GeneralName = when (name) {
                is RFC822Name -> RFC822Name.fromAsn1Representation(X509GeneralName.Rfc822(""))
                is DNSName -> DNSName.fromAsn1Representation(X509GeneralName.Dns(""))
                is X400AddressName -> X400AddressName(Asn1.Sequence { })
                is DirectoryName -> DirectoryName(X500Name(emptyList(), false))
                is UriName -> UriName.fromAsn1Representation(X509GeneralName.UniformResourceIdentifier("."))
                is IPAddressName -> IPAddressName(address = IpAddress("0.0.0.0"))

                else -> throw IOException("Unsupported GeneralName type: $name")
            }
            GeneralSubtree(newName, Asn1Integer(0), Asn1Integer(-1))
        } catch (e: IOException) {
            throw RuntimeException("Unexpected error: $e", e)
        }
    }

    /**
     * Merges permitted NameConstraints
     */
    @ExperimentalPkiApi
    fun intersectAndReturnExclusions(other: GeneralSubtrees): GeneralSubtrees? {

        val newThis = mutableListOf<GeneralSubtree>()
        var newExcluded: MutableList<GeneralSubtree>? = null

        // Step 1: If this is empty, just add everything in other
        if (trees.isEmpty()) {
            (this.trees as MutableList).addAll(other.trees)
            return null
        }

        // Step 2: Minimize both
        val primary = this.minimize().trees.toMutableList()
        val secondary = other.minimize().trees

        var i = 0
        while (i < primary.size) {
            val thisEntry = primary[i].base
            var sameType = false
            var removed = false

            // Step 3a: check each against secondary
            for (candidateGS in secondary) {
                val candidate = candidateGS.base
                when (thisEntry.constrains(candidate)) {
                    GeneralName.ConstraintResult.NARROWS -> {
                        sameType = false
                        break
                    }
                    GeneralName.ConstraintResult.SAME_TYPE -> {
                        sameType = true
                        continue
                    }
                    GeneralName.ConstraintResult.MATCH,
                    GeneralName.ConstraintResult.WIDENS -> {
                        // remove thisEntry, add candidate to newThis
                        primary.removeAt(i)
                        newThis += candidateGS
                        sameType = false
                        removed = true
                        break
                    }
                    GeneralName.ConstraintResult.DIFF_TYPE -> continue
                }
            }

            // Step 3b: if sameType true → no overlap, must exclude widest
            if (!removed && sameType) {
                var intersectionFound = false
                for (altPrimary in primary) {
                    if (altPrimary.base::class == thisEntry::class) {
                        for (altSecondary in secondary) {
                            when (altPrimary.base.constrains(altSecondary.base)) {
                                GeneralName.ConstraintResult.MATCH,
                                GeneralName.ConstraintResult.WIDENS,
                                GeneralName.ConstraintResult.NARROWS -> {
                                    intersectionFound = true
                                    break
                                }
                                else -> {}
                            }
                        }
                    }
                    if (intersectionFound) break
                }

                if (!intersectionFound) {
                    if (newExcluded == null) newExcluded = mutableListOf()

                    if (thisEntry is DirectoryName) {
                        // for x500Name exclude actual subtree
                        if (newExcluded.none { it.base == primary[i].base }) {
                            newExcluded += primary[i]
                        }
                    } else {
                        val widest = createWidestSubtree(thisEntry)
                        if (newExcluded.none { it.base == widest.base }) {
                            newExcluded += widest
                        }
                    }
                }

                primary.removeAt(i)
                continue // don’t advance i since we removed
            }

            if (!removed) {
                i++
            }
        }

        // Step 4: add replacements
        primary += newThis

        // Step 5: add entries from secondary that have no type in primary
        for (entry in secondary) {
            val entryName = entry.base
            var diffType = false
            for ((thisEntry) in primary) {
                when (thisEntry.constrains(entryName)) {
                    GeneralName.ConstraintResult.DIFF_TYPE -> {
                        diffType = true
                        continue
                    }
                    GeneralName.ConstraintResult.NARROWS,
                    GeneralName.ConstraintResult.SAME_TYPE,
                    GeneralName.ConstraintResult.MATCH,
                    GeneralName.ConstraintResult.WIDENS -> {
                        diffType = false
                        break
                    }
                }
            }
            if (diffType) {
                primary += entry
            }
        }

        // Update this.trees
        (this.trees as MutableList).clear()
        (this.trees as MutableList).addAll(primary)

        // Step 6: return exclusions
        return newExcluded?.takeIf { it.isNotEmpty() }?.let { GeneralSubtrees(it) }
    }

    fun copy(): GeneralSubtrees = GeneralSubtrees(trees.toList())

}
