package at.asitplus.signum.indispensable.pki.extn

import at.asitplus.cidre.IpAddress
import at.asitplus.signum.indispensable.pki.ExperimentalPkiApi
import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.Asn1String
import at.asitplus.awesn1.TagClass
import at.asitplus.awesn1.encoding.parse
import at.asitplus.awesn1.serialization.Asn1Tag
import kotlinx.serialization.Serializable
import at.asitplus.signum.indispensable.pki.x500.DirectoryName
import at.asitplus.signum.indispensable.pki.x500.GeneralName
import at.asitplus.signum.indispensable.pki.x500.GeneralNameSerializer
import at.asitplus.signum.indispensable.pki.x500.IPAddressName
import at.asitplus.signum.indispensable.pki.x500.X400AddressName
import at.asitplus.signum.indispensable.pki.x500.X500Name
import kotlinx.io.IOException

private fun contextTag(value: ULong) = Asn1Element.Tag(value, constructed = false, TagClass.CONTEXT_SPECIFIC)


/**
 * ```
 * GeneralSubtree ::= SEQUENCE {
 *   base     GeneralName,
 *   minimum  [0] BaseDistance DEFAULT 0,
 *   maximum  [1] BaseDistance OPTIONAL }
 * BaseDistance ::= INTEGER (0..MAX)
 * ```
 * `minimum`/`maximum` are IMPLICIT context-tagged INTEGERs. The declarative [Asn1Tag]s let the DER format
 * match them by tag *class* + number — the previous hand-rolled decode keyed on the tag value alone and
 * would have accepted, e.g., a UNIVERSAL tag 0/1 in their place.
 */
@ConsistentCopyVisibility
@Serializable
data class GeneralSubtree private constructor(
    @Serializable(with = GeneralNameSerializer::class) val base: GeneralName,
    @Asn1Tag(0u) private val taggedMinimum: Asn1Integer? = null,
    @Asn1Tag(1u) private val taggedMaximum: Asn1Integer? = null,
) {
    /** Effective `minimum`, defaulting to 0 when absent per RFC 5280. */
    val minimum: Asn1Integer get() = taggedMinimum ?: Asn1Integer(0)

    /** `maximum`, or `null` when the subtree imposes no upper bound. */
    val maximum: Asn1Integer? get() = taggedMaximum

    companion object {
        // A factory (not a secondary constructor) because the tagged backing fields erase to the same
        // JVM signature as (base, minimum, maximum). Call sites keep using GeneralSubtree(...) unchanged.
        operator fun invoke(
            base: GeneralName,
            minimum: Asn1Integer = Asn1Integer(0),
            maximum: Asn1Integer? = null,
        ): GeneralSubtree = GeneralSubtree(base, minimum.takeIf { it != Asn1Integer(0) }, maximum)
    }
}

/**
 * A `GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree` plus the RFC 5280 name-constraint
 * merge/minimize logic. (De)serialization is handled at the containing [NameConstraints] as a
 * `List<GeneralSubtree>` under its `[0]`/`[1]` field, so this type carries no ASN.1 (de)coding of its own.
 */
data class GeneralSubtrees(
    var trees: MutableList<GeneralSubtree>
) {

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
        trees.addAll(other.trees)
        minimize()
    }

    /**
     * Creates Subtree containing widest name of that type
     */
    private fun createWidestSubtree(name: GeneralName): GeneralSubtree {
        return try {
            val newName: GeneralName = when (name.type) {
                GeneralName.NameType.RFC822 -> GeneralName.X509Representable.fromAsn1Representation(GeneralName.NameType.RFC822, Asn1String.IA5("").encodeToTlv() withImplicitTag contextTag(1u))
                GeneralName.NameType.DNS -> GeneralName.X509Representable.fromAsn1Representation(GeneralName.NameType.DNS, Asn1String.IA5("").encodeToTlv() withImplicitTag contextTag(2u))
                GeneralName.NameType.X400 -> X400AddressName(Asn1Element.parse("".encodeToByteArray()))
                GeneralName.NameType.DIRECTORY -> DirectoryName(X500Name(emptyList(), false))
                GeneralName.NameType.URI -> GeneralName.X509Representable.fromAsn1Representation(GeneralName.NameType.URI, Asn1String.IA5(".").encodeToTlv() withImplicitTag contextTag(6u))
                GeneralName.NameType.IP -> IPAddressName(address = IpAddress("0.0.0.0"))

                else -> throw IOException("Unsupported GeneralName type: ${name.type}")
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
        require(other.trees != null) { "other GeneralSubtrees must not be null" }

        val newThis = mutableListOf<GeneralSubtree>()
        var newExcluded: MutableList<GeneralSubtree>? = null

        // Step 1: If this is empty, just add everything in other
        if (trees.isEmpty()) {
            this.trees.addAll(other.trees)
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
                    if (altPrimary.base.type == thisEntry.type) {
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

                    if (thisEntry.type == GeneralName.NameType.DIRECTORY) {
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
            for (thisEntryGS in primary) {
                val thisEntry = thisEntryGS.base
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
                break
            }
            if (diffType) {
                primary += entry
            }
        }

        // Update this.trees
        this.trees.clear()
        this.trees.addAll(primary)

        // Step 6: return exclusions
        return newExcluded?.takeIf { it.isNotEmpty() }?.let { GeneralSubtrees(it) }
    }

}
