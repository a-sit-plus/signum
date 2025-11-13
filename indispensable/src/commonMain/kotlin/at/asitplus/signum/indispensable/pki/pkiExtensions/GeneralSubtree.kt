package at.asitplus.signum.indispensable.pki.pkiExtensions

import at.asitplus.cidre.IpAddress
import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1ExplicitlyTagged
import at.asitplus.signum.indispensable.asn1.Asn1Integer
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.decodeRethrowing
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.encoding.parse
import at.asitplus.signum.indispensable.pki.generalNames.DNSName
import at.asitplus.signum.indispensable.pki.generalNames.GeneralName
import at.asitplus.signum.indispensable.pki.generalNames.GeneralNameOption
import at.asitplus.signum.indispensable.pki.generalNames.IPAddressName
import at.asitplus.signum.indispensable.pki.generalNames.RFC822Name
import at.asitplus.signum.indispensable.pki.generalNames.UriName
import at.asitplus.signum.indispensable.pki.generalNames.X400AddressName
import at.asitplus.signum.indispensable.pki.generalNames.X500Name
import kotlinx.io.IOException


data class GeneralSubtree(
    val base: GeneralName,
    val minimum: Asn1Integer,
    val maximum: Asn1Integer? = null
) : Asn1Encodable<Asn1Sequence> {

    override fun encodeToTlv() = Asn1.Sequence {
        +base
        +minimum
        if (maximum != null) +maximum
    }

    companion object : Asn1Decodable<Asn1Sequence, GeneralSubtree> {
        override fun doDecode(src: Asn1Sequence): GeneralSubtree = src.decodeRethrowing { 
            val base = GeneralName.decodeFromTlv(next())
            var minimum = Asn1Integer(0)
            if (hasNext()) {
                minimum = Asn1Integer.decodeFromTlv(next().asPrimitive())
            }

            return if (!hasNext()) GeneralSubtree(
                base = base,
                minimum = minimum
            ) else GeneralSubtree(
                base,
                minimum,
                Asn1Integer.decodeFromTlv(next().asPrimitive())
            )
        }
    }
}

data class GeneralSubtrees(
    var trees: MutableList<GeneralSubtree>
) : Asn1Encodable<Asn1ExplicitlyTagged> {

    override fun encodeToTlv() = Asn1.ExplicitlyTagged(2uL) {
        trees.forEach { +it }
    }

    companion object : Asn1Decodable<Asn1ExplicitlyTagged, GeneralSubtrees> {
        override fun doDecode(src: Asn1ExplicitlyTagged): GeneralSubtrees = src.decodeRethrowing {
            val trees = buildList {
                while (hasNext()) {
                    val child = next().asSequence()
                    add(GeneralSubtree.decodeFromTlv(child))
                }
            }.toMutableList()
            return GeneralSubtrees(trees)
        }
    }

    /**
     * Removes all redundant entries
     */
    @OptIn(ExperimentalPkiApi::class)
    private fun minimize(): GeneralSubtrees {
        val mutableTrees = trees.toMutableList()

        var i = 0
        while (i < mutableTrees.size - 1) {
            val current = mutableTrees[i].base.name
            var removeCurrent = false

            var j = i + 1
            while (j < mutableTrees.size) {
                val subsequent = mutableTrees[j].base.name
                when (current.constrains(subsequent)) {
                    GeneralNameOption.ConstraintResult.DIFF_TYPE -> {
                        j++
                    }

                    GeneralNameOption.ConstraintResult.MATCH -> {
                        removeCurrent = true
                        break
                    }

                    GeneralNameOption.ConstraintResult.NARROWS -> {
                        removeCurrent = true
                        break
                    }

                    GeneralNameOption.ConstraintResult.WIDENS -> {
                        mutableTrees.removeAt(j)
                    }

                    GeneralNameOption.ConstraintResult.SAME_TYPE -> {
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
    private fun createWidestSubtree(name: GeneralNameOption): GeneralSubtree {
        return try {
            val newName = when (name.type) {
                GeneralNameOption.NameType.RFC822 -> GeneralName(RFC822Name(Asn1String.IA5(""), type = GeneralNameOption.NameType.RFC822))
                GeneralNameOption.NameType.DNS -> GeneralName(DNSName(Asn1String.IA5(""), true, GeneralNameOption.NameType.DNS))
                GeneralNameOption.NameType.X400 -> GeneralName(X400AddressName(Asn1Element.parse("".encodeToByteArray())))
                GeneralNameOption.NameType.DIRECTORY -> GeneralName(X500Name(emptyList(), false))
                GeneralNameOption.NameType.URI -> GeneralName(UriName(Asn1String.IA5("."), false, false))
                GeneralNameOption.NameType.IP -> GeneralName(IPAddressName(address = IpAddress("0.0.0.0")))

                else -> throw IOException("Unsupported GeneralNameOption type: ${name.type}")
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
            val thisEntry = primary[i].base.name
            var sameType = false
            var removed = false

            // Step 3a: check each against secondary
            for (candidateGS in secondary) {
                val candidate = candidateGS.base.name
                when (thisEntry.constrains(candidate)) {
                    GeneralNameOption.ConstraintResult.NARROWS -> {
                        sameType = false
                        break
                    }
                    GeneralNameOption.ConstraintResult.SAME_TYPE -> {
                        sameType = true
                        continue
                    }
                    GeneralNameOption.ConstraintResult.MATCH,
                    GeneralNameOption.ConstraintResult.WIDENS -> {
                        // remove thisEntry, add candidate to newThis
                        primary.removeAt(i)
                        newThis += candidateGS
                        sameType = false
                        removed = true
                        break
                    }
                    GeneralNameOption.ConstraintResult.DIFF_TYPE -> continue
                }
            }

            // Step 3b: if sameType true → no overlap, must exclude widest
            if (!removed && sameType) {
                var intersectionFound = false
                for (altPrimary in primary) {
                    if (altPrimary.base.name.type == thisEntry.type) {
                        for (altSecondary in secondary) {
                            when (altPrimary.base.name.constrains(altSecondary.base.name)) {
                                GeneralNameOption.ConstraintResult.MATCH,
                                GeneralNameOption.ConstraintResult.WIDENS,
                                GeneralNameOption.ConstraintResult.NARROWS -> {
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

                    if (thisEntry.type == GeneralNameOption.NameType.DIRECTORY) {
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
            val entryName = entry.base.name
            var diffType = false
            for (thisEntryGS in primary) {
                val thisEntry = thisEntryGS.base.name
                when (thisEntry.constrains(entryName)) {
                    GeneralNameOption.ConstraintResult.DIFF_TYPE -> {
                        diffType = true
                        continue
                    }
                    GeneralNameOption.ConstraintResult.NARROWS,
                    GeneralNameOption.ConstraintResult.SAME_TYPE,
                    GeneralNameOption.ConstraintResult.MATCH,
                    GeneralNameOption.ConstraintResult.WIDENS -> {
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

