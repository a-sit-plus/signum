package at.asitplus.signum.indispensable.pki.pkiExtensions

import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1ExplicitlyTagged
import at.asitplus.signum.indispensable.asn1.Asn1Integer
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.Asn1TagMismatchException
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.encoding.parse
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
        override fun doDecode(src: Asn1Sequence): GeneralSubtree {
            val base = GeneralName.doDecode(src.nextChild())
            var minimum = Asn1Integer(0)
            if (src.children.size > 1) {
                minimum = Asn1Integer.doDecode(src.nextChild().asPrimitive())
            }

            return if (src.children.size < 3) GeneralSubtree(
                base = base,
                minimum = minimum
            ) else GeneralSubtree(
                base,
                minimum,
                Asn1Integer.doDecode(src.nextChild().asPrimitive())
            )
        }
    }
}

data class GeneralSubtrees(
    val trees: List<GeneralSubtree>
) : Asn1Encodable<Asn1ExplicitlyTagged> {
    override fun encodeToTlv() = Asn1.ExplicitlyTagged(2uL) {
        trees.forEach { +it }
    }

    companion object : Asn1Decodable<Asn1ExplicitlyTagged, GeneralSubtrees> {
        override fun doDecode(src: Asn1ExplicitlyTagged): GeneralSubtrees {
            val trees = emptyList<GeneralSubtree>().toMutableList()
            if (src.children.isNotEmpty()) {
                src.children.forEach {
                    if (it.tag != Asn1Element.Tag.SEQUENCE) throw Asn1TagMismatchException(
                        Asn1Element.Tag.SEQUENCE, it.tag
                    )
                    trees += GeneralSubtree.doDecode(it.asSequence())
                }
            }
            return GeneralSubtrees(trees)
        }
    }

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
                        // Not comparable; continue checking
                        j++
                    }

                    GeneralNameOption.ConstraintResult.MATCH -> {
                        // Duplicate found; mark current for removal
                        removeCurrent = true
                        break
                    }

                    GeneralNameOption.ConstraintResult.NARROWS -> {
                        // Subsequent is narrower; remove it
                        mutableTrees.removeAt(j)
                    }

                    GeneralNameOption.ConstraintResult.WIDENS -> {
                        // Current is narrower; mark it for removal
                        removeCurrent = true
                        break
                    }

                    GeneralNameOption.ConstraintResult.SAME_TYPE -> {
                        // Same type but not narrowing/widening; continue
                        j++
                    }
                }
            }

            if (removeCurrent) {
                mutableTrees.removeAt(i)
                // Do not increment i; new element is now at index i
            } else {
                i++
            }
        }

        return GeneralSubtrees(mutableTrees)
    }

    fun union(other: GeneralSubtrees?): GeneralSubtrees {
        if (other == null) return this

        val combinedTrees = trees.toMutableList()
        combinedTrees.addAll(other.trees)

        val minimized = GeneralSubtrees(combinedTrees).minimize()
        return minimized
    }

    private fun createWidestSubtree(name: GeneralNameOption): GeneralSubtree {
        return try {
            val newName = when (name.type) {
                GeneralNameOption.NameType.RFC822 -> GeneralName(RFC822Name(Asn1String.IA5("")))
                GeneralNameOption.NameType.DNS -> GeneralName(DNSName(Asn1String.IA5("")))
                GeneralNameOption.NameType.X400 -> GeneralName(X400AddressName(Asn1Element.parse("".encodeToByteArray())))
                GeneralNameOption.NameType.DIRECTORY -> GeneralName(X500Name(emptyList()))
                GeneralNameOption.NameType.URI -> GeneralName(UriName(Asn1String.IA5("")))
                GeneralNameOption.NameType.IP -> GeneralName(IPAddressName(ByteArray(0)))

                else -> throw IOException("Unsupported GeneralNameOption type: ${name.type}")
            }
            GeneralSubtree(newName, Asn1Integer(0), Asn1Integer(-1))
        } catch (e: IOException) {
            throw RuntimeException("Unexpected error: $e", e)
        }
    }

    fun intersect(other: GeneralSubtrees?): GeneralSubtrees? {
        requireNotNull(other) { "Other GeneralSubtrees must not be null" }

        val newThis = mutableListOf<GeneralSubtree>()
        var newExcluded: MutableList<GeneralSubtree>? = null

        val mutableThis = trees.toMutableList()

        // If this is empty, just return the other
        if (mutableThis.isEmpty()) {
            return other
        }

        // minimize for easier check
        val thisMinimized = GeneralSubtrees(mutableThis).minimize().trees.toMutableList()
        val otherMinimized = other.minimize().trees

        var i = 0
        while (i < thisMinimized.size) {
            val thisEntry = thisMinimized[i].base.name
            var sameType = false
            var removed = false

            // If the widest of this in other narrows thisEntry, remove thisEntry and add widest other to newtHIS
            // Check if there is a name of the same type, but don't MATCH, NARROWS or WIDENS
            for (j in otherMinimized.indices) {
                val otherEntry = otherMinimized[j].base.name
                when (thisEntry.constrains(otherEntry)) {
                    GeneralNameOption.ConstraintResult.NARROWS -> {
                        thisMinimized.removeAt(i)
                        newThis.add(otherMinimized[j])
                        removed = true
                        sameType = false
                        break
                    }

                    GeneralNameOption.ConstraintResult.SAME_TYPE -> {
                        sameType = true
                    }

                    GeneralNameOption.ConstraintResult.MATCH,
                    GeneralNameOption.ConstraintResult.WIDENS -> {
                        sameType = false
                        break
                    }

                    else -> continue
                }
            }

            if (!removed && sameType) {
                var intersection = false
                // Check if there are any entries in this and other with the same type that either
                // MATCH, NARROWS or WIDENS, and if not add widest subtree
                for (thisAltEntry in thisMinimized) {
                    if (thisAltEntry.base.name.type == thisEntry.type) {
                        for (otherAltEntry in otherMinimized) {
                            val constraintType =
                                thisAltEntry.base.name.constrains(otherAltEntry.base.name)
                            if (constraintType == GeneralNameOption.ConstraintResult.MATCH ||
                                constraintType == GeneralNameOption.ConstraintResult.WIDENS ||
                                constraintType == GeneralNameOption.ConstraintResult.NARROWS
                            ) {
                                intersection = true
                                break
                            }
                        }
                    }
                }

                if (!intersection) {
                    if (newExcluded == null) newExcluded = mutableListOf()
                    val widestSubtree = createWidestSubtree(thisEntry)
                    if (newExcluded.none { it == widestSubtree }) {
                        newExcluded.add(widestSubtree)
                    }
                }

                thisMinimized.removeAt(i)
                continue
            }

            if (!removed) i++
        }

        // Add all entries in newThis to this
        thisMinimized.addAll(newThis)

        // All all entries from other to this if the entry don't have any entry of the same type in this
        for (otherEntryGS in otherMinimized) {
            val otherEntry = otherEntryGS.base.name
            var sameTypeFound = false
            for (thisEntryGS in thisMinimized) {
                when (thisEntryGS.base.name.constrains(otherEntry)) {
                    GeneralNameOption.ConstraintResult.DIFF_TYPE -> continue
                    else -> {
                        sameTypeFound = true
                        break
                    }
                }
            }
            if (!sameTypeFound) {
                thisMinimized.add(otherEntryGS)
            }
        }

        return newExcluded?.let { GeneralSubtrees(it) }
    }
}

