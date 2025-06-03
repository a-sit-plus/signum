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
            if (src.hasMoreChildren()) {
                minimum = Asn1Integer.doDecode(src.nextChild().asPrimitive())
            }

            return if (!src.hasMoreChildren()) GeneralSubtree(
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
    var trees: MutableList<GeneralSubtree>
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
                        j++
                    }

                    GeneralNameOption.ConstraintResult.MATCH -> {
                        removeCurrent = true
                        break
                    }

                    GeneralNameOption.ConstraintResult.NARROWS -> {
                        mutableTrees.removeAt(j)
                    }

                    GeneralNameOption.ConstraintResult.WIDENS -> {
                        removeCurrent = true
                        break
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

        return GeneralSubtrees(mutableTrees)
    }

    fun unionWith(other: GeneralSubtrees?) {
        other?.trees?.let { trees.addAll(it) }
        minimize()
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

    fun intersectWith(other: GeneralSubtrees): GeneralSubtrees? {
        if (other.trees.isEmpty()) return null

        val primary = this.minimize().trees.toMutableList()
        val secondary = other.minimize().trees
        val additions = mutableListOf<GeneralSubtree>()
        var exclusions: MutableList<GeneralSubtree>? = null

        var index = 0
        while (index < primary.size) {
            val currentName = primary[index].base.name
            var shouldRemove = false
            var hasOnlySameType = false
            var replacement: GeneralSubtree? = null

            for (candidate in secondary) {
                val candidateName = candidate.base.name
                when (currentName.constrains(candidateName)) {
                    GeneralNameOption.ConstraintResult.NARROWS -> {
                        shouldRemove = true
                        replacement = candidate
                        hasOnlySameType = false
                        break
                    }

                    GeneralNameOption.ConstraintResult.SAME_TYPE -> {
                        hasOnlySameType = true
                    }

                    GeneralNameOption.ConstraintResult.MATCH,
                    GeneralNameOption.ConstraintResult.WIDENS -> {
                        hasOnlySameType = false
                        break
                    }

                    else -> {} // Ignore DIFF_TYPE
                }
            }

            if (shouldRemove) {
                primary.removeAt(index)
                additions += replacement!!
                continue
            }

            if (hasOnlySameType) {
                var foundCompatible = false

                for (altPrimary in primary) {
                    val altName = altPrimary.base.name
                    if (altName.type != currentName.type) continue

                    for (altSecondary in secondary) {
                        val secName = altSecondary.base.name
                        when (altName.constrains(secName)) {
                            GeneralNameOption.ConstraintResult.MATCH,
                            GeneralNameOption.ConstraintResult.NARROWS,
                            GeneralNameOption.ConstraintResult.WIDENS -> {
                                foundCompatible = true
                                break
                            }

                            else -> {}
                        }
                    }
                    if (foundCompatible) break
                }

                if (!foundCompatible) {
                    if (exclusions == null) exclusions = mutableListOf()
                    val widest = createWidestSubtree(currentName)
                    if (exclusions.none { it.base == widest.base }) {
                        exclusions += widest
                    }
                    primary.removeAt(index)
                    continue
                }
            }

            index++
        }

        primary += additions

        for (entry in secondary) {
            val otherName = entry.base.name
            val typeExists = primary.any {
                when (it.base.name.constrains(otherName)) {
                    GeneralNameOption.ConstraintResult.DIFF_TYPE -> false
                    else -> true
                }
            }
            if (!typeExists) {
                primary += entry
            }
        }

        this.trees.clear()
        this.trees.addAll(primary)

        return exclusions?.takeIf { it.isNotEmpty() }?.let { GeneralSubtrees(it) }
    }
}

