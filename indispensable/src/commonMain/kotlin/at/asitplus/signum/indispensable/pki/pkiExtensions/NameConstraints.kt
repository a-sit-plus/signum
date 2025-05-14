package at.asitplus.signum.indispensable.pki.pkiExtensions

import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1ExplicitlyTagged
import at.asitplus.signum.indispensable.asn1.Asn1Integer
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.Asn1StructuralException
import at.asitplus.signum.indispensable.asn1.Asn1TagMismatchException
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.pki.X509CertificateExtension

class NameConstraints(
    val permitted: GeneralSubtrees? = null,
    val excluded: GeneralSubtrees? = null
)

class GeneralSubtrees(
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
}

class GeneralSubtree(
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
            val base = GeneralName.doDecode(src.children[0])
            var minimum = Asn1Integer(0)
            if (src.children.size > 1) {
                minimum = Asn1Integer.doDecode(src.children[1].asPrimitive())
            }

            return if (src.children.size < 3) GeneralSubtree(
                base = base,
                minimum = minimum
            ) else GeneralSubtree(
                base,
                minimum,
                Asn1Integer.doDecode(src.children[2].asPrimitive())
            )
        }
    }
}


fun X509CertificateExtension.decodeNameConstraints(): NameConstraints {
    if (oid != KnownOIDs.nameConstraints_2_5_29_30) throw Asn1StructuralException(message = "This extension is not NameConstraints extension.")
    if (value.tag != Asn1Element.Tag.OCTET_STRING) throw Asn1TagMismatchException(
        Asn1Element.Tag.OCTET_STRING,
        value.tag
    )

    val src = value.asEncapsulatingOctetString().children.firstOrNull() ?: return NameConstraints()

    if (src.tag != Asn1Element.Tag.SEQUENCE) throw Asn1TagMismatchException(
        Asn1Element.Tag.SEQUENCE,
        src.tag
    )
    val permitted = GeneralSubtrees.doDecode(src.asSequence().children[0].asExplicitlyTagged())
    val excluded = if (src.asSequence().children.size > 1) {
        GeneralSubtrees.doDecode(src.asSequence().children[1].asExplicitlyTagged())
    } else {
        null
    }

    return NameConstraints(permitted)
}

