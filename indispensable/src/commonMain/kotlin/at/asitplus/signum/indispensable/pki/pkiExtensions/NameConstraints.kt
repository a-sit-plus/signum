package at.asitplus.signum.indispensable.pki.pkiExtensions

import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Primitive
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.Asn1StructuralException
import at.asitplus.signum.indispensable.asn1.Asn1TagMismatchException
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.encoding.asAsn1String
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.X509CertificateExtension
import kotlinx.io.IOException

data class NameConstraints(
    var permitted: GeneralSubtrees? = null,
    var excluded: GeneralSubtrees? = null
) {
    companion object {
        val PERMITTED: ULong = 0u
        val EXCLUDED: ULong = 1u
    }

    fun mergeWith(newConstraints: NameConstraints?) {
        if (newConstraints == null) {
            return
        }

        val newExcluded = newConstraints.excluded
        if (excluded == null) {
            if (newExcluded != null) {
                excluded = newExcluded.copy()
            }
        } else {
            if (newExcluded != null) {
                excluded!!.unionWith(newExcluded)
            }
        }

        val newPermitted = newConstraints.permitted
        if (permitted == null) {
            if (newPermitted != null) {
                permitted = newPermitted.copy()
            }
        } else {
            if (newPermitted != null) {
                val toExclude = permitted!!.intersectWith(newPermitted)
                if (toExclude != null) {
                    if (excluded != null) {
                        excluded!!.unionWith(toExclude)
                    } else {
                        excluded = toExclude.copy()
                    }
                }
            }
        }
    }

    fun verify(cert: X509Certificate): Boolean {
        val subject = cert.tbsCertificate.subjectName

        if (subject.relativeDistinguishedNames.isNotEmpty()) {
            if (!verify(subject)) {
                return false
            }
        }

        val alternativeNames = mutableListOf<GeneralName>()
        val alternativeNameExtension = cert.tbsCertificate.subjectAlternativeNames
        alternativeNameExtension?.generalNames?.forEach { alternativeNames.add(it) }

        if (alternativeNames.isEmpty()) {
            val fallbackEmails = subject.relativeDistinguishedNames
                .flatMap { it.attrsAndValues }
                .filter { it.oid == KnownOIDs.emailAddress_1_2_840_113549_1_9_1 }
                .mapNotNull { attr ->
                    val str = (attr.value as? Asn1Primitive)?.asAsn1String()?.value
                    str?.let {
                        runCatching {
                            GeneralName(RFC822Name(Asn1String.IA5(it)))
                        }.getOrNull()
                    }
                }

            alternativeNames.addAll(fallbackEmails)
        }


        val cn = subject.findMostSpecificCommonName()?.value?.asPrimitive()
        if (cn != null) {
            try {
                val isIp = kotlin.runCatching { IPAddressName.doDecode(cn) }.isSuccess
                val neededType = if (isIp) GeneralNameOption.NameType.IP else GeneralNameOption.NameType.DNS

                if (alternativeNames.none { it.name.type == neededType }) {
                    val generalName = if (isIp) IPAddressName.doDecode(cn) else DNSName.doDecode(cn)
                    alternativeNames.add(GeneralName(generalName))
                }
            } catch (_: IOException) {
                // cn is not ip or dns
            }
        }

        for (alt in alternativeNames) {
            if (!verify(alt.name)) {
                return false
            }
        }

        return true
    }


    fun verify(name: GeneralNameOption?): Boolean {
        if (name == null) {
            throw IOException("name is null")
        }

        if (!excluded?.trees.isNullOrEmpty()) {
            for (generalSubtree in excluded!!.trees) {
                val excludedName = generalSubtree.base.name
                when (excludedName.constrains(name)) {
                    GeneralNameOption.ConstraintResult.MATCH,
                    GeneralNameOption.ConstraintResult.NARROWS -> return false
                    GeneralNameOption.ConstraintResult.DIFF_TYPE,
                    GeneralNameOption.ConstraintResult.WIDENS,
                    GeneralNameOption.ConstraintResult.SAME_TYPE -> continue
                }
            }
        }

        if (!permitted?.trees.isNullOrEmpty()) {
            var sameType = false

            for (generalSubtree in permitted!!.trees) {
                val permittedName = generalSubtree.base.name
                when (permittedName.constrains(name)) {
                    GeneralNameOption.ConstraintResult.MATCH,
                    GeneralNameOption.ConstraintResult.NARROWS -> return true
                    GeneralNameOption.ConstraintResult.DIFF_TYPE -> continue
                    GeneralNameOption.ConstraintResult.WIDENS,
                    GeneralNameOption.ConstraintResult.SAME_TYPE -> {
                        sameType = true
                        continue
                    }
                }
            }
            return !sameType
        }
        return true
    }
}

fun X509CertificateExtension.decodeNameConstraints(): NameConstraints {
    if (oid != KnownOIDs.nameConstraints_2_5_29_30) throw Asn1StructuralException(message = "This extension is not NameConstraints extension.")

    val src = value.asEncapsulatingOctetString().children.firstOrNull() ?: return NameConstraints()

    if (src.tag != Asn1Element.Tag.SEQUENCE) throw Asn1TagMismatchException(Asn1Element.Tag.SEQUENCE, src.tag)
    val genTrees = src.asSequence().children
    var permitted: GeneralSubtrees? = null
    var excluded: GeneralSubtrees? = null
    genTrees.forEach {
        if (it.tag.tagValue == NameConstraints.PERMITTED) permitted = GeneralSubtrees.doDecode(it.asExplicitlyTagged())
        if (it.tag.tagValue == NameConstraints.EXCLUDED) excluded = GeneralSubtrees.doDecode(it.asExplicitlyTagged())
    }
    return NameConstraints(permitted, excluded)
}

