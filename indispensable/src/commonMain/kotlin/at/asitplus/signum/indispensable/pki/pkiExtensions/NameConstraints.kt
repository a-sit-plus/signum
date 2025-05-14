package at.asitplus.signum.indispensable.pki.pkiExtensions

import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.Asn1StructuralException
import at.asitplus.signum.indispensable.asn1.Asn1TagMismatchException
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.toBigInteger
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.X509CertificateExtension
import kotlinx.io.IOException

data class NameConstraints(
    var permitted: GeneralSubtrees? = null,
    var excluded: GeneralSubtrees? = null
) {
    private var hasMin: Boolean = false
    private var hasMax: Boolean = false
    private var minMaxValid: Boolean = false

    fun merge(newConstraints: NameConstraints?) {
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
                excluded!!.union(newExcluded)
            }
        }

        val newPermitted = newConstraints.permitted
        if (permitted == null) {
            if (newPermitted != null) {
                permitted = newPermitted.copy()
            }
        } else {
            if (newPermitted != null) {
                val toExclude = permitted!!.intersect(newPermitted)
                if (toExclude != null) {
                    if (excluded != null) {
                        excluded!!.union(toExclude)
                    } else {
                        excluded = toExclude.copy()
                    }
                }
            }
        }
    }

    private fun calcMinMax() {
        hasMin = false
        hasMax = false
        excluded?.trees?.forEach { subtree ->
            if (subtree.minimum.toBigInteger().intValue() != 0) hasMin = true
            if (subtree.maximum?.toBigInteger()?.intValue() != -1) hasMax = true
        }
        permitted?.trees?.forEach { subtree ->
            if (subtree.minimum.toBigInteger().intValue() != 0) hasMin = true
            if (subtree.maximum?.toBigInteger()?.intValue() != -1) hasMax = true
        }
        minMaxValid = true
    }

    fun verify(cert: X509Certificate): Boolean {

        if (!minMaxValid) {
            calcMinMax()
        }

        if (hasMin) {
            throw IOException("Non-zero minimum BaseDistance in name constraints not supported")
        }

        if (hasMax) {
            throw IOException("Maximum BaseDistance in name constraints not supported")
        }

        val subject = cert.tbsCertificate.subjectName

        if (subject.relativeDistinguishedNames.isNotEmpty()) {
            if (!verify(subject)) {
                return false
            }
        }

        // Extract Subject Alternative Names (SAN)
        val alternativeNames = mutableListOf<GeneralName>()
        val alternativeNameExtension = cert.tbsCertificate.subjectAlternativeNames
        if (alternativeNameExtension != null) {
            alternativeNameExtension.dnsNames?.forEach { alternativeNames.add(GeneralName(DNSName(Asn1String.IA5(it)))) }
            alternativeNameExtension.rfc822Names?.forEach { alternativeNames.add(GeneralName(RFC822Name(Asn1String.IA5(it)))) }
            alternativeNameExtension.uris?.forEach { alternativeNames.add(GeneralName(UriName(Asn1String.IA5(it)))) }
            alternativeNameExtension.directoryNames.forEach { alternativeNames.add(GeneralName(X500Name(it))) }
            alternativeNameExtension.x400Addresses.forEach { alternativeNames.add(GeneralName(X400AddressName(it))) }
            alternativeNameExtension.ipAddresses.forEach { alternativeNames.add(GeneralName(IPAddressName(it))) }
        }


        // If no IP/DNS in SAN, fallback to last CN in subject DN
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

        // Verify each altName against constraints
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
    if (value.tag != Asn1Element.Tag.OCTET_STRING) throw Asn1TagMismatchException(Asn1Element.Tag.OCTET_STRING, value.tag)

    val src = value.asEncapsulatingOctetString().children.firstOrNull() ?: return NameConstraints()

    if (src.tag != Asn1Element.Tag.SEQUENCE) throw Asn1TagMismatchException(Asn1Element.Tag.SEQUENCE, src.tag)
    val permitted = GeneralSubtrees.doDecode(src.asSequence().children[0].asExplicitlyTagged())
    val excluded = if (src.asSequence().children.size > 1) {
        GeneralSubtrees.doDecode(src.asSequence().children[1].asExplicitlyTagged())
    } else {
        null
    }

    return NameConstraints(permitted, excluded)
}

