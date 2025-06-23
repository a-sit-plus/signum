package at.asitplus.signum.indispensable.pki.pkiExtensions

import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1EncapsulatingOctetString
import at.asitplus.signum.indispensable.asn1.Asn1Primitive
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.Asn1StructuralException
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.encoding.asAsn1String
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.X509CertificateExtension
import kotlinx.io.IOException

/**
 * Name Constraints Extension
 * This extension specifies permitted and excluded subtrees that require restrictions on names
 * included in certificates issued by a given CA. Applied to the subject DNs and subject ANs.
 * RFC 5280: 4.2.1.10.
 * */
class NameConstraintsExtension(
    oid: ObjectIdentifier,
    critical: Boolean,
    value: Asn1EncapsulatingOctetString,
    var permitted: GeneralSubtrees? = null,
    var excluded: GeneralSubtrees? = null
) : X509CertificateExtension(oid, critical, value) {

    constructor(
        base: X509CertificateExtension,
        permitted: GeneralSubtrees? = null,
        excluded: GeneralSubtrees? = null
    ) : this(base.oid, base.critical, base.value.asEncapsulatingOctetString(), permitted, excluded)

    companion object : Asn1Decodable<Asn1Sequence, X509CertificateExtension> {
        private val PERMITTED: ULong = 0u
        private val EXCLUDED: ULong = 1u

        override fun doDecode(src: Asn1Sequence): NameConstraintsExtension {
            val base = decodeBase(src)

            if (base.oid != KnownOIDs.nameConstraints_2_5_29_30) throw Asn1StructuralException(message = "This extension is not NameConstraints extension.")

            val inner = base.value.asEncapsulatingOctetString()
                .nextChildOrNull()
                ?.takeIf { it.tag == Asn1Element.Tag.SEQUENCE }
                ?.asSequence()
                ?: return NameConstraintsExtension(base)

            if (inner.children.size > 2) throw Asn1StructuralException("Invalid NameConstraints extension found (>2 children): ${inner.toDerHexString()}")

            var permitted: GeneralSubtrees? = null
            var excluded: GeneralSubtrees? = null
            while (inner.hasMoreChildren()) {
                val child = inner.nextChild()
                when (child.tag.tagValue) {
                    PERMITTED -> permitted = GeneralSubtrees.decodeFromTlv(child.asExplicitlyTagged())
                    EXCLUDED -> excluded = GeneralSubtrees.decodeFromTlv(child.asExplicitlyTagged())
                }
            }
            return NameConstraintsExtension(base, permitted, excluded)
        }
    }

    fun mergeWith(newConstraints: NameConstraintsExtension?) {
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

    /**
     * Verify that a certificate follows these NameConstraints
     *  - subject name and AlternativeName is consistent with both permitted and excluded subtree
     * */
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
            // RFC 5280 4.2.1.10
            // If constraints are specified for the RFC822Name, but the cert lacks a SAN,
            // the constraint must be enforced on the emailAddress attribute within the subject DN
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


        // If subjectAlternativeNames does not contain an IPAddressName or DNSName,
        // check whether the last CN in the subjectName can be used
        val cn = subject.findMostSpecificCommonName()?.value?.asPrimitive()
        if (cn != null) {
            try {
                val isIp = kotlin.runCatching { IPAddressName.decodeFromTlv(cn) }.isSuccess
                val neededType = if (isIp) GeneralNameOption.NameType.IP else GeneralNameOption.NameType.DNS

                if (alternativeNames.none { it.name.type == neededType }) {
                    val generalName = if (isIp) IPAddressName.decodeFromTlv(cn) else DNSName.decodeFromTlv(cn)
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

    /**
     * verify that a name is consistent with both permitted and excluded subtree
     * */
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

    fun copy(): NameConstraintsExtension {
        return NameConstraintsExtension(
            oid = this.oid,
            critical = this.critical,
            value = this.value.asEncapsulatingOctetString(),
            permitted = this.permitted,
            excluded = this.excluded
        )
    }
}

