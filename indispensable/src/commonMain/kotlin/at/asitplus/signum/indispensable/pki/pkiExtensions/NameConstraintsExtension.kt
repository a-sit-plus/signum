package at.asitplus.signum.indispensable.pki.pkiExtensions

import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.X509CertificateExtension
import at.asitplus.signum.indispensable.pki.generalNames.DNSName
import at.asitplus.signum.indispensable.pki.generalNames.GeneralName
import at.asitplus.signum.indispensable.pki.generalNames.GeneralNameOption
import at.asitplus.signum.indispensable.pki.generalNames.IPAddressName
import at.asitplus.signum.indispensable.pki.generalNames.RFC822Name
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

    /** Indicates whether the NameConstraints extension contains only valid general names in both the permitted and excluded subtrees. */
    val isValid : Boolean by lazy {
        fun GeneralSubtree.isInvalid(): Boolean {
            val name = base.name
            if (name.isValid == false) return true
            if (name is IPAddressName && name.addressAndPrefix == null) return true
            return false
        }

        val allTrees = listOfNotNull(permitted?.trees, excluded?.trees).flatten()
        allTrees.none { it.isInvalid() }
    }

    constructor(
        base: X509CertificateExtension,
        permitted: GeneralSubtrees? = null,
        excluded: GeneralSubtrees? = null
    ) : this(base.oid, base.critical, base.value.asEncapsulatingOctetString(), permitted, excluded)

    companion object : Asn1Decodable<Asn1Sequence, X509CertificateExtension> {
        private val PERMITTED: ULong = 0u
        private val EXCLUDED: ULong = 1u

        override fun doDecode(src: Asn1Sequence): NameConstraintsExtension = src.decodeRethrowing {
            val base = decodeBase(src)

            if (base.oid != KnownOIDs.nameConstraints_2_5_29_30) throw Asn1StructuralException(message = "Expected NameConstraints extension (OID: ${KnownOIDs.nameConstraints_2_5_29_30}), but found OID: ${base.oid}")

            val inner = base.value.asEncapsulatingOctetString()
                .singleOrNull()
                ?.asSequence()
                ?: return NameConstraintsExtension(base)

            val (permitted, excluded) = inner.decodeRethrowing {
                if (inner.children.size > 2) throw Asn1StructuralException("Invalid NameConstraints extension found (>2 children): ${inner.toDerHexString()}")
                var permitted: GeneralSubtrees? = null
                var excluded: GeneralSubtrees? = null
                while (hasNext()) {
                    val child = next()
                    when (child.tag.tagValue) {
                        PERMITTED -> permitted = GeneralSubtrees.decodeFromTlv(child.asExplicitlyTagged())
                        EXCLUDED -> excluded = GeneralSubtrees.decodeFromTlv(child.asExplicitlyTagged())
                    }
                }
                permitted to excluded
            }
            return NameConstraintsExtension(base, permitted, excluded)
        }
    }

    @ExperimentalPkiApi
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
                val toExclude = permitted!!.intersectAndReturnExclusions(newPermitted)
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
    fun verify(cert: X509Certificate, isLeaf: Boolean = false): Boolean {
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
                    val str = (attr.value as? Asn1Primitive)?.let { Asn1String.decodeFromTlv(it) }?.value
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
                val cnValue = Asn1String.decodeFromTlv(cn)
                val isIp = runCatching { IPAddressName.fromString(cnValue.value) }.isSuccess
                val neededType = if (isIp) GeneralNameOption.NameType.IP else GeneralNameOption.NameType.DNS

                if (alternativeNames.none { it.name.type == neededType }) {
                    val generalName = if (isIp) IPAddressName.fromString(cnValue.value) else DNSName(Asn1String.IA5(cnValue.value))
                    alternativeNames.add(GeneralName(generalName))
                }
            } catch (_: Throwable) {
                // cn is not ip or dns
            }
        }

        for (alt in alternativeNames) {
            if (alt.name.isValid == false) throw Asn1Exception("Invalid alternative name")
            if (alt.name is IPAddressName && isLeaf && alt.name.addressAndPrefix != null) throw Asn1Exception("Leaf certificate must not contain an IPAddressName with a CIDRE range.")
            if (!verify(alt.name)) {
                return false
            }
        }

        return true
    }

    /**
     * verify that a name is consistent with both permitted and excluded subtree
     * */
    @OptIn(ExperimentalPkiApi::class)
    fun verify(name: GeneralNameOption?): Boolean {
        if (name == null) {
            throw IOException("name is null")
        }

        if (!excluded?.trees.isNullOrEmpty()) {
            for (generalSubtree in excluded!!.trees) {
                val excludedName = generalSubtree.base.name
                when (excludedName.constrains(name)) {
                    GeneralNameOption.ConstraintResult.MATCH,
                    GeneralNameOption.ConstraintResult.WIDENS -> return false
                    GeneralNameOption.ConstraintResult.DIFF_TYPE,
                    GeneralNameOption.ConstraintResult.NARROWS,
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
                    GeneralNameOption.ConstraintResult.WIDENS -> {
                        return true
                    }

                    GeneralNameOption.ConstraintResult.NARROWS,
                    GeneralNameOption.ConstraintResult.SAME_TYPE -> {
                        sameType = true
                        continue
                    }

                    else -> continue
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

