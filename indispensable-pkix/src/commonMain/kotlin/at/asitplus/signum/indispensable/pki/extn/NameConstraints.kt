package at.asitplus.signum.indispensable.pki.extn

import at.asitplus.awesn1.*
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.indispensable.SourceRepresentationStorage
import at.asitplus.signum.indispensable.pki.CertificateExtension
import kotlinx.serialization.Serializable
import at.asitplus.awesn1.serialization.Asn1Tag
import at.asitplus.signum.indispensable.pki.*
import at.asitplus.signum.indispensable.pki.x500.*
import kotlinx.io.IOException

/**
 * Name Constraints Extension
 * This extension specifies permitted and excluded subtrees that require restrictions on names
 * included in certificates issued by a given CA. Applied to the subject DNs and subject ANs.
 * RFC 5280: 4.2.1.10.
 * */
data class NameConstraints(
    val permitted: GeneralSubtrees? = null,
    val excluded: GeneralSubtrees? = null,
    override val critical: Boolean = true,
) : CertificateExtension {
    @SignumInternals override val sourceRepresentation = SourceRepresentationStorage()
    override val oid get() = Companion.oid

    companion object : Identifiable {
        override val oid get() = KnownOIDs.nameConstraints_2_5_29_30
    }

    /** Indicates whether the NameConstraints extension contains only valid general names in both the permitted and excluded subtrees. */
    val isValid: Boolean by lazy {
        fun GeneralSubtree.isInvalid(): Boolean {
            // Known validation gap: minimum/maximum are decoded but not processed or rejected.
            // Critical constraints using them require handling when this name form occurs later:
            // https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.10
            val name = base
            if (name.isValid == false) return true
            if (name is IPAddressName && name.addressAndPrefix == null) return true
            return false
        }

        val allTrees = listOfNotNull(permitted?.trees, excluded?.trees).flatten()
        allTrees.none { it.isInvalid() }
    }

    /**
     * RFC 5280 6.1.4(g): intersect permitted subtrees, union excluded subtrees. Purely functional:
     * returns a new [NameConstraints]; neither [this] nor [newConstraints] is modified. Trust-store
     * data therefore survives validation runs untouched.
     */
    @ExperimentalPkiApi
    fun mergedWith(newConstraints: NameConstraints?): NameConstraints {
        if (newConstraints == null) return this

        val newExcluded = newConstraints.excluded
        val mergedExcluded = when {
            excluded == null -> newExcluded?.copy()
            newExcluded != null -> excluded.unionWith(newExcluded)
            else -> excluded
        }

        val newPermitted = newConstraints.permitted
        val (mergedPermitted, extraExclusions) = when {
            permitted == null -> newPermitted?.let { GeneralSubtrees(it.trees) to null } ?: (null to null)
            newPermitted != null -> {
                val (intersection, exclusions) = permitted.intersectWithExclusions(newPermitted)
                intersection to exclusions
            }
            else -> permitted to null
        }

        val finalExcluded = when {
            extraExclusions == null -> mergedExcluded
            mergedExcluded != null -> mergedExcluded.unionWith(extraExclusions)
            else -> extraExclusions
        }

        // Ensure the merged constraints do not leak state into the anchor: fresh instance every time
        return NameConstraints(mergedPermitted, finalExcluded, critical)
    }

    /**
     * Verify that a certificate follows these NameConstraints
     *  - subject name and AlternativeName is consistent with both permitted and excluded subtree
     * */
    fun verify(cert: Certificate, isLeaf: Boolean = false): Boolean {
        val subject = cert.tbsCertificate.subjectName

        if (subject.relativeDistinguishedNames.isNotEmpty()) {
            if (!verify(DirectoryName(subject))) {
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
                .filter { it.oid == AttributeTypeAndValue.Descriptor.OID.emailAddress }
                .mapNotNull { attr ->
                    val str =
                        ((attr as? at.asitplus.signum.indispensable.pki.AttributeTypeAndValue)?.value as? Asn1Primitive)?.let {
                            Asn1String.decodeFromTlv(it)
                        }?.value
                    str?.let {
                        runCatching {
                            RFC822Name(Asn1String.IA5(it))
                        }.getOrNull()
                    }
                }

            alternativeNames.addAll(fallbackEmails)
        }

        // RFC 5280 6.1.3(b)-(c) constrains the subject DN as directoryName and SANs by their own
        // name types. Do not reinterpret a CN (e.g. "Alice") as a DNS/IP SAN. Legacy TLS CN fallback
        // is application policy, outside basic path validation:
        // https://www.rfc-editor.org/rfc/rfc5280.html#section-6.1.3

        for (alt in alternativeNames) {
            val altName = alt
            if (altName.isValid == false) throw Asn1Exception("Invalid alternative name")
            if (altName is IPAddressName && isLeaf && altName.addressAndPrefix != null) throw Asn1Exception("Leaf certificate must not contain an IPAddressName with a CIDRE range.")
            if (!verify(alt)) {
                return false
            }
        }

        return true
    }

    /**
     * verify that a name is consistent with both permitted and excluded subtree
     * */
    @OptIn(ExperimentalPkiApi::class)
    fun verify(name: GeneralName?): Boolean {
        if (name == null) {
            throw IOException("name is null")
        }

        if (!excluded?.trees.isNullOrEmpty()) {
            for (generalSubtree in excluded!!.trees) {
                val excludedName = generalSubtree.base
                when (excludedName.constrains(name)) {
                    ConstraintResult.MATCH,
                    ConstraintResult.WIDENS -> return false

                    ConstraintResult.DIFF_TYPE,
                    ConstraintResult.NARROWS,
                    ConstraintResult.SAME_TYPE -> continue
                }
            }
        }

        if (!permitted?.trees.isNullOrEmpty()) {

            var sameType = false

            for (generalSubtree in permitted!!.trees) {
                val permittedName = generalSubtree.base
                when (permittedName.constrains(name)) {
                    ConstraintResult.MATCH,
                    ConstraintResult.WIDENS -> {
                        return true
                    }

                    ConstraintResult.NARROWS,
                    ConstraintResult.SAME_TYPE -> {
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

}

/**
 * ```
 * NameConstraints ::= SEQUENCE {
 *   permittedSubtrees [0] GeneralSubtrees OPTIONAL,
 *   excludedSubtrees  [1] GeneralSubtrees OPTIONAL }
 * ```
 * `GeneralSubtrees` is itself a `SEQUENCE OF GeneralSubtree`; the IMPLICIT `[0]`/`[1]` tags replace that
 * SEQUENCE tag, so each field is a `List<GeneralSubtree>` carrying the context tag directly. Shared by both
 * the ASN.1 provider for both encoding and decoding.
 */
@Serializable
internal class NameConstraintsBody(
    @Asn1Tag(0u) val permitted: List<X509GeneralSubtree>? = null,
    @Asn1Tag(1u) val excluded: List<X509GeneralSubtree>? = null,
)
