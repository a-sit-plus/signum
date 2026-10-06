package at.asitplus.signum.indispensable.pki.extn

import at.asitplus.awesn1.*
import at.asitplus.awesn1.serialization.Asn1Tag
import kotlinx.serialization.Serializable
import at.asitplus.signum.indispensable.pki.Certificate
import at.asitplus.signum.indispensable.pki.CertificateExtension
import at.asitplus.signum.indispensable.pki.X509CertificateExtension
import at.asitplus.signum.indispensable.pki.AttributeTypeAndValue
import at.asitplus.signum.indispensable.pki.GeneralName
import at.asitplus.signum.indispensable.pki.Name
import at.asitplus.signum.indispensable.pki.X509GeneralSubtree
import at.asitplus.signum.indispensable.pki.fromAsn1Representation
import at.asitplus.signum.indispensable.pki.X500Name
import at.asitplus.signum.indispensable.pki.x500.DirectoryName
import at.asitplus.signum.indispensable.pki.x500.IPAddressName
import at.asitplus.signum.indispensable.pki.x500.RFC822Name
import at.asitplus.signum.indispensable.pki.x500.constrains
import at.asitplus.signum.Signum
import at.asitplus.signum.indispensable.pki.*
import at.asitplus.signum.indispensable.pki.x500.*
import kotlinx.io.IOException
import kotlinx.serialization.Serializable
import at.asitplus.awesn1.crypto.pki.X509CertificateExtension as Awesn1X509CertificateExtension

/**
 * Name Constraints Extension
 * This extension specifies permitted and excluded subtrees that require restrictions on names
 * included in certificates issued by a given CA. Applied to the subject DNs and subject ANs.
 * RFC 5280: 4.2.1.10.
 * */
class NameConstraints internal constructor(
    asn1Representation: Awesn1X509CertificateExtension,
    val permitted: GeneralSubtrees? = null,
    val excluded: GeneralSubtrees? = null
) : X509CertificateExtension(asn1Representation) {

    /**
     * Builds a Name Constraints extension programmatically from [permitted]/[excluded] subtrees.
     * RFC 5280 §4.2.1.10 requires this extension to be critical, hence [critical] defaults to `true`.
     */
    constructor(
        permitted: GeneralSubtrees? = null,
        excluded: GeneralSubtrees? = null,
        critical: Boolean = true,
    ) : this(
        Awesn1X509CertificateExtension(
            KnownOIDs.nameConstraints_2_5_29_30,
            critical,
            Signum.Der.encodeToByteArray(
                NameConstraintsBody.serializer(),
                NameConstraintsBody(
                    permitted?.trees?.map { it.asn1Representation },
                    excluded?.trees?.map { it.asn1Representation }),
            ),
        ),
        permitted,
        excluded,
    )

    /** Indicates whether the NameConstraints extension contains only valid general names in both the permitted and excluded subtrees. */
    val isValid: Boolean by lazy {
        fun GeneralSubtree.isInvalid(): Boolean {
            // Known validation gap: minimum/maximum are decoded but not processed or rejected.
            // Critical constraints using them require handling when this name form occurs later:
            // https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.10
            // PkixDerRegressionTest keeps active failing regressions for both fields.
            val name = base
            if (name.isValid == false) return true
            if (name is IPAddressName && name.addressAndPrefix == null) return true
            return false
        }

        val allTrees = listOfNotNull(permitted?.trees, excluded?.trees).flatten()
        allTrees.none { it.isInvalid() }
    }

    companion object : CertificateExtension.Descriptor<NameConstraints> {
        override val oid get() = KnownOIDs.nameConstraints_2_5_29_30

        override fun fromAsn1Representation(src: Awesn1X509CertificateExtension): NameConstraints {
            // Known validation gap: a failed decode below becomes empty constraints. For critical
            // extensions this must eventually reject, not silently waive the constraint (RFC 5280
            // 4.2). PkixDerRegressionTest pins this with an active failing regression.
            // https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2
            val body =
                Signum.Der.decodeFromByteArray(NameConstraintsBody.serializer(), src.value)
            return NameConstraints(
                src,
                permitted = body.permitted?.let {
                    GeneralSubtrees(it.map { subtree ->
                        GeneralSubtree.fromAsn1Representation(
                            subtree
                        )
                    })
                },
                excluded = body.excluded?.let {
                    GeneralSubtrees(it.map { subtree ->
                        GeneralSubtree.fromAsn1Representation(
                            subtree
                        )
                    })
                },
            )
        }
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
        return NameConstraints(asn1Representation, mergedPermitted, finalExcluded)
    }

    /**
     * Verify that a certificate follows these NameConstraints
     *  - subject name and AlternativeName is consistent with both permitted and excluded subtree
     * */
    fun verify(cert: Certificate, isLeaf: Boolean = false): Boolean {
        val subject = cert.tbsCertificate.subjectName

        if (subject.relativeDistinguishedNames.isNotEmpty()) {
            if (!verify(DirectoryName(subject as X500Name))) {
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
                    GeneralName.ConstraintResult.MATCH,
                    GeneralName.ConstraintResult.WIDENS -> return false

                    GeneralName.ConstraintResult.DIFF_TYPE,
                    GeneralName.ConstraintResult.NARROWS,
                    GeneralName.ConstraintResult.SAME_TYPE -> continue
                }
            }
        }

        if (!permitted?.trees.isNullOrEmpty()) {

            var sameType = false

            for (generalSubtree in permitted!!.trees) {
                val permittedName = generalSubtree.base
                when (permittedName.constrains(name)) {
                    GeneralName.ConstraintResult.MATCH,
                    GeneralName.ConstraintResult.WIDENS -> {
                        return true
                    }

                    GeneralName.ConstraintResult.NARROWS,
                    GeneralName.ConstraintResult.SAME_TYPE -> {
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

    fun copy(): NameConstraints =
        NameConstraints(asn1Representation, permitted, excluded)
}

/**
 * ```
 * NameConstraints ::= SEQUENCE {
 *   permittedSubtrees [0] GeneralSubtrees OPTIONAL,
 *   excludedSubtrees  [1] GeneralSubtrees OPTIONAL }
 * ```
 * `GeneralSubtrees` is itself a `SEQUENCE OF GeneralSubtree`; the IMPLICIT `[0]`/`[1]` tags replace that
 * SEQUENCE tag, so each field is a `List<GeneralSubtree>` carrying the context tag directly. Shared by both
 * [NameConstraints.fromAsn1Representation] (decode) and the programmatic [NameConstraints] constructor (encode).
 */
@Serializable
internal class NameConstraintsBody(
    @Asn1Tag(0u) val permitted: List<X509GeneralSubtree>? = null,
    @Asn1Tag(1u) val excluded: List<X509GeneralSubtree>? = null,
)

/**
 * The most specific (leaf-most) `commonName` (OID 2.5.4.3) attribute in this [Name]'s RDN sequence, or
 * `null` if it carries none. RFC 5280 orders the RDNSequence most-general-first, so the last CN wins.
 */
private fun Name.findMostSpecificCommonName(): AttributeTypeAndValue? =
    relativeDistinguishedNames.asReversed()
        .flatMap { it.attrsAndValues }
        .firstOrNull { it.oid == AttributeTypeAndValue.Descriptor.OID.commonName }
