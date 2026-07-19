package at.asitplus.signum.indispensable.pki.extn

import at.asitplus.signum.indispensable.pki.ExperimentalPkiApi
import at.asitplus.awesn1.*
import at.asitplus.awesn1.encoding.parse
import at.asitplus.awesn1.serialization.Asn1Tag
import at.asitplus.awesn1.serialization.DER
import kotlinx.serialization.Serializable
import at.asitplus.signum.indispensable.pki.Certificate
import at.asitplus.signum.indispensable.pki.CertificateExtension
import at.asitplus.signum.indispensable.pki.X509CertificateExtension
import at.asitplus.signum.indispensable.pki.x500.DNSName
import at.asitplus.signum.indispensable.pki.x500.DirectoryName
import at.asitplus.signum.indispensable.pki.x500.GeneralName
import at.asitplus.signum.indispensable.pki.x500.IPAddressName
import at.asitplus.signum.indispensable.pki.x500.RFC822Name
import at.asitplus.signum.indispensable.pki.x500.X500Name
import at.asitplus.signum.indispensable.pki.x500.findMostSpecificCommonName
import kotlinx.io.IOException
import at.asitplus.awesn1.crypto.pki.X509CertificateExtension as Awesn1X509CertificateExtension

/**
 * Name Constraints Extension
 * This extension specifies permitted and excluded subtrees that require restrictions on names
 * included in certificates issued by a given CA. Applied to the subject DNs and subject ANs.
 * RFC 5280: 4.2.1.10.
 * */
class NameConstraints internal constructor(
    asn1Representation: Awesn1X509CertificateExtension,
    var permitted: GeneralSubtrees? = null,
    var excluded: GeneralSubtrees? = null
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
            DER.encodeToByteArray(
                NameConstraintsBody.serializer(),
                NameConstraintsBody(permitted?.trees, excluded?.trees),
            ),
        ),
        permitted,
        excluded,
    )

    /** Indicates whether the NameConstraints extension contains only valid general names in both the permitted and excluded subtrees. */
    val isValid : Boolean by lazy {
        fun GeneralSubtree.isInvalid(): Boolean {
            val name = base
            if (name.isValid == false) return true
            if (name is IPAddressName && name.addressAndPrefix == null) return true
            return false
        }

        val allTrees = listOfNotNull(permitted?.trees, excluded?.trees).flatten()
        allTrees.none { it.isInvalid() }
    }

    companion object : CertificateExtension.Descriptor {
        override val oid get() = KnownOIDs.nameConstraints_2_5_29_30

        override fun fromAsn1Representation(src: Awesn1X509CertificateExtension): NameConstraints {
            val body = runCatching {
                DER.decodeFromByteArray(NameConstraintsBody.serializer(), src.value)
            }.getOrNull() ?: return NameConstraints(src)
            return NameConstraints(
                src,
                permitted = body.permitted?.let { GeneralSubtrees(it.toMutableList()) },
                excluded = body.excluded?.let { GeneralSubtrees(it.toMutableList()) },
            )
        }
    }

    @ExperimentalPkiApi
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
                .filter { it.oid == KnownOIDs.emailAddress_1_2_840_113549_1_9_1 }
                .mapNotNull { attr ->
                    val str = ((attr as? at.asitplus.signum.indispensable.pki.AttributeTypeAndValue.X509Representable)?.value as? Asn1Primitive)?.let { Asn1String.decodeFromTlv(it) }?.value
                    str?.let {
                        runCatching {
                            RFC822Name(Asn1String.IA5(it))
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
                val neededType = if (isIp) GeneralName.NameType.IP else GeneralName.NameType.DNS

                if (alternativeNames.none { it.type == neededType }) {
                    val generalName = if (isIp) IPAddressName.fromString(cnValue.value) else DNSName(Asn1String.IA5(cnValue.value))
                    alternativeNames.add(generalName)
                }
            } catch (_: Throwable) {
                // cn is not ip or dns
            }
        }

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
private class NameConstraintsBody(
    @Asn1Tag(0u) val permitted: List<GeneralSubtree>? = null,
    @Asn1Tag(1u) val excluded: List<GeneralSubtree>? = null,
)

