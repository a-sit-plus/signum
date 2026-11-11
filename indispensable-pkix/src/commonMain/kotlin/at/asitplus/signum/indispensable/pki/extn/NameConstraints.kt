package at.asitplus.signum.indispensable.pki.extn

import at.asitplus.awesn1.*
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.indispensable.SourceRepresentationStorage
import at.asitplus.signum.indispensable.pki.CertificateExtension
import kotlinx.serialization.Serializable
import at.asitplus.awesn1.serialization.Asn1Tag

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
    internal class Asn1Representation(
        @Asn1Tag(0u) val permitted: List<GeneralSubtree.Asn1Representation>? = null,
        @Asn1Tag(1u) val excluded: List<GeneralSubtree.Asn1Representation>? = null,
    )
}
