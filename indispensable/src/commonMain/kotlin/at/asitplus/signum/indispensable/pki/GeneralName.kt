package at.asitplus.signum.indispensable.pki

import at.asitplus.signum.Signum
import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.crypto.pki.X509GeneralName
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.Decodable
import at.asitplus.signum.indispensable.Encodable

/** An encoding-independent RFC 5280/C509 `GeneralName`. */
interface GeneralName : Encodable {

    /**
     * Describes a typed [GeneralName] `GeneralName` alternative and knows how to construct it from
     * its generic awesn1 [X509GeneralName] representation. Mirrors [CertificateExtension.Descriptor];
     * register custom alternatives via [Signum.register].
     */
    interface Descriptor<out T : GeneralName> : Decodable<T> {
        /** The CHOICE alternative this descriptor handles, e.g. [X509GeneralName.Tags.dnsName]. */
        val tag: Asn1Element.Tag
        fun fromAsn1Representation(src: X509GeneralName): T
    }


    companion object /*for extension functions and properties*/ {
        /**
         * Upgrades the generic awesn1 [src] name to a registered typed alternative (e.g. a validated
         * `DNSName` from `indispensable-pkix`) when a [Descriptor] is registered for its CHOICE tag,
         * falling back to a generic [BaseX509GeneralName] otherwise. Decoding failures of a typed
         * alternative also fall back to the generic representation rather than throwing.
         */
        fun fromAsn1Representation(src: X509GeneralName): GeneralName =
            Signum.generalNameDescriptorFor(src.tag)?.let { descriptor ->
                catchingUnwrapped { descriptor.fromAsn1Representation(src) }.getOrNull()
            } ?: BaseX509GeneralName(src)

        operator fun invoke(src: X509GeneralName): GeneralName = fromAsn1Representation(src)
    }


    enum class ConstraintResult {
        DIFF_TYPE,     // Different type, no constraint
        MATCH,         // Exact match
        NARROWS,       // Input narrows this name
        WIDENS,        // Input widens this name
        SAME_TYPE;     // Same type, but no match/narrow/widen
    }

    /**
     * Returns whether this name is valid:
     * - `true`: validation succeeded
     * - `false`: validation failed
     * - `null`: no validation implemented (the generic [GeneralName] never validates)
     */
    val isValid: Boolean? get() = null

    /**
     * Returns a copy of this name with `isValid` set per [validate]. Intended for variants that do
     * not implement validation (`isValid == null`), to mark them before constraint checks.
     */
    fun createValidatedCopy(validate: (GeneralName) -> Boolean): GeneralName
}

/** The context-specific [Asn1Element.Tag] of this awesn1 `GeneralName` CHOICE alternative. */
val X509GeneralName.tag: Asn1Element.Tag
    get() = when (this) {
        is X509GeneralName.Other -> X509GeneralName.Tags.otherName
        is X509GeneralName.Rfc822 -> X509GeneralName.Tags.rfc822Name
        is X509GeneralName.Dns -> X509GeneralName.Tags.dnsName
        is X509GeneralName.X400Address -> X509GeneralName.Tags.x400Address
        is X509GeneralName.Directory -> X509GeneralName.Tags.directoryName
        is X509GeneralName.EdiParty -> X509GeneralName.Tags.ediPartyName
        is X509GeneralName.UniformResourceIdentifier -> X509GeneralName.Tags.uniformResourceIdentifier
        is X509GeneralName.IpAddress -> X509GeneralName.Tags.ipAddress
        is X509GeneralName.RegisteredId -> X509GeneralName.Tags.registeredID
    }

/**
 * Generic, unvalidated [GeneralName] that simply wraps a raw [X509GeneralName]. Used as the
 * fallback when no typed [GeneralName.Descriptor] is registered for a CHOICE tag. `open` so
 * external modules may subclass it to inherit the wrapping plumbing.
 */
open class BaseX509GeneralName(
    model: X509GeneralName,
    override val isValid: Boolean? = null,
) : GeneralName {
    override val representations: Map<Encodable.Representation, Any> = mapOf(X509 to model)

    val tag: Asn1Element.Tag get() = asn1Representation.tag

    override fun equals(other: Any?): Boolean =
        other is GeneralName && asn1Representation == other.asn1Representation

    override fun hashCode(): Int = asn1Representation.hashCode()

    override fun toString(): String = "GeneralName($asn1Representation)"

    override fun createValidatedCopy(validate: (GeneralName) -> Boolean): GeneralName =
        BaseX509GeneralName(asn1Representation, validate(this))
}
