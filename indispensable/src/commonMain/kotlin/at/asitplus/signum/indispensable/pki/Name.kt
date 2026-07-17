package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.crypto.pki.X500RelativeDistinguishedName
import at.asitplus.signum.indispensable.DerEncodable

/**
 * An [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280) `Name` (the issuer/subject
 * `RDNSequence`), modeled independently of any concrete encoding.
 *
 * The logical content — an ordered list of [RelativeDistinguishedName]s — is shared across
 * encodings. The DER/X.509 serialization is [X509Representable] (implemented by
 * [at.asitplus.signum.indispensable.pki.x500.X500Name]); a future C509/CBOR serialization
 * would add a sibling representation carrying the same [relativeDistinguishedNames]. This mirrors
 * the [CsrAttribute]/[AlternativeNames] pattern: the data classes stay encoding-agnostic, and the
 * X.509 specialization carries the awesn1 backing.
 */
interface Name {

    val relativeDistinguishedNames: List<RelativeDistinguishedName>

    /**
     * A [Name] that has a DER/X.509 representation, backed by awesn1: the `RDNSequence` as a list of
     * [X500RelativeDistinguishedName] (the [DerEncodable] serializable form).
     */
    interface X509Representable : Name, DerEncodable<List<X500RelativeDistinguishedName>>
}

internal fun Name.requireX509(): Name.X509Representable =
    this as? Name.X509Representable
        ?: throw Asn1Exception("Name has no X.509/DER representation")
