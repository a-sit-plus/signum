package at.asitplus.signum.indispensable.pki.extn

import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.KnownOIDs
import at.asitplus.awesn1.basicConstraints_2_5_29_19
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.toInt
import at.asitplus.signum.indispensable.pki.CertificateExtension
import at.asitplus.signum.indispensable.pki.X509CertificateExtension
import kotlinx.serialization.Serializable
import at.asitplus.awesn1.crypto.pki.X509CertificateExtension as Awesn1X509CertificateExtension

/**
 * Basic Constraints Extension
 * RFC 5280: 4.2.1.9.
 * Defines whether the subject of the cert is a CA and how deep a cert path may exist through that CA.
 * A `null` [pathLenConstraint] on a CA means unbounded (encoded by omitting `pathLenConstraint`).
*/
class BasicConstraints internal constructor(
    asn1Representation: Awesn1X509CertificateExtension,
    val ca: Boolean,
    val pathLenConstraint: UInt?
) : X509CertificateExtension(asn1Representation) {

    /** Builds a Basic Constraints extension programmatically. Typically critical (RFC 5280 §4.2.1.9). */
    constructor(
        ca: Boolean,
        pathLenConstraint: UInt? = null,
        critical: Boolean = true,
    ) : this(
        Awesn1X509CertificateExtension(
            KnownOIDs.basicConstraints_2_5_29_19,
            critical,
            DER.encodeToByteArray(
                BasicConstraintsBody.serializer(),
                BasicConstraintsBody(
                    // DER: cA DEFAULT FALSE is omitted when false; pathLen only meaningful (and encoded) for a
                    // bounded CA — an unbounded CA (null / UInt.MAX_VALUE) omits it.
                    cA = if (ca) true else null,
                    pathLenConstraint = pathLenConstraint?.takeIf { it != UInt.MAX_VALUE }?.let { Asn1Integer(it) },
                ),
            ),
        ),
        ca,
        pathLenConstraint,
    )

    companion object : CertificateExtension.Descriptor {
        override val oid get() = KnownOIDs.basicConstraints_2_5_29_19

        override fun fromAsn1Representation(src: Awesn1X509CertificateExtension): BasicConstraints {
            val body = DER.decodeFromByteArray(BasicConstraintsBody.serializer(), src.value)
            val ca = body.cA ?: false
            val pathLenConstraint = body.pathLenConstraint?.toInt()?.toUInt()
                ?: if (ca) UInt.MAX_VALUE else null
            return BasicConstraints(src, ca, pathLenConstraint)
        }
    }
}

/**
 * ```
 * BasicConstraints ::= SEQUENCE {
 *   cA                BOOLEAN DEFAULT FALSE,
 *   pathLenConstraint INTEGER (0..MAX) OPTIONAL }
 * ```
 * Shared by decode and the programmatic constructor.
 */
@Serializable
private class BasicConstraintsBody(
    val cA: Boolean? = null,
    val pathLenConstraint: Asn1Integer? = null,
)
