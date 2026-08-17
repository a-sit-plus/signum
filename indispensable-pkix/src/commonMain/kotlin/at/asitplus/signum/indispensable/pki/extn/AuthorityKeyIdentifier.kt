package at.asitplus.signum.indispensable.pki.extn

import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.KnownOIDs
import at.asitplus.awesn1.authorityKeyIdentifier_2_5_29_35
import at.asitplus.awesn1.serialization.Asn1Tag
import at.asitplus.awesn1.serialization.DER
import at.asitplus.signum.indispensable.pki.CertificateExtension
import at.asitplus.signum.indispensable.pki.X509CertificateExtension
import at.asitplus.signum.indispensable.pki.GeneralName
import at.asitplus.signum.indispensable.pki.x500.GeneralNameListSerializer
import kotlinx.serialization.Serializable
import at.asitplus.awesn1.crypto.pki.X509CertificateExtension as Awesn1X509CertificateExtension

/**
 * Authority Key Identifier extension. RFC 5280 §4.2.1.1 — MUST be non-critical.
 */
class AuthorityKeyIdentifier internal constructor(
    asn1Representation: Awesn1X509CertificateExtension,
    val keyIdentifier: ByteArray?,
    val authorityCertIssuer: List<GeneralName> = emptyList<GeneralName>(),
    val authorityCertSerialNumber: ByteArray?
) : X509CertificateExtension(asn1Representation) {

    /** Builds an Authority Key Identifier extension programmatically. */
    constructor(
        keyIdentifier: ByteArray? = null,
        authorityCertIssuer: List<GeneralName> = emptyList(),
        authorityCertSerialNumber: Asn1Integer? = null,
        critical: Boolean = false,
    ) : this(
        Awesn1X509CertificateExtension(
            KnownOIDs.authorityKeyIdentifier_2_5_29_35,
            critical,
            DER.encodeToByteArray(
                AuthorityKeyIdentifierBody.serializer(),
                AuthorityKeyIdentifierBody(
                    keyIdentifier = keyIdentifier,
                    authorityCertIssuer = authorityCertIssuer.ifEmpty { null },
                    authorityCertSerialNumber = authorityCertSerialNumber,
                ),
            ),
        ),
        keyIdentifier,
        authorityCertIssuer,
        authorityCertSerialNumber?.encodeToTlv()?.content,
    )

    companion object : CertificateExtension.Descriptor {
        override val oid get() = KnownOIDs.authorityKeyIdentifier_2_5_29_35

        override fun fromAsn1Representation(src: Awesn1X509CertificateExtension): AuthorityKeyIdentifier {
            val body = DER.decodeFromByteArray(AuthorityKeyIdentifierBody.serializer(), src.value)
            return AuthorityKeyIdentifier(
                src,
                keyIdentifier = body.keyIdentifier,
                authorityCertIssuer = body.authorityCertIssuer ?: emptyList(),
                authorityCertSerialNumber = body.authorityCertSerialNumber?.encodeToTlv()?.content,
            )
        }
    }
}

/**
 * ```
 * AuthorityKeyIdentifier ::= SEQUENCE {
 *   keyIdentifier             [0] KeyIdentifier             OPTIONAL,   -- OCTET STRING
 *   authorityCertIssuer       [1] GeneralNames              OPTIONAL,   -- SEQUENCE OF GeneralName
 *   authorityCertSerialNumber [2] CertificateSerialNumber   OPTIONAL }  -- INTEGER
 * ```
 * All members are IMPLICIT context-tagged. `keyIdentifier` is a `ByteArray` (awesn1 encodes it as the
 * OCTET STRING); [1]/[2] infer their tags from the `List` / `Asn1Integer` descriptors. Shared by decode
 * and the programmatic constructor.
 */
@Serializable
private class AuthorityKeyIdentifierBody(
    @Asn1Tag(0u) val keyIdentifier: ByteArray? = null,
    @Asn1Tag(1u) @Serializable(with = GeneralNameListSerializer::class)
    val authorityCertIssuer: List<GeneralName>? = null,
    @Asn1Tag(2u) val authorityCertSerialNumber: Asn1Integer? = null,
)
