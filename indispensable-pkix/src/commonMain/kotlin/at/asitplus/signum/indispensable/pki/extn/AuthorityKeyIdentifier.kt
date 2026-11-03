package at.asitplus.signum.indispensable.pki.extn

import at.asitplus.awesn1.*
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.indispensable.SourceRepresentationStorage
import at.asitplus.signum.indispensable.pki.CertificateExtension
import at.asitplus.signum.indispensable.pki.GeneralName
import com.ionspin.kotlin.bignum.integer.BigInteger
import kotlinx.serialization.Serializable
import at.asitplus.awesn1.serialization.Asn1Tag
import at.asitplus.signum.indispensable.pki.x500.GeneralNameListSerializer

/**
 * Authority Key Identifier extension. RFC 5280 §4.2.1.1 — MUST be non-critical.
 */
data class AuthorityKeyIdentifier(
    val keyIdentifier: ByteArray? = null,
    val authorityCertIssuer: List<GeneralName> = emptyList(),
    val authorityCertSerialNumber: BigInteger? = null,
    override val critical: Boolean = false,
) : CertificateExtension {
    @SignumInternals override val sourceRepresentation = SourceRepresentationStorage()
    override val oid get() = Companion.oid

    companion object : Identifiable {
        override val oid get() = KnownOIDs.authorityKeyIdentifier_2_5_29_35
    }

    override fun equals(other: Any?): Boolean = other is AuthorityKeyIdentifier && critical == other.critical &&
            keyIdentifier.contentEquals(other.keyIdentifier) && authorityCertIssuer == other.authorityCertIssuer &&
            authorityCertSerialNumber == other.authorityCertSerialNumber
    override fun hashCode(): Int = 31 * (31 * (31 * keyIdentifier.contentHashCode() + authorityCertIssuer.hashCode()) + authorityCertSerialNumber.hashCode()) + critical.hashCode()
}

/**
 * ```
 * AuthorityKeyIdentifier ::= SEQUENCE {
 *   keyIdentifier             [0] KeyIdentifier             OPTIONAL,   -- OCTET STRING
 *   authorityCertIssuer       [1] GeneralNames              OPTIONAL,   -- SEQUENCE OF GeneralName
 *   authorityCertSerialNumber [2] CertificateSerialNumber   OPTIONAL }  -- INTEGER
 * ```
 * All members are IMPLICIT context-tagged. `keyIdentifier` is a `ByteArray` (awesn1 encodes it as the
 * OCTET STRING); [1]/[2] infer their tags from the `List` / `Asn1Integer` descriptors. Used by the ASN.1 provider for encoding and decoding.
 */
@Serializable
internal class AuthorityKeyIdentifierBody(
    @Asn1Tag(0u) val keyIdentifier: ByteArray? = null,
    @Asn1Tag(1u) @Serializable(with = GeneralNameListSerializer::class)
    val authorityCertIssuer: List<GeneralName>? = null,
    @Asn1Tag(2u) val authorityCertSerialNumber: Asn1Integer? = null,
)
