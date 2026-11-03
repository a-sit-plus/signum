package at.asitplus.signum.indispensable.pki.extn

import at.asitplus.awesn1.*
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.indispensable.SourceRepresentationStorage
import at.asitplus.signum.indispensable.pki.CertificateExtension
import at.asitplus.signum.Signum
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlin.jvm.JvmInline
import kotlinx.serialization.Serializable

/**
 * Certificate Policies Extension
 * This extension specifies the rules for issuing the certificate and how it can be used.
 * RFC 5280: 4.2.1.4.
 * */
data class CertificatePolicies(
    val certificatePolicies: List<PolicyInformation>,
    override val critical: Boolean = false,
) : CertificateExtension {
    @SignumInternals override val sourceRepresentation = SourceRepresentationStorage()
    override val oid get() = Companion.oid

    companion object : Identifiable {
        override val oid get() = KnownOIDs.certificatePolicies_2_5_29_32
    }
}

/**
 * ```
 * PolicyInformation ::= SEQUENCE {
 *   policyIdentifier   CertPolicyId,
 *   policyQualifiers   SEQUENCE SIZE (1..MAX) OF PolicyQualifierInfo OPTIONAL }
 * ```
 */
@Serializable
data class PolicyInformation(
    override val oid: ObjectIdentifier,
    val policyQualifiers: List<PolicyQualifierInfo> = emptyList()
) : Identifiable

/**
 * ```
 * PolicyQualifierInfo ::= SEQUENCE {
 *   policyQualifierId   PolicyQualifierId,
 *   qualifier           ANY DEFINED BY policyQualifierId }
 * ```
 * The [qualifier] branch is a fixed CHOICE selected by [oid] (`id-qt-cps` / `id-qt-unotice`), so it is
 * (de)serialized by a small custom serializer that peeks the discriminator OID and dispatches to the
 * matching awesn1 serializer — the only permitted manual step, everything else stays kotlinx-serialization.
 */
@Serializable(with = PolicyQualifierInfo.Companion::class)
data class PolicyQualifierInfo(
    override val oid: ObjectIdentifier,
    val qualifier: Qualifier
) : Identifiable {

    companion object : KSerializer<PolicyQualifierInfo> {

        /** Wire shape: `SEQUENCE { OID, ANY }` — the qualifier is captured opaquely, then dispatched by OID. */
        @Serializable
        private class Wire(val oid: ObjectIdentifier, val qualifier: Asn1Element)

        override val descriptor: SerialDescriptor get() = Wire.serializer().descriptor

        override fun deserialize(decoder: Decoder): PolicyQualifierInfo {
            val wire = decoder.decodeSerializableValue(Wire.serializer())
            val qualifier: Qualifier = when (wire.oid) {
                KnownOIDs.cps -> Qualifier.CPSUri(Signum.Der.decodeFromTlv(Asn1String.IA5.serializer(), wire.qualifier))
                KnownOIDs.unotice -> Signum.Der.decodeFromTlv(Qualifier.UserNotice.serializer(), wire.qualifier)
                else -> throw SerializationException("Unsupported PolicyQualifierInfo OID: ${wire.oid}")
            }
            return PolicyQualifierInfo(wire.oid, qualifier)
        }

        override fun serialize(encoder: Encoder, value: PolicyQualifierInfo) {
            val qualifierElement: Asn1Element = when (val q = value.qualifier) {
                is Qualifier.CPSUri -> Signum.Der.encodeToTlv(Asn1String.IA5.serializer(), q.uri)
                is Qualifier.UserNotice -> Signum.Der.encodeToTlv(Qualifier.UserNotice.serializer(), q)
            }
            encoder.encodeSerializableValue(Wire.serializer(), Wire(value.oid, qualifierElement))
        }
    }
}

sealed interface Qualifier {

    data class CPSUri(val uri: Asn1String.IA5) : Qualifier

    /**
     * ```
     * UserNotice ::= SEQUENCE {
     *   noticeRef     NoticeReference OPTIONAL,
     *   explicitText  DisplayText     OPTIONAL }
     * ```
     * The two optional members are distinguished by their leading tag (a SEQUENCE vs. a string).
     */
    @Serializable
    data class UserNotice(
        val noticeRef: NoticeReference? = null,
        val explicitText: DisplayText? = null
    ) : Qualifier
}

/**
 * ```
 * NoticeReference ::= SEQUENCE {
 *   organization   DisplayText,
 *   noticeNumbers  SEQUENCE OF INTEGER }
 * ```
 */
@Serializable
data class NoticeReference(
    val organization: DisplayText,
    val noticeNumbers: List<Asn1Integer>
)

/**
 * ```
 * DisplayText ::= CHOICE {
 *   ia5String      IA5String,
 *   visibleString  VisibleString,
 *   bmpString      BMPString,
 *   utf8String     UTF8String }
 * ```
 * Modeled as a thin wrapper around [Asn1String], whose serializer round-trips the concrete string tag.
 * A value class (not a data class) so it encodes as the bare string, without a spurious SEQUENCE wrapper.
 */
@JvmInline
@Serializable
value class DisplayText(val value: Asn1String)
