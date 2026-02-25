package at.asitplus.signum.indispensable.asn1.serialization

import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.SerialDescriptor

/**
 * Explicit-tag modelling wrapper.
 *
 * This wrapper requires an effective implicit tag override resolving to
 * CONTEXT-SPECIFIC + CONSTRUCTED. Missing/invalid configuration is rejected
 * at runtime by the DER serializer/decoder.
 */
@Serializable
data class ExplicitlyTagged<T>(
    val value: T,
)

/**
 * OCTET STRING encapsulation wrapper.
 *
 * This is encoded as UNIVERSAL OCTET STRING with primitive form and the
 * encoded payload value bytes as content.
 */
@Serializable
@Asn1Tag(
    tagNumber = 4u,
    tagClass = Asn1TagClass.UNIVERSAL,
    constructed = Asn1ConstructedBit.PRIMITIVE,
)
data class OctetStringEncapsulated<T>(
    val value: T,
)

private const val ExplicitlyTaggedSerialName =
    "at.asitplus.signum.indispensable.asn1.serialization.ExplicitlyTagged"

internal fun SerialDescriptor.isAsn1ExplicitWrapperDescriptor(): Boolean =
    serialName.removeSuffix("?").substringBefore('<').let { rawName -> rawName == ExplicitlyTaggedSerialName }
