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
data class Asn1Explicit<T>(
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
    tagNumber = 4,
    tagClass = Asn1TagClass.UNIVERSAL,
    constructed = Asn1ConstructedBit.PRIMITIVE,
)
data class Asn1OctetWrapped<T>(
    val value: T,
)

private const val Asn1ExplicitSerialName = "at.asitplus.signum.indispensable.asn1.serialization.Asn1Explicit"

internal fun SerialDescriptor.isAsn1ExplicitWrapperDescriptor(): Boolean =
    serialName.removeSuffix("?").substringBefore('<') == Asn1ExplicitSerialName
