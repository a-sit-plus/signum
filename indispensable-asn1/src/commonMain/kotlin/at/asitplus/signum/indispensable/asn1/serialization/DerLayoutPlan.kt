package at.asitplus.signum.indispensable.asn1.serialization

import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.StructureKind

/**
 * Per-operation descriptor-plan context for DER serialization.
 *
 * This is intentionally ephemeral: created once per encode/decode call and
 * discarded afterwards. No global cache is used.
 */
internal class DerLayoutPlanContext(
    private val formatConfiguration: DerConfiguration,
) {
    private val primed = mutableSetOf<SerialDescriptor>()
    private val optionalLayoutChecked = mutableSetOf<SerialDescriptor>()
    private val bitStringCompatible = mutableMapOf<SerialDescriptor, Boolean>()
    private val nullAnalysis = mutableMapOf<NullAnalysisKey, Asn1NullEncodingAnalysis>()
    private val leadingTagAnalysis = mutableMapOf<LeadingTagKey, Asn1LeadingTagsResolution>()

    fun prime(descriptor: SerialDescriptor) {
        if (!primed.add(descriptor)) return

        bitStringCompatible[descriptor] = descriptor.isAsn1BitStringCompatibleDescriptor()
        // Warm default analyses used frequently in runtime paths.
        analyzeNullable(descriptor)
        possibleLeadingTags(descriptor)

        if (descriptor.kind is StructureKind.CLASS || descriptor.kind is StructureKind.OBJECT) {
            ensureNoAmbiguousOptionalLayout(descriptor)
        }

        for (i in 0 until descriptor.elementsCount) {
            prime(descriptor.getElementDescriptor(i))
        }
    }

    fun ensureNoAmbiguousOptionalLayout(descriptor: SerialDescriptor) {
        if (!optionalLayoutChecked.add(descriptor)) return
        descriptor.ensureNoAsn1AmbiguousOptionalLayout(
            formatExplicitNulls = formatConfiguration.explicitNulls,
        )
    }

    fun isBitStringCompatible(descriptor: SerialDescriptor): Boolean =
        bitStringCompatible.getOrPut(descriptor) {
            descriptor.isAsn1BitStringCompatibleDescriptor()
        }

    fun analyzeNullable(
        descriptor: SerialDescriptor,
        propertyAsn1Tag: Asn1Tag? = null,
        inlineAsn1Tag: Asn1Tag? = null,
        propertyAsBitString: Boolean = false,
        inlineAsBitString: Boolean = false,
    ): Asn1NullEncodingAnalysis {
        val key = NullAnalysisKey(
            descriptor = descriptor,
            propertyAsn1Tag = propertyAsn1Tag,
            inlineAsn1Tag = inlineAsn1Tag,
            propertyAsBitString = propertyAsBitString,
            inlineAsBitString = inlineAsBitString,
        )
        return nullAnalysis.getOrPut(key) {
            descriptor.analyzeAsn1NullableNullEncoding(
                propertyAsn1Tag = propertyAsn1Tag,
                inlineAsn1Tag = inlineAsn1Tag,
                propertyAsBitString = propertyAsBitString,
                inlineAsBitString = inlineAsBitString,
                formatExplicitNulls = formatConfiguration.explicitNulls,
            )
        }
    }

    fun possibleLeadingTags(
        descriptor: SerialDescriptor,
        propertyAsn1Tag: Asn1Tag? = null,
        inlineAsn1Tag: Asn1Tag? = null,
        propertyAsBitString: Boolean = false,
        inlineAsBitString: Boolean = false,
    ): Asn1LeadingTagsResolution {
        val key = LeadingTagKey(
            descriptor = descriptor,
            propertyAsn1Tag = propertyAsn1Tag,
            inlineAsn1Tag = inlineAsn1Tag,
            propertyAsBitString = propertyAsBitString,
            inlineAsBitString = inlineAsBitString,
        )
        return leadingTagAnalysis.getOrPut(key) {
            descriptor.possibleLeadingTagsForAsn1(
                propertyAsn1Tag = propertyAsn1Tag,
                inlineAsn1Tag = inlineAsn1Tag,
                propertyAsBitString = propertyAsBitString,
                inlineAsBitString = inlineAsBitString,
            )
        }
    }

    private data class NullAnalysisKey(
        val descriptor: SerialDescriptor,
        val propertyAsn1Tag: Asn1Tag?,
        val inlineAsn1Tag: Asn1Tag?,
        val propertyAsBitString: Boolean,
        val inlineAsBitString: Boolean,
    )

    private data class LeadingTagKey(
        val descriptor: SerialDescriptor,
        val propertyAsn1Tag: Asn1Tag?,
        val inlineAsn1Tag: Asn1Tag?,
        val propertyAsBitString: Boolean,
        val inlineAsBitString: Boolean,
    )
}

