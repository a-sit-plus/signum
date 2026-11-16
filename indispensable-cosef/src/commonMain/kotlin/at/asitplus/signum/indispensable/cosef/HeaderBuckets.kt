@file:OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)

package at.asitplus.signum.indispensable.cosef

import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import kotlinx.serialization.*
import kotlinx.serialization.cbor.Cbor
import kotlinx.serialization.cbor.CborArray
import kotlinx.serialization.cbor.CborLabel
import kotlinx.serialization.descriptors.*
import kotlinx.serialization.encoding.*

/** Tracks only modeled top-level labels at the serializer boundary; unknown skipped labels are outside this contract. */
internal class HeaderBucketSerializer<Header : CoseHeader>(
    private val delegate: KSerializer<Header>,
    private val labels: MutableSet<CoseHeaderLabel> = mutableSetOf(),
) : KSerializer<Header> {
    override val descriptor = delegate.descriptor
    init {
        require(descriptor.kind == StructureKind.CLASS || descriptor.kind == StructureKind.OBJECT) { "Headers must be map models" }
        require(descriptor.annotations.none { it is CborArray }) { "Headers must be maps" }
        val declared = (0 until descriptor.elementsCount).map { descriptor.label(it) }
        require(declared.distinct().size == declared.size) { "Duplicate modeled header labels" }
    }

    private fun record(index: Int) {
        require(labels.add(descriptor.label(index))) { "Duplicate modeled header label ${descriptor.label(index)}" }
    }

    override fun serialize(encoder: Encoder, value: Header) = delegate.serialize(object : Encoder by encoder {
        override fun beginStructure(descriptor: SerialDescriptor): CompositeEncoder {
            val parent = encoder.beginStructure(descriptor)
            return object : CompositeEncoder by parent {
                override fun encodeBooleanElement(descriptor: SerialDescriptor, index: Int, value: Boolean) { record(index); parent.encodeBooleanElement(descriptor, index, value) }
                override fun encodeByteElement(descriptor: SerialDescriptor, index: Int, value: Byte) { record(index); parent.encodeByteElement(descriptor, index, value) }
                override fun encodeShortElement(descriptor: SerialDescriptor, index: Int, value: Short) { record(index); parent.encodeShortElement(descriptor, index, value) }
                override fun encodeCharElement(descriptor: SerialDescriptor, index: Int, value: Char) { record(index); parent.encodeCharElement(descriptor, index, value) }
                override fun encodeIntElement(descriptor: SerialDescriptor, index: Int, value: Int) { record(index); parent.encodeIntElement(descriptor, index, value) }
                override fun encodeLongElement(descriptor: SerialDescriptor, index: Int, value: Long) { record(index); parent.encodeLongElement(descriptor, index, value) }
                override fun encodeFloatElement(descriptor: SerialDescriptor, index: Int, value: Float) { record(index); parent.encodeFloatElement(descriptor, index, value) }
                override fun encodeDoubleElement(descriptor: SerialDescriptor, index: Int, value: Double) { record(index); parent.encodeDoubleElement(descriptor, index, value) }
                override fun encodeStringElement(descriptor: SerialDescriptor, index: Int, value: String) { record(index); parent.encodeStringElement(descriptor, index, value) }
                override fun encodeInlineElement(descriptor: SerialDescriptor, index: Int): Encoder { record(index); return parent.encodeInlineElement(descriptor, index) }
                override fun <T> encodeSerializableElement(descriptor: SerialDescriptor, index: Int, serializer: SerializationStrategy<T>, value: T) { record(index); parent.encodeSerializableElement(descriptor, index, serializer, value) }
                override fun <T : Any> encodeNullableSerializableElement(descriptor: SerialDescriptor, index: Int, serializer: SerializationStrategy<T>, value: T?) { record(index); parent.encodeNullableSerializableElement(descriptor, index, serializer, value) }
            }
        }
    }, value)

    override fun deserialize(decoder: Decoder): Header = delegate.deserialize(object : Decoder by decoder {
        override fun beginStructure(descriptor: SerialDescriptor): CompositeDecoder {
            val parent = decoder.beginStructure(descriptor)
            return object : CompositeDecoder by parent {
                override fun decodeElementIndex(descriptor: SerialDescriptor): Int =
                    parent.decodeElementIndex(descriptor).also { if (it != CompositeDecoder.DECODE_DONE) record(it) }
            }
        }
    })
}

private fun SerialDescriptor.label(index: Int): CoseHeaderLabel =
    getElementAnnotations(index).filterIsInstance<CborLabel>().singleOrNull()?.let {
        require(it.label in Int.MIN_VALUE..Int.MAX_VALUE) { "Header label exceeds supported integer range" }
        CoseHeaderLabel.Numeric(it.label.toInt())
    } ?: CoseHeaderLabel.Text(getElementName(index))

internal data class DecodedHeader<Header : CoseHeader>(val header: Header, val labels: Set<CoseHeaderLabel>)

internal fun <Header : CoseHeader> decodeHeader(bytes: ByteArray, serializer: KSerializer<Header>, format: Cbor): DecodedHeader<Header> {
    val labels = mutableSetOf<CoseHeaderLabel>()
    // h'' is an empty protected map, not a CBOR document. Required application properties still fail correctly.
    val header = format.decodeFromByteArray(HeaderBucketSerializer(serializer, labels), if (bytes.isEmpty()) byteArrayOf(0xA0.toByte()) else bytes)
    return DecodedHeader(header, labels)
}

internal data class EncodedHeader<Header : CoseHeader>(val header: Header, val bytes: ByteArray, val labels: Set<CoseHeaderLabel>)

internal fun <Header : CoseHeader> encodeHeader(header: Header, serializer: KSerializer<Header>, protected: Boolean): EncodedHeader<Header> {
    val labels = mutableSetOf<CoseHeaderLabel>()
    val bytes = coseCompliantSerializer.encodeToByteArray(HeaderBucketSerializer(serializer, labels), header)
    val decoded = decodeHeader(bytes, serializer, coseCompliantSerializer)
    require(decoded.header.algorithm == header.algorithm && decoded.header.kid.contentEquals(header.kid) &&
            decoded.header.criticalHeaders == header.criticalHeaders) { "Header serializer changed authentication parameters" }
    return EncodedHeader(decoded.header, if (protected && bytes.contentEquals(byteArrayOf(0xA0.toByte()))) byteArrayOf() else bytes, labels)
}

internal fun validateBuckets(
    protected: CoseHeader,
    unprotected: CoseHeader,
    protectedLabels: Set<CoseHeaderLabel>,
    unprotectedLabels: Set<CoseHeaderLabel>,
) {
    for ((header, labels) in listOf(protected to protectedLabels, unprotected to unprotectedLabels)) {
        require(header.algorithm == null || CoseHeaderLabel.Numeric(1) in labels) { "Algorithm must be present on the wire" }
        require(header.kid == null || CoseHeaderLabel.Numeric(4) in labels) { "Key ID must be present on the wire" }
        require(header.criticalHeaders == null || CoseHeaderLabel.Numeric(2) in labels) { "crit must be present on the wire" }
    }
    require((protectedLabels intersect unprotectedLabels).isEmpty()) { "Header parameters must not occur in both buckets" }
    require(unprotected.criticalHeaders == null && CoseHeaderLabel.Numeric(2) !in unprotectedLabels) { "crit must be protected" }
    require((protected.iv ?: unprotected.iv) == null || (protected.partialIv ?: unprotected.partialIv) == null) { "IV and Partial IV are mutually exclusive" }
    protected.criticalHeaders?.let { critical ->
        require(critical.isNotEmpty() && critical.distinct().size == critical.size) { "crit must be nonempty and unique" }
        require(CoseHeaderLabel.Numeric(2) !in critical && protectedLabels.containsAll(critical)) { "crit must refer to present protected parameters" }
    }
}

/** Application must explicitly process every critical parameter before accepting or creating a message. */
internal fun processCritical(header: CoseHeader, process: (CoseHeaderLabel) -> Boolean) {
    header.criticalHeaders?.forEach { require(process(it)) { "Unprocessed critical parameter $it" } }
}
