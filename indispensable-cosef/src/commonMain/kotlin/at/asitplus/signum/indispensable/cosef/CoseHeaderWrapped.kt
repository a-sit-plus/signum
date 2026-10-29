package at.asitplus.signum.indispensable.cosef

import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.cbor.Cbor
import kotlinx.serialization.cbor.CborArray
import kotlinx.serialization.cbor.CborDecoder
import kotlinx.serialization.cbor.CborElement
import kotlinx.serialization.cbor.CborInteger
import kotlinx.serialization.cbor.CborMap
import kotlinx.serialization.cbor.CborNull
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.nullable
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.serializer

/**
 * An effective header [H] together with the labels carried in its unprotected bucket
 *
 * The buckets are kept as raw [CborMap]s, so parameters [H] does not model are neither lost nor rejected. [header]
 * is the strict union of both buckets decoded with the serializer of [H].
 */
@OptIn(ExperimentalSerializationApi::class)
class CoseHeaderWrapped<H : CoseHeaderBase> private constructor(
    /** The effective header: both buckets combined and decoded. */
    val header: H,
    internal val protectedHeader: CborMap,
    internal val unprotectedHeader: CborMap,
) {

    /** Labels carried in the unprotected bucket. */
    val unprotectedLabels: Set<CborElement> = unprotectedHeader.keys

    /** Labels listed in `crit` (label 2), which the application must understand */
    val criticalLabels: List<CborElement> = (protectedHeader[LABEL_CRIT] as? CborArray)?.toList().orEmpty()

    /** The protected bucket encoded for transmission, zero-length when empty */
    internal val plainProtectedHeader: ByteArray get() = encodeProtectedBucket(protectedHeader)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CoseHeaderWrapped<*>) return false
        return header == other.header && unprotectedLabels == other.unprotectedLabels
    }

    override fun hashCode(): Int = 31 * header.hashCode() + unprotectedLabels.hashCode()

    override fun toString(): String = "CoseHeaderWrapped(header=$header, unprotectedLabels=$unprotectedLabels)"

    companion object {

        /** Splits [header] into buckets: labels in [unprotectedLabels] go unprotected, all others protected. */
        operator fun <H : CoseHeaderBase> invoke(
            header: H,
            serializer: KSerializer<H>,
            unprotectedLabels: Set<CborElement> = emptySet(),
            serialFormat: Cbor = coseCompliantSerializer,
        ): CoseHeaderWrapped<H> {
            val encoded = serialFormat.encodeToCborElement(serializer, header) as? CborMap
                ?: throw IllegalArgumentException("A COSE header must be encoded as a CBOR map")
            val protectedHeader = CborMap(encoded.filterKeys { it !in unprotectedLabels })
            val unprotectedHeader = CborMap(encoded.filterKeys { it in unprotectedLabels })
            requireValidBuckets(protectedHeader, unprotectedHeader)
            return CoseHeaderWrapped(header, protectedHeader, unprotectedHeader)
        }

        /** Creates a wrapper while [H] is still reified at the call site. */
        inline operator fun <reified H : CoseHeaderBase> invoke(
            header: H,
            unprotectedLabels: Set<CborElement> = emptySet(),
            serialFormat: Cbor = coseCompliantSerializer,
        ): CoseHeaderWrapped<H> =
            invoke(header, serialFormat.serializersModule.serializer(), unprotectedLabels, serialFormat)

        /** Validates both buckets and decodes their strict union with [serializer]; unknown labels are ignored. */
        fun <H : CoseHeaderBase> fromBuckets(
            serializer: KSerializer<H>,
            protectedHeader: CborMap,
            unprotectedHeader: CborMap,
            serialFormat: Cbor = coseCompliantSerializer,
        ): CoseHeaderWrapped<H> {
            requireValidBuckets(protectedHeader, unprotectedHeader)
            val header = serialFormat.decodeFromCborElement(serializer, CborMap(protectedHeader + unprotectedHeader))
            return CoseHeaderWrapped(header, protectedHeader, unprotectedHeader)
        }

        /** Decodes both buckets while [H] is still reified at the call site. */
        inline fun <reified H : CoseHeaderBase> fromBuckets(
            protectedHeader: CborMap,
            unprotectedHeader: CborMap,
            serialFormat: Cbor = coseCompliantSerializer,
        ): CoseHeaderWrapped<H> =
            fromBuckets(serialFormat.serializersModule.serializer(), protectedHeader, unprotectedHeader, serialFormat)
    }
}

@OptIn(ExperimentalSerializationApi::class)
private val LABEL_CRIT: CborElement = CborInteger(2)

@OptIn(ExperimentalSerializationApi::class)
internal val EMPTY_BUCKET: CborMap = CborMap(emptyMap<CborElement, CborElement>())

/** RFC 9052 §3 for every header model: no label in both buckets; `crit` only protected, as a non-empty array. */
@OptIn(ExperimentalSerializationApi::class)
internal fun requireValidBuckets(protectedHeader: CborMap, unprotectedHeader: CborMap) {
    val duplicates = protectedHeader.keys intersect unprotectedHeader.keys
    require(duplicates.isEmpty()) {
        "Header parameters $duplicates must not occur in both protected and unprotected header"
    }
    require(LABEL_CRIT !in unprotectedHeader) { "crit must be placed in the protected header" }
    protectedHeader[LABEL_CRIT]?.let {
        require(it is CborArray && it.isNotEmpty()) { "crit must be a non-empty array of labels" }
    }
}

/** Encodes a [CoseHeader] into a bucket. */
@OptIn(ExperimentalSerializationApi::class)
internal fun CoseHeader.toBucket(): CborMap =
    coseCompliantSerializer.encodeToCborElement(CoseHeader.serializer(), this) as CborMap

/** Wraps two [CoseHeader]s, one per bucket, for the [CoseHeader]-based builders. */
internal fun wrapCoseHeaders(protectedHeader: CoseHeader, unprotectedHeader: CoseHeader?): CoseHeaderWrapped<CoseHeader> =
    CoseHeaderWrapped.fromBuckets(
        CoseHeader.serializer(),
        protectedHeader.toBucket(),
        unprotectedHeader?.toBucket() ?: EMPTY_BUCKET,
    )

/** A zero-length protected header is an empty bucket. */
@OptIn(ExperimentalSerializationApi::class)
internal fun decodeProtectedBucket(plainProtectedHeader: ByteArray): CborMap =
    if (plainProtectedHeader.isEmpty()) EMPTY_BUCKET
    else coseCompliantSerializer.decodeFromByteArray(CborMap.serializer(), plainProtectedHeader)

/** An empty bucket is transmitted as a zero-length byte string. */
@OptIn(ExperimentalSerializationApi::class)
internal fun encodeProtectedBucket(protectedHeader: CborMap): ByteArray =
    if (protectedHeader.isEmpty()) byteArrayOf()
    else coseCompliantSerializer.encodeToByteArray(CborMap.serializer(), protectedHeader)

/** Always writes a map (RFC 9052 §3); reads the CBOR `null` written by the deprecated types as an empty bucket. */
@OptIn(ExperimentalSerializationApi::class)
internal object UnprotectedHeaderSerializer : KSerializer<CborMap> {

    override val descriptor: SerialDescriptor = CborMap.serializer().descriptor

    override fun serialize(encoder: Encoder, value: CborMap) =
        encoder.encodeSerializableValue(CborMap.serializer(), value)

    override fun deserialize(decoder: Decoder): CborMap {
        val cborDecoder = decoder as? CborDecoder
            ?: throw SerializationException("COSE structures can only be decoded from CBOR")
        return when (val element = cborDecoder.decodeCborElement()) {
            is CborMap -> element
            is CborNull -> EMPTY_BUCKET
            else -> throw SerializationException("Unprotected header must be a CBOR map, was ${element::class.simpleName}")
        }
    }
}

/**
 * Unprotected header of the deprecated [CoseBytes], as it was before the header rework: `null` is written as an
 * empty map, and both an empty map and CBOR `null` are read back as `null`.
 */
@OptIn(ExperimentalSerializationApi::class)
internal object LegacyUnprotectedHeaderSerializer : KSerializer<CoseHeader?> {

    override val descriptor: SerialDescriptor = CoseHeader.serializer().descriptor.nullable

    override fun serialize(encoder: Encoder, value: CoseHeader?) =
        encoder.encodeSerializableValue(CoseHeader.serializer(), value ?: CoseHeader())

    override fun deserialize(decoder: Decoder): CoseHeader? {
        val cborDecoder = decoder as? CborDecoder
            ?: throw SerializationException("COSE structures can only be decoded from CBOR")
        return when (val element = cborDecoder.decodeCborElement()) {
            is CborNull -> null
            is CborMap ->
                if (element.isEmpty()) null
                else coseCompliantSerializer.decodeFromCborElement(CoseHeader.serializer(), element)
            else -> throw SerializationException("Unprotected header must be a CBOR map, was ${element::class.simpleName}")
        }
    }
}