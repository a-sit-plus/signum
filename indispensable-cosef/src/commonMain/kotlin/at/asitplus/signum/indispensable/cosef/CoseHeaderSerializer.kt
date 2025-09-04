package at.asitplus.signum.indispensable.cosef

import at.asitplus.catching
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.CborLabel
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.encoding.decodeStructure
import kotlinx.serialization.encoding.encodeStructure

/**
 * Handles serialization of [CoseHeader], accounting for [CoseHeader.certificateChain], which may be an array OR a
 * byte string.
 */
@OptIn(ExperimentalSerializationApi::class)
object CoseHeaderSerializer : KSerializer<CoseHeader> {

    override val descriptor: SerialDescriptor = buildClassSerialDescriptor("CoseHeader") {
        element("alg", CoseAlgorithm.serializer().descriptor, listOf(CborLabel(1)))
        element("crit", String.serializer().descriptor, listOf(CborLabel(2)))
        element("content type", String.serializer().descriptor, listOf(CborLabel(3)))
        element("kid", ByteArraySerializer().descriptor, listOf(CborLabel(4), ByteString()))
        element("IV", ByteArraySerializer().descriptor, listOf(CborLabel(5), ByteString()))
        element("Partial IV", ByteArraySerializer().descriptor, listOf(CborLabel(6), ByteString()))
        element("x5chain", ListSerializer(ByteArraySerializer()).descriptor, listOf(CborLabel(33), ByteString()))
        element("typ", String.serializer().descriptor, listOf(CborLabel(16)))
    }

    override fun deserialize(decoder: Decoder): CoseHeader {
        val labels = mapOf<String, Long>(
            "alg" to 1,
            "crit" to 2,
            "content type" to 3,
            "kid" to 4,
            "IV" to 5,
            "Partial IV" to 6,
            "x5chain" to 33,
            "typ" to 16
        )

        var alg: CoseAlgorithm? = null
        var crit: String? = null
        var contentType: String? = null
        var kid: ByteArray? = null
        var iv: ByteArray? = null
        var partialIv: ByteArray? = null
        var x5chain: List<ByteArray>? = null
        var typ: String? = null

        decoder.decodeStructure(descriptor) {
            while (true) {
                val index = decodeElementIndex(descriptor)
                if (index == -1) break
                val label = descriptor.getElementAnnotations(index)
                    .filterIsInstance<CborLabel>().first().label
                when (label) {
                    labels["alg"] -> alg = decodeNullableSerializableElement(
                        CoseAlgorithmSerializer.descriptor,
                        index,
                        CoseAlgorithm.serializer()
                    )

                    labels["crit"] -> crit = decodeStringElement(String.serializer().descriptor, index)
                    labels["content type"] -> contentType = decodeStringElement(String.serializer().descriptor, index)
                    labels["kid"] -> kid = decodeNullableSerializableElement(
                        ByteArraySerializer().descriptor,
                        index,
                        ByteArraySerializer()
                    )

                    labels["IV"] -> iv = decodeNullableSerializableElement(
                        ByteArraySerializer().descriptor,
                        index,
                        ByteArraySerializer()
                    )

                    labels["Partial IV"] -> partialIv = decodeNullableSerializableElement(
                        ByteArraySerializer().descriptor,
                        index,
                        ByteArraySerializer()
                    )
                    // may be a list of byte array or a single byte array
                    labels["x5chain"] -> x5chain = catching {
                        decodeNullableSerializableElement(
                            ListSerializer(ByteArraySerializer()).descriptor,
                            index,
                            ListSerializer(ByteArraySerializer())
                        )
                    }.getOrElse {
                        listOf(
                            decodeSerializableElement(
                                ByteArraySerializer().descriptor,
                                index,
                                ByteArraySerializer()
                            )
                        )
                    }

                    labels["typ"] -> typ = decodeStringElement(String.serializer().descriptor, index)

                    else -> break
                }
            }
        }
        return CoseHeader(
            algorithm = alg,
            criticalHeaders = crit,
            contentType = contentType,
            kid = kid,
            iv = iv,
            partialIv = partialIv,
            certificateChain = x5chain,
            type = typ
        )
    }

    override fun serialize(encoder: Encoder, value: CoseHeader) {
        with(value) {
            encoder.encodeStructure(descriptor) {
                algorithm?.let {
                    encodeSerializableElement(
                        descriptor,
                        0,
                        CoseAlgorithmSerializer,
                        algorithm
                    )
                }
                criticalHeaders?.let {
                    encodeStringElement(
                        descriptor,
                        1,
                        criticalHeaders
                    )
                }
                contentType?.let {
                    encodeStringElement(
                        descriptor,
                        2,
                        contentType
                    )
                }
                kid?.let {
                    encodeSerializableElement(
                        descriptor,
                        3,
                        ByteArraySerializer(),
                        kid
                    )
                }
                iv?.let {
                    encodeSerializableElement(
                        descriptor,
                        4,
                        ByteArraySerializer(),
                        iv
                    )
                }
                partialIv?.let {
                    encodeSerializableElement(
                        descriptor,
                        5,
                        ByteArraySerializer(),
                        partialIv
                    )
                }
                certificateChain?.let {
                    if (it.size == 1) {
                        encodeSerializableElement(
                            descriptor,
                            6,
                            ByteArraySerializer(),
                            certificateChain.first()
                        )
                    } else {
                        encodeSerializableElement(
                            descriptor,
                            6,
                            ListSerializer(ByteArraySerializer()),
                            certificateChain
                        )
                    }
                }
                type?.let {
                    encodeStringElement(
                        descriptor,
                        7,
                        type
                    )
                }
            }
        }
    }
}

@OptIn(ExperimentalSerializationApi::class)
object ProtectedCoseHeaderSerializer : KSerializer<CoseHeader> {
    override val descriptor: SerialDescriptor = buildClassSerialDescriptor("ProtectedHeader")

    override fun serialize(encoder: Encoder, value: CoseHeader) {
        val headerBytes = coseCompliantSerializer.encodeToByteArray(CoseHeader.serializer(), value)
        // Empty map (0xA0) → h'' (zero-length bstr)
        val wrapped = if (headerBytes.size == 1 && headerBytes[0] == 0xA0.toByte()) {
            byteArrayOf()
        } else {
            headerBytes
        }

        encoder.encodeSerializableValue(ByteArraySerializer(), wrapped)
    }

    override fun deserialize(decoder: Decoder): CoseHeader {
        val raw = decoder.decodeSerializableValue(ByteArraySerializer())
        return if (raw.isEmpty()) {
            CoseHeader()
        } else {
            coseCompliantSerializer.decodeFromByteArray(CoseHeader.serializer(), raw)
        }
    }
}