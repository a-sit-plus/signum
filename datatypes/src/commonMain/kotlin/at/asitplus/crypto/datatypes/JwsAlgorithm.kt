package at.asitplus.crypto.datatypes

import at.asitplus.crypto.datatypes.asn1.*
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder


/**
 * Since we support only JWS algorithms (with one exception), this class is called what it's called.
 */
@OptIn(ExperimentalUnsignedTypes::class)
@Serializable(with = JwsAlgorithmSerializer::class)
enum class JwsAlgorithm(val identifier: String, override val oid: ObjectIdentifier) : Asn1Encodable<Asn1Sequence>,
    Identifiable {

    ES256("ES256", KnownOIDs.ecdsaWithSHA256),
    ES384("ES384", KnownOIDs.ecdsaWithSHA384),
    ES512("ES512", KnownOIDs.ecdsaWithSHA512),

    HS256("HS256", KnownOIDs.hmacWithSHA256),
    HS384("HS384", KnownOIDs.hmacWithSHA384),
    HS512("HS512", KnownOIDs.hmacWithSHA512),

    PS256("PS256", KnownOIDs.rsaPSS),
    PS384("PS384", KnownOIDs.rsaPSS),
    PS512("PS512", KnownOIDs.rsaPSS),

    RS256("RS256", KnownOIDs.sha256WithRSAEncryption),
    RS384("RS384", KnownOIDs.sha384WithRSAEncryption),
    RS512("RS512", KnownOIDs.sha512WithRSAEncryption),

    /**
     * The one exception, which is not a valid JWS algorithm identifier
     */
    NON_JWS_SHA1_WITH_RSA("RS1", KnownOIDs.sha1WithRSAEncryption);

    /**
     * For `ESXXX` and `HSXXX` this is the length (in bytes) of the signature value obtained when using a certain signature algorithm.
     *
     * `null` for RSA-based signatures with length depending on the key size (i.e. `PSXXX`, `RSXXX`, and [NON_JWS_SHA1_WITH_RSA])
     *
     */
    val signatureValueLength: Int?
        get() = when (this) {
            ES256 -> 256 / 8 * 2
            ES384 -> 384 / 8 * 2
            ES512 -> 512 / 8 * 2
            HS256 -> 256 / 8
            HS384 -> 384 / 8
            HS512 -> 512 / 8
            else -> null
        }

    private fun encodePSSParams(bits: Int): Asn1Sequence {
        val shaOid = when (bits) {
            256 -> KnownOIDs.`sha-256`
            384 -> KnownOIDs.`sha-384`
            512 -> KnownOIDs.`sha-512`
            else -> TODO()
        }
        return asn1Sequence {
            append(oid)
            sequence {
                tagged(0.toUByte()) {
                    sequence {
                        append(shaOid)
                        asn1null()
                    }
                }
                tagged(1.toUByte()) {
                    sequence {
                        append(KnownOIDs.`pkcs1-MGF`)
                        sequence {
                            append(shaOid)
                            asn1null()
                        }
                    }
                }
                tagged(2.toUByte()) {
                    int(bits / 8)
                }
            }
        }
    }

    override fun encodeToTlv() = when (this) {
        ES256, ES384, ES512 -> asn1Sequence { append(oid) }

        PS256 -> encodePSSParams(256)

        PS384 -> encodePSSParams(384)

        PS512 -> encodePSSParams(512)

        HS256, HS384, HS512,
        RS256, RS384, RS512, NON_JWS_SHA1_WITH_RSA -> asn1Sequence {
            append(oid)
            asn1null()
        }
    }

    companion object : Asn1Decodable<Asn1Sequence, JwsAlgorithm> {

        private fun fromOid(oid: ObjectIdentifier) = entries.first { it.oid == oid }

        @Throws(Throwable::class)
        override fun decodeFromTlv(src: Asn1Sequence): JwsAlgorithm {
            return when (val oid = (src.nextChild() as Asn1Primitive).readOid()) {
                ES512.oid, ES384.oid, ES256.oid -> JwsAlgorithm.fromOid(oid)

                NON_JWS_SHA1_WITH_RSA.oid -> NON_JWS_SHA1_WITH_RSA
                RS256.oid, RS384.oid, RS512.oid,
                HS256.oid, HS384.oid, HS512.oid -> JwsAlgorithm.fromOid(oid).also {
                    if (src.nextChild().tag != BERTags.NULL) throw IllegalArgumentException("RSA Params not allowed")
                }

                PS256.oid, PS384.oid, PS512.oid -> parsePssParams(src)
                else -> throw IllegalArgumentException("Unsupported algorithm oid: $oid")
            }

        }


        private fun parsePssParams(src: Asn1Sequence): JwsAlgorithm {
            val seq = src.nextChild() as Asn1Sequence
            val first = (seq.nextChild() as Asn1Tagged).verify(0.toUByte()).single() as Asn1Sequence

            val sigAlg = (first.nextChild() as Asn1Primitive).readOid()
            if (first.nextChild().tag != BERTags.NULL) throw IllegalArgumentException(
                "PSS Params not supported yet"
            )

            val second = (seq.nextChild() as Asn1Tagged).verify(1.toUByte()).single() as Asn1Sequence
            val mgf = (second.nextChild() as Asn1Primitive).readOid()
            if (mgf != KnownOIDs.`pkcs1-MGF`) throw IllegalArgumentException("Illegal OID: $mgf")
            val inner = second.nextChild() as Asn1Sequence
            val innerHash = (inner.nextChild() as Asn1Primitive).readOid()
            if (innerHash != sigAlg) throw IllegalArgumentException("HashFunction mismatch! Expected: $sigAlg, is: $innerHash")

            if (inner.nextChild().tag != BERTags.NULL) throw IllegalArgumentException(
                "PSS Params not supported yet"
            )


            val last = (seq.nextChild() as Asn1Tagged).verify(2.toUByte()).single() as Asn1Primitive
            val saltLen = last.readInt()


            return sigAlg.let {
                when (it) {
                    KnownOIDs.`sha-256` -> PS256.also { if (saltLen != 256 / 8) throw IllegalArgumentException("Non-recommended salt length used: $saltLen") }
                    KnownOIDs.`sha-384` -> PS384.also { if (saltLen != 384 / 8) throw IllegalArgumentException("Non-recommended salt length used: $saltLen") }
                    KnownOIDs.`sha-512` -> PS512.also { if (saltLen != 512 / 8) throw IllegalArgumentException("Non-recommended salt length used: $saltLen") }

                    else -> throw IllegalArgumentException("Unsupported OID: $it")
                }
            }
        }
    }
}

object JwsAlgorithmSerializer : KSerializer<JwsAlgorithm> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("JwsAlgorithmSerializer", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: JwsAlgorithm) {
        value.let { encoder.encodeString(it.identifier) }
    }

    override fun deserialize(decoder: Decoder): JwsAlgorithm {
        val decoded = decoder.decodeString()
        return JwsAlgorithm.entries.first { it.identifier == decoded }
    }
}
