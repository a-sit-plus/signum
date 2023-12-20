package at.asitplus.crypto.datatypes

import at.asitplus.crypto.datatypes.asn1.*
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

@Serializable(with = CryptoAlgorithmSerializer::class)
enum class CryptoAlgorithm(override val oid: ObjectIdentifier) : Asn1Encodable<Asn1Sequence>, Identifiable {

    // ECDSA with SHA-size
    ES256(KnownOIDs.ecdsaWithSHA256),
    ES384(KnownOIDs.ecdsaWithSHA384),
    ES512(KnownOIDs.ecdsaWithSHA512),

    // HMAC-size with SHA-size
    HS256(KnownOIDs.hmacWithSHA256),
    HS384(KnownOIDs.hmacWithSHA384),
    HS512(KnownOIDs.hmacWithSHA512),

    // RSASSA-PSS with SHA-size
    PS256(KnownOIDs.rsaPSS),
    PS384(KnownOIDs.rsaPSS),
    PS512(KnownOIDs.rsaPSS),

    // RSASSA-PKCS1-v1_5 with SHA-size
    RS256(KnownOIDs.sha256WithRSAEncryption),
    RS384(KnownOIDs.sha384WithRSAEncryption),
    RS512(KnownOIDs.sha512WithRSAEncryption),

    // RSASSA-PKCS1-v1_5 using SHA-1
    RS1(KnownOIDs.sha1WithRSAEncryption);

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
        RS256, RS384, RS512, RS1 -> asn1Sequence {
            append(oid)
            asn1null()
        }
    }

    companion object : Asn1Decodable<Asn1Sequence, CryptoAlgorithm> {

        @Throws(Asn1OidException::class)
        private fun fromOid(oid: ObjectIdentifier) = runCatching { entries.first { it.oid == oid } }.getOrElse {
            throw Asn1OidException("Unsupported OID: $oid", oid)
        }

        @Throws(Asn1Exception::class)
        override fun decodeFromTlv(src: Asn1Sequence): CryptoAlgorithm = runRethrowing {
            when (val oid = (src.nextChild() as Asn1Primitive).readOid()) {
                ES512.oid, ES384.oid, ES256.oid -> fromOid(oid)

                RS1.oid -> RS1
                RS256.oid, RS384.oid, RS512.oid,
                HS256.oid, HS384.oid, HS512.oid -> fromOid(oid).also {
                    val tag = src.nextChild().tag
                    if (tag != BERTags.NULL)
                        throw Asn1TagMismatchException(BERTags.NULL, tag, "RSA Params not allowed.")
                }

                PS256.oid, PS384.oid, PS512.oid -> parsePssParams(src)
                else -> throw Asn1Exception("Unsupported algorithm oid: $oid")
            }
        }

        @Throws(Asn1Exception::class)
        private fun parsePssParams(src: Asn1Sequence): CryptoAlgorithm = runRethrowing {
            val seq = src.nextChild() as Asn1Sequence
            val first = (seq.nextChild() as Asn1Tagged).verifyTag(0.toUByte()).single() as Asn1Sequence

            val sigAlg = (first.nextChild() as Asn1Primitive).readOid()
            val tag = first.nextChild().tag
            if (tag != BERTags.NULL)
                throw Asn1TagMismatchException(BERTags.NULL, tag, "PSS Params not supported yet")

            val second = (seq.nextChild() as Asn1Tagged).verifyTag(1.toUByte()).single() as Asn1Sequence
            val mgf = (second.nextChild() as Asn1Primitive).readOid()
            if (mgf != KnownOIDs.`pkcs1-MGF`) throw IllegalArgumentException("Illegal OID: $mgf")
            val inner = second.nextChild() as Asn1Sequence
            val innerHash = (inner.nextChild() as Asn1Primitive).readOid()
            if (innerHash != sigAlg) throw IllegalArgumentException("HashFunction mismatch! Expected: $sigAlg, is: $innerHash")

            if (inner.nextChild().tag != BERTags.NULL) throw IllegalArgumentException(
                "PSS Params not supported yet"
            )

            val last = (seq.nextChild() as Asn1Tagged).verifyTag(2.toUByte()).single() as Asn1Primitive
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

object CryptoAlgorithmSerializer : KSerializer<CryptoAlgorithm> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("CryptoAlgorithmSerializer", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: CryptoAlgorithm) {
        value.let { encoder.encodeString(it.name) }
    }

    override fun deserialize(decoder: Decoder): CryptoAlgorithm {
        val decoded = decoder.decodeString()
        return CryptoAlgorithm.entries.first { it.name == decoded }
    }
}