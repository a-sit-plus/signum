package at.asitplus.signum.indispensable

import at.asitplus.catching
import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.encoding.Asn1.ExplicitlyTagged
import at.asitplus.signum.indispensable.asn1.encoding.Asn1.Null
import at.asitplus.signum.indispensable.asn1.encoding.decodeToInt
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

@Serializable(with = X509SignatureAlgorithmSerializer::class)
enum class X509SignatureAlgorithm(
    override val oid: ObjectIdentifier,
    val isEc: Boolean = false
) : Asn1Encodable<Asn1Sequence>, Identifiable, SpecializedSignatureAlgorithm {

    // ECDSA with SHA-size
    ES256(KnownOIDs.ecdsaWithSHA256, true),
    ES384(KnownOIDs.ecdsaWithSHA384, true),
    ES512(KnownOIDs.ecdsaWithSHA512, true),

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

    private fun encodePSSParams(bits: Int): Asn1Sequence =
        when (bits) {
            256 -> KnownOIDs.sha_256
            384 -> KnownOIDs.sha_384
            512 -> KnownOIDs.sha_512
            else -> TODO()
        }.let { shaOid ->
            Asn1.Sequence {
                +oid
                +Asn1.Sequence {
                    +ExplicitlyTagged(0u) {
                        +Asn1.Sequence {
                            +shaOid
                            +Null()
                        }
                    }
                    +ExplicitlyTagged(1u) {
                        +Asn1.Sequence {
                            +KnownOIDs.pkcs1_MGF
                            +Asn1.Sequence {
                                +shaOid
                                +Null()
                            }
                        }
                    }
                    +ExplicitlyTagged(2u) {
                        +Asn1.Int(bits / 8)
                    }
                }
            }
        }

    override fun encodeToTlv() = when (this) {
        ES256, ES384, ES512 -> Asn1.Sequence { +oid }

        PS256 -> encodePSSParams(256)

        PS384 -> encodePSSParams(384)

        PS512 -> encodePSSParams(512)

        RS256, RS384, RS512, RS1 -> Asn1.Sequence {
            +oid
            +Null()
        }
    }

    val digest: Digest
        get() = when (this) {
            RS1 -> Digest.SHA1
            ES256, PS256, RS256 -> Digest.SHA256
            ES384, PS384, RS384 -> Digest.SHA384
            ES512, PS512, RS512 -> Digest.SHA512
        }

    override val algorithm: SignatureAlgorithm
        get() = when (this) {
            ES256, ES384, ES512 -> SignatureAlgorithm.ECDSA(this.digest, null)
            PS256, PS384, PS512 -> SignatureAlgorithm.RSA(this.digest, RSAPadding.PSS)
            RS1, RS256, RS384, RS512 -> SignatureAlgorithm.RSA(this.digest, RSAPadding.PKCS1)
        }

    companion object : Asn1Decodable<Asn1Sequence, X509SignatureAlgorithm> {

        @Throws(Asn1OidException::class)
        private fun fromOid(oid: ObjectIdentifier) = catching { entries.first { it.oid == oid } }.getOrElse {
            throw Asn1OidException("Unsupported OID: $oid", oid)
        }

        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Sequence): X509SignatureAlgorithm = src.decodeRethrowing {
            when (val oid = next().asPrimitive().readOid()) {
                ES512.oid, ES384.oid, ES256.oid -> fromOid(oid)

                RS1.oid, RS256.oid, RS384.oid, RS512.oid -> fromOid(oid).also {
                    val tag = next().tag
                    if (tag != Asn1Element.Tag.NULL)
                        throw Asn1TagMismatchException(Asn1Element.Tag.NULL, tag, "RSA Params not allowed.")
                }

                PS256.oid, PS384.oid, PS512.oid -> parsePssParams(src)
                else -> throw Asn1Exception("Unsupported algorithm oid: $oid")
            }
        }

        @Throws(Asn1Exception::class)
        private fun parsePssParams(src: Asn1Sequence): X509SignatureAlgorithm = src.decodeRethrowing {
            val seqIterator = next().asSequence().iterator()
            val firstIterator = seqIterator.next().asExplicitlyTagged().verifyTag(0u).single().asSequence().iterator()

            val sigAlg = firstIterator.next().asPrimitive().readOid()
            val tag = firstIterator.next().tag
            if (tag != Asn1Element.Tag.NULL)
                throw Asn1TagMismatchException(Asn1Element.Tag.NULL, tag, "PSS Params not supported yet")

            val secondIterator = seqIterator.next().asExplicitlyTagged().verifyTag(1u).single().asSequence().iterator()
            val mgf = secondIterator.next().asPrimitive().readOid()
            if (mgf != KnownOIDs.pkcs1_MGF) throw IllegalArgumentException("Illegal OID: $mgf")
            val innerIterator = secondIterator.next().asSequence().iterator()
            val innerHash = innerIterator.next().asPrimitive().readOid()
            if (innerHash != sigAlg) throw IllegalArgumentException("HashFunction mismatch! Expected: $sigAlg, is: $innerHash")

            if (innerIterator.next().tag != Asn1Element.Tag.NULL) throw IllegalArgumentException(
                "PSS Params not supported yet"
            )

            val last = seqIterator.next().asExplicitlyTagged().verifyTag(2u).single().asPrimitive()
            val saltLen = last.decodeToInt()

            sigAlg.let {
                when (it) {
                    KnownOIDs.sha_256 -> PS256.also { if (saltLen != 256 / 8) throw IllegalArgumentException("Non-recommended salt length used: $saltLen") }
                    KnownOIDs.sha_384 -> PS384.also { if (saltLen != 384 / 8) throw IllegalArgumentException("Non-recommended salt length used: $saltLen") }
                    KnownOIDs.sha_512 -> PS512.also { if (saltLen != 512 / 8) throw IllegalArgumentException("Non-recommended salt length used: $saltLen") }

                    else -> throw IllegalArgumentException("Unsupported OID: $it")
                }
            }
        }

    }
}

/** Finds a X.509 signature algorithm matching this algorithm. Curve restrictions are not preserved. */
fun SignatureAlgorithm.toX509SignatureAlgorithm() = catching {
    when (this) {
        is SignatureAlgorithm.ECDSA -> when (this.digest) {
            Digest.SHA256 -> X509SignatureAlgorithm.ES256
            Digest.SHA384 -> X509SignatureAlgorithm.ES384
            Digest.SHA512 -> X509SignatureAlgorithm.ES512
            else -> throw IllegalArgumentException("Digest ${this.digest} is unsupported by X.509 EC")
        }

        is SignatureAlgorithm.RSA -> when (this.padding) {
            RSAPadding.PKCS1 -> when (this.digest) {
                Digest.SHA1 -> X509SignatureAlgorithm.RS1
                Digest.SHA256 -> X509SignatureAlgorithm.RS256
                Digest.SHA384 -> X509SignatureAlgorithm.RS384
                Digest.SHA512 -> X509SignatureAlgorithm.RS512
            }

            RSAPadding.PSS -> when (this.digest) {
                Digest.SHA256 -> X509SignatureAlgorithm.PS256
                Digest.SHA384 -> X509SignatureAlgorithm.PS384
                Digest.SHA512 -> X509SignatureAlgorithm.PS512
                else -> throw IllegalArgumentException("Digest ${this.digest} is unsupported by X.509 RSA-PSS")
            }
        }
    }
}

/** Finds a X.509 signature algorithm matching this algorithm. Curve restrictions are not preserved. */
fun SpecializedSignatureAlgorithm.toX509SignatureAlgorithm() =
    this.algorithm.toX509SignatureAlgorithm()

object X509SignatureAlgorithmSerializer : KSerializer<X509SignatureAlgorithm> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("X509SignatureAlgorithmSerializer", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: X509SignatureAlgorithm) {
        value.let { encoder.encodeString(it.name) }
    }

    override fun deserialize(decoder: Decoder): X509SignatureAlgorithm {
        val decoded = decoder.decodeString()
        return X509SignatureAlgorithm.entries.first { it.name == decoded }
    }
}