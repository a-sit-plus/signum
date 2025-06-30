package at.asitplus.signum.indispensable

import at.asitplus.catching
import at.asitplus.catchingUnwrapped
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
sealed class X509SignatureAlgorithm(
    override val oid: ObjectIdentifier,
    open val name: String
) : Asn1Encodable<Asn1Sequence>, Identifiable, SpecializedSignatureAlgorithm {

    // ECDSA with SHA-size
    data class EC(override val oid: ObjectIdentifier, override val name: String) : X509SignatureAlgorithm(oid, name)

    // RSA
    data class RSA(override val oid: ObjectIdentifier, override val name: String, val pssBits: Int? = null) : X509SignatureAlgorithm(oid, name)

    data class Other(
        override val oid: ObjectIdentifier,
        val value: Asn1Sequence,
        override val name: String = "Unknown($oid)"
    ) : X509SignatureAlgorithm(oid, name)

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
        is EC -> Asn1.Sequence { +oid }

        is RSA -> pssBits?.let { encodePSSParams(it) } ?: Asn1.Sequence {
            +oid
            +Null()
        }

        is Other -> value
    }

    val digest: Digest
        get() = when (this) {
            RS1 -> Digest.SHA1
            ES256, PS256, RS256 -> Digest.SHA256
            ES384, PS384, RS384 -> Digest.SHA384
            ES512, PS512, RS512 -> Digest.SHA512
            else -> throw IllegalArgumentException("Unsupported hash algorithm.")
        }

    override val algorithm: SignatureAlgorithm
        get() = when (this) {
            is EC -> SignatureAlgorithm.ECDSA(digest, null)
            is RSA -> SignatureAlgorithm.RSA(digest, if (pssBits != null) RSAPadding.PSS else RSAPadding.PKCS1)
            else -> throw IllegalArgumentException("Unsupported signature algorithm.")
        }

    companion object : Asn1Decodable<Asn1Sequence, X509SignatureAlgorithm> {
        val ES256 = EC(KnownOIDs.ecdsaWithSHA256, "ES256")
        val ES384 = EC(KnownOIDs.ecdsaWithSHA384, "ES384")
        val ES512 = EC(KnownOIDs.ecdsaWithSHA512, "ES512")

        val PS256 = RSA(KnownOIDs.rsaPSS, "PS256", 256)
        val PS384 = RSA(KnownOIDs.rsaPSS, "PS384", 384)
        val PS512 = RSA(KnownOIDs.rsaPSS, "PS512", 512)

        val RS1   = RSA(KnownOIDs.sha1WithRSAEncryption, "RS1")
        val RS256 = RSA(KnownOIDs.sha256WithRSAEncryption, "RS256")
        val RS384 = RSA(KnownOIDs.sha384WithRSAEncryption, "RS384")
        val RS512 = RSA(KnownOIDs.sha512WithRSAEncryption, "RS512")

        val entries: List<X509SignatureAlgorithm> = listOf(
            ES256, ES384, ES512,
            PS256, PS384, PS512,
            RS1, RS256, RS384, RS512
        )

        private fun fromOid(oid: ObjectIdentifier): X509SignatureAlgorithm? =
            entries.firstOrNull { it.oid == oid }


        override fun doDecode(src: Asn1Sequence): X509SignatureAlgorithm = src.decodeRethrowing {
            when (val oid = next().asPrimitive().readOid()) {
                ES512.oid, ES384.oid, ES256.oid -> fromOid(oid)

                RS1.oid, RS256.oid, RS384.oid, RS512.oid -> fromOid(oid).also {
                    val tag = next().tag
                    if (tag != Asn1Element.Tag.NULL)
                        throw Asn1TagMismatchException(Asn1Element.Tag.NULL, tag, "RSA Params not allowed.")
                }

                PS256.oid, PS384.oid, PS512.oid -> parsePssParams(this)
                else -> throw Asn1Exception("Unsupported algorithm oid: $oid")
            }
        }


        @Throws(Asn1Exception::class)
        private fun parsePssParams(src: Asn1Structure.Iterator): X509SignatureAlgorithm = runRethrowing{
            val (algSequence, mgfSequence, saltLen) = src.next().asSequence().decodeRethrowing {
                Triple(
                    next().asExplicitlyTagged().verifyTag(0u).single().asSequence(),
                    next().asExplicitlyTagged().verifyTag(1u).single().asSequence(),
                    next().asExplicitlyTagged().verifyTag(2u).single().asPrimitive().decodeToInt()
                )
            }

            val (sigAlg, tagged) = algSequence.decodeRethrowing { next().asPrimitive().readOid() to next().tag }

            if (tagged != Asn1Element.Tag.NULL)
                throw Asn1TagMismatchException(Asn1Element.Tag.NULL, tagged, "PSS Params not supported yet")

            val (mgfOid, mgfParams) = mgfSequence.decodeRethrowing {
                next().asPrimitive().readOid() to next().asSequence()
            }

            if (mgfOid != KnownOIDs.pkcs1_MGF) throw IllegalArgumentException("Illegal OID: $mgfOid")

            val (innerHash, innerTagged) = mgfParams.decodeRethrowing { next().asPrimitive().readOid() to next().tag }

            if (innerHash != sigAlg) throw IllegalArgumentException("HashFunction mismatch! Expected: $sigAlg, is: $innerHash")
            if (innerTagged != Asn1Element.Tag.NULL) throw IllegalArgumentException(
                "PSS Params not supported yet"
            )

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