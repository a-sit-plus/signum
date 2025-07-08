package at.asitplus.signum.indispensable

import at.asitplus.catching
import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1Exception
import at.asitplus.signum.indispensable.asn1.Asn1ExplicitlyTagged
import at.asitplus.signum.indispensable.asn1.Asn1Primitive
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.Asn1TagMismatchException
import at.asitplus.signum.indispensable.asn1.Identifiable
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.encoding.Asn1.ExplicitlyTagged
import at.asitplus.signum.indispensable.asn1.encoding.Asn1.Null
import at.asitplus.signum.indispensable.asn1.encoding.decodeToInt
import at.asitplus.signum.indispensable.asn1.readOid
import at.asitplus.signum.indispensable.asn1.runRethrowing
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.update

@Serializable(with = X509SignatureAlgorithmSerializer::class)
open class X509SignatureAlgorithm private constructor(
    override val oid: ObjectIdentifier,
    open val name: String,
    val parameters: List<Asn1Element> = emptyList()
) : Asn1Encodable<Asn1Sequence>, Identifiable, SpecializedSignatureAlgorithm {

    // ECDSA with SHA-size
    data class EC(override val oid: ObjectIdentifier, override val name: String) : X509SignatureAlgorithm(oid, name)

    // RSA
    data class RSA(override val oid: ObjectIdentifier, override val name: String, val pssBits: Int? = null) : X509SignatureAlgorithm(oid, name)


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

        else -> Asn1.Sequence {
            +oid
            parameters.forEach { +it }
        }
    }

    val digest: Digest
        get() = when (this) {
            RS1 -> Digest.SHA1
            ES256, PS256, RS256 -> Digest.SHA256
            ES384, PS384, RS384 -> Digest.SHA384
            ES512, PS512, RS512 -> Digest.SHA512
            else -> throw IllegalArgumentException("Unsupported hash algorithm.")
        }

    // TODO update when core signature data classes become extensible
    override val algorithm: SignatureAlgorithm
        get() = when (this) {
            is EC -> SignatureAlgorithm.ECDSA(digest, null)
            is RSA -> SignatureAlgorithm.RSA(digest, if (pssBits != null) RSAPadding.PSS else RSAPadding.PKCS1)
            else -> throw IllegalArgumentException("Unsupported signature algorithm.")
        }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as X509SignatureAlgorithm

        if (oid != other.oid) return false
        if (name != other.name) return false
        if (parameters != other.parameters) return false

        return true
    }

    override fun hashCode(): Int {
        var result = oid.hashCode()
        result = 31 * result + name.hashCode()
        result = 31 * result + parameters.hashCode()
        return result
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

        private val _registeredAlgorithms = MutableStateFlow(
            setOf(
                ES256, ES384, ES512,
                PS256, PS384, PS512,
                RS1, RS256, RS384, RS512
            )
        )
        val registeredAlgorithms: Set<X509SignatureAlgorithm>
            get() = _registeredAlgorithms.value

        fun register(algorithm: X509SignatureAlgorithm) {
            _registeredAlgorithms.update { it + algorithm}
        }

        private fun fromOid(oid: ObjectIdentifier): X509SignatureAlgorithm? =
            registeredAlgorithms.firstOrNull { it.oid == oid }

        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Sequence): X509SignatureAlgorithm = runRethrowing {
            when (val oid = (src.nextChild() as Asn1Primitive).readOid()) {
                KnownOIDs.rsaPSS -> parsePssParams(src)
                else -> {
                    val alg = fromOid(oid)
                    if (alg is RSA) {
                        val tag = src.nextChild().tag
                        if (tag != Asn1Element.Tag.NULL)
                            throw Asn1TagMismatchException(Asn1Element.Tag.NULL, tag, "RSA Params not allowed.")
                    }
                    alg ?: X509SignatureAlgorithm(
                        oid,
                        "Unknown($oid)",
                        generateSequence { src.takeIf { it.hasMoreChildren() }?.nextChild() }.toList()
                    )
                }
            }
        }

        @Throws(Asn1Exception::class)
        private fun parsePssParams(src: Asn1Sequence): X509SignatureAlgorithm = runRethrowing {
            val seq = src.nextChild() as Asn1Sequence
            val first = (seq.nextChild() as Asn1ExplicitlyTagged).verifyTag(0u).single() as Asn1Sequence

            val sigAlg = (first.nextChild() as Asn1Primitive).readOid()
            val tag = first.nextChild().tag
            if (tag != Asn1Element.Tag.NULL)
                throw Asn1TagMismatchException(Asn1Element.Tag.NULL, tag, "PSS Params not supported yet")

            val second = (seq.nextChild() as Asn1ExplicitlyTagged).verifyTag(1u).single() as Asn1Sequence
            val mgf = (second.nextChild() as Asn1Primitive).readOid()
            if (mgf != KnownOIDs.pkcs1_MGF) throw IllegalArgumentException("Illegal OID: $mgf")
            val inner = second.nextChild() as Asn1Sequence
            val innerHash = (inner.nextChild() as Asn1Primitive).readOid()
            if (innerHash != sigAlg) throw IllegalArgumentException("HashFunction mismatch! Expected: $sigAlg, is: $innerHash")

            if (inner.nextChild().tag != Asn1Element.Tag.NULL) throw IllegalArgumentException(
                "PSS Params not supported yet"
            )

            val last = (seq.nextChild() as Asn1ExplicitlyTagged).verifyTag(2u).single() as Asn1Primitive
            val saltLen = last.decodeToInt()

            return sigAlg.let {
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
        return X509SignatureAlgorithm.registeredAlgorithms.first { it.name == decoded }
    }
}