package at.asitplus.signum.indispensable

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.encoding.Asn1.ExplicitlyTagged
import at.asitplus.signum.indispensable.asn1.encoding.Asn1.Null
import at.asitplus.signum.indispensable.asn1.encoding.decodeToInt
import at.asitplus.signum.indispensable.misc.BitLength
import at.asitplus.signum.indispensable.misc.bit
import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.contract

/**
 * Represents X.509Signature algorithms including and beyond what's known to Signum.
 * IF you want to create a custom, unsupported algorithm, pass it as an [Asn1Sequence] into [X509SignatureAlgorithmEntry.decodeFromTlv]
 */
open class X509SignatureAlgorithmEntry internal constructor(
    override val oid: ObjectIdentifier,
    val parameters: List<Asn1Element>
) : Asn1Encodable<Asn1Sequence>, Identifiable {
    override fun encodeToTlv() =
        Asn1.Sequence {
            +oid
            parameters.forEach { +it }
        }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is X509SignatureAlgorithmEntry) return false

        if (oid != other.oid) return false
        if (parameters != other.parameters) return false

        return true
    }

    override fun hashCode(): Int {
        var result = oid.hashCode()
        result = 31 * result + parameters.hashCode()
        return result
    }


    companion object : Asn1Decodable<Asn1Sequence, X509SignatureAlgorithmEntry> {

        private fun fromOid(oid: ObjectIdentifier): X509SignatureAlgorithm? =
            X509SignatureAlgorithm.entries.firstOrNull { it.oid == oid }

        override fun doDecode(src: Asn1Sequence): X509SignatureAlgorithmEntry = runRethrowing {
            val oid = (src.nextChild() as Asn1Primitive).readOid()
            catchingUnwrapped {
                when (oid) {
                    KnownOIDs.rsaPSS -> parsePssParams(src)
                    else -> {
                        val alg = fromOid(oid)
                        if (alg is X509SignatureAlgorithm.RSA) {
                            val tag = src.nextChild().tag
                            if (tag != Asn1Element.Tag.NULL)
                                throw Asn1TagMismatchException(Asn1Element.Tag.NULL, tag, "RSA Params not allowed.")
                        }
                        alg ?: X509SignatureAlgorithmEntry(
                            oid,
                            generateSequence { src.takeIf { it.hasMoreChildren() }?.nextChild() }.toList()
                        )
                    }
                }
            }.getOrElse {
                X509SignatureAlgorithmEntry(oid, src.children.subList(1, src.children.size))
            }
        }

        @Throws(Asn1Exception::class)
        private fun parsePssParams(src: Asn1Sequence): X509SignatureAlgorithm =
            runRethrowing {
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
                val saltLen = last.decodeToInt().bit

                return sigAlg.let {
                    when (it) {
                        KnownOIDs.sha_256 -> X509SignatureAlgorithm.PS256.also {
                            if (saltLen != it.saltLength) throw IllegalArgumentException(
                                "Non-recommended salt length used: $saltLen"
                            )
                        }

                        KnownOIDs.sha_384 -> X509SignatureAlgorithm.PS256.also {
                            if (saltLen != it.saltLength) throw IllegalArgumentException(
                                "Non-recommended salt length used: $saltLen"
                            )
                        }

                        KnownOIDs.sha_512 -> X509SignatureAlgorithm.PS256.also {
                            if (saltLen != it.saltLength) throw IllegalArgumentException(
                                "Non-recommended salt length used: $saltLen"
                            )
                        }

                        else -> throw IllegalArgumentException("Unsupported OID: $it")
                    }
                }
            }
    }
}

/** smart-casts the receiver to an [X509SignatureAlgorithm] if known.*/
@OptIn(ExperimentalContracts::class)
fun X509SignatureAlgorithmEntry.isKnown(): Boolean {
    contract {
        returns(true) implies (this@isKnown is X509SignatureAlgorithm)
    }
    return (this is X509SignatureAlgorithm)
}


open class X509SignatureAlgorithm(
    override val algorithm: SignatureAlgorithm,
    val name: String,
    oid: ObjectIdentifier,
    parameters: List<Asn1Element> = emptyList()
) : X509SignatureAlgorithmEntry(oid, parameters), SpecializedSignatureAlgorithm {

    // ECDSA with SHA-size
    data class EC(override val oid: ObjectIdentifier, val digest: Digest?) :
        X509SignatureAlgorithm(
            algorithm = SignatureAlgorithm.ECDSA(digest, null),
            name = digest?.outputLength?.bits?.let { "ES$it" } ?: "ECDSA raw",
            oid
        )

    // RSA
    data class RSA(override val oid: ObjectIdentifier, val digest: Digest, val saltLength: BitLength? = null) :
        X509SignatureAlgorithm(
            algorithm =
                SignatureAlgorithm.RSA(digest, if (saltLength != null) RSAPadding.PSS else RSAPadding.PKCS1),
            saltLength?.let { "PS${it.bits}" } ?: if (digest == Digest.SHA1) "RS1" else "RS${digest.outputLength.bits}",
            oid,
            saltLength?.let { encodePSSParams(digest, it) } ?: listOf(Asn1.Null())) {

        companion object {
            private fun encodePSSParams(digest: Digest, bits: BitLength): List<Asn1Element> =
                digest.oid.let { shaOid ->
                    require(bits == digest.outputLength) { "Non-Recommended PSS salt sizes not yet supported" }
                    listOf(
                        ExplicitlyTagged(0u) {
                            +Asn1.Sequence {
                                +shaOid
                                +Null()
                            }
                        },
                        ExplicitlyTagged(1u) {
                            +Asn1.Sequence {
                                +KnownOIDs.pkcs1_MGF
                                +Asn1.Sequence {
                                    +shaOid
                                    +Null()
                                }
                            }
                        },
                        ExplicitlyTagged(2u) {
                            +Asn1.Int(bits.bytes)

                        })
                }
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as X509SignatureAlgorithm

        if (oid != other.oid) return false
        if (parameters != other.parameters) return false

        return true
    }

    override fun hashCode(): Int {
        var result = oid.hashCode()
        result = 31 * result + parameters.hashCode()
        return result
    }


    companion object : Asn1Decodable<Asn1Sequence, X509SignatureAlgorithm> {
        val ES256 = EC(KnownOIDs.ecdsaWithSHA256, Digest.SHA256)
        val ES384 = EC(KnownOIDs.ecdsaWithSHA384, Digest.SHA384)
        val ES512 = EC(KnownOIDs.ecdsaWithSHA512, Digest.SHA512)

        val PS256 = RSA(KnownOIDs.rsaPSS, Digest.SHA256, 256.bit)
        val PS384 = RSA(KnownOIDs.rsaPSS, Digest.SHA384, 384.bit)
        val PS512 = RSA(KnownOIDs.rsaPSS, Digest.SHA512, 512.bit)

        val RS1 = RSA(KnownOIDs.sha1WithRSAEncryption, Digest.SHA1)
        val RS256 = RSA(KnownOIDs.sha256WithRSAEncryption, Digest.SHA256)
        val RS384 = RSA(KnownOIDs.sha384WithRSAEncryption, Digest.SHA384)
        val RS512 = RSA(KnownOIDs.sha512WithRSAEncryption, Digest.SHA512)

        val entries = setOf(
            ES256, ES384, ES512,
            PS256, PS384, PS512,
            RS1, RS256, RS384, RS512
        )

        override fun doDecode(src: Asn1Sequence): X509SignatureAlgorithm =
            X509SignatureAlgorithmEntry.doDecode(src).let {
                it as? X509SignatureAlgorithm ?: throw Asn1Exception("Unsupported signature algorithm: ${it.oid}")
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
fun SpecializedSignatureAlgorithm.toX509SignatureAlgorithm(): KmmResult<X509SignatureAlgorithm> =
    this.algorithm.toX509SignatureAlgorithm()