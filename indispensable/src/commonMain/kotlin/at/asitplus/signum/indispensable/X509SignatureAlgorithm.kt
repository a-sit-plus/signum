package at.asitplus.signum.indispensable

import at.asitplus.catching
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.encoding.Asn1.ExplicitlyTagged
import at.asitplus.signum.indispensable.asn1.encoding.Asn1.Null
import at.asitplus.signum.indispensable.asn1.encoding.decodeToInt
import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.contract

// future: SPI
private interface X509SignatureAlgorithmProvider {
    fun loaderForOid(oid: ObjectIdentifier): ((Asn1Structure.Iterator) -> X509SignatureAlgorithm)?
}

sealed class X509SignatureAlgorithmDescription(
    override val oid: ObjectIdentifier
) : Asn1Encodable<Asn1Sequence>, Identifiable {

    abstract val parameters: List<Asn1Element>

    override fun encodeToTlv() = Asn1.Sequence {
        +oid
        parameters.forEach { +it }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is X509SignatureAlgorithmDescription) return false
        return (oid == other.oid) && (parameters == other.parameters)
    }

    override fun hashCode() = (31 * oid.hashCode() + parameters.hashCode())

    internal class Unknown(oid: ObjectIdentifier, override val parameters: List<Asn1Element>) :
        X509SignatureAlgorithmDescription(oid)

    companion object : Asn1Decodable<Asn1Sequence, X509SignatureAlgorithmDescription> {
        override fun doDecode(src: Asn1Sequence) = src.decodeRethrowing {
            val oid = next().asPrimitive().readOid()
            // future: SPI
            sequenceOf<X509SignatureAlgorithmProvider>(X509SignatureAlgorithm.Provider)
                .firstNotNullOfOrNull { it.loaderForOid(oid) }
                ?.invoke(this@decodeRethrowing)
                ?: Unknown(oid, generateSequence(this@decodeRethrowing::nextOrNull).toList())
        }
    }
}

/** smart-casts the receiver to an [X509SignatureAlgorithm.Supported] if supported.*/
@OptIn(ExperimentalContracts::class)
fun X509SignatureAlgorithmDescription.isSupported(): Boolean {
    contract {
        returns(true) implies (this@isSupported is X509SignatureAlgorithm)
    }
    return (this is X509SignatureAlgorithm)
}

/** throws if the [X509SignatureAlgorithm] is unsupported */
@OptIn(ExperimentalContracts::class)
fun X509SignatureAlgorithmDescription.requireSupported() {
    contract {
        returns() implies (this@requireSupported is X509SignatureAlgorithm)
    }
    if (this !is X509SignatureAlgorithm) throw UnsupportedCryptoException("Unsupported X.509 signature algorithm (OID = ${this.oid})")
}

// future: open
sealed class X509SignatureAlgorithm(
    oid: ObjectIdentifier
) : X509SignatureAlgorithmDescription(oid), SpecializedSignatureAlgorithm {

    /** The [X509SignatureAlgorithmProvider] for Signum's natively supported [X509SignatureAlgorithm]s */
    internal object Provider : X509SignatureAlgorithmProvider {
        override fun loaderForOid(oid: ObjectIdentifier) = when (oid) {
            KnownOIDs.rsaPSS -> X509SignatureAlgorithm::parsePssParams
            else -> when (val alg = entries.firstOrNull { it.oid == oid }) {
                null -> null
                is RSAPKCS1 -> ({
                    if (it.next() != Asn1Null) {
                        throw Asn1TagMismatchException(
                            Asn1Element.Tag.NULL, it.currentElement.tag,
                            "RSA Params not allowed."
                        )
                    }
                    alg
                })

                else -> ({ alg })
            }
        }
    }

    // ECDSA with SHA-size
    sealed class ECDSA(oid: ObjectIdentifier, override val algorithm: SignatureAlgorithm, override val digest: Digest) :
        X509SignatureAlgorithm(oid) {
        override val parameters get() = emptyList<Asn1Element>()
    }

    @Deprecated("Use type check", replaceWith = ReplaceWith("this is X509SignatureAlgorithm.ECDSA"))
    val isEc get() = this is ECDSA

    // RSASSA-PSS with SHA-size
    sealed class RSAPSS(override val algorithm: SignatureAlgorithm.RSA) : X509SignatureAlgorithm(KnownOIDs.rsaPSS) {
        override val digest get() = algorithm.digest

        override val parameters by lazy {
            val shaOid = digest.oid
            val shaLength = digest.outputLength
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
                    +Asn1.Int(shaLength.bytes)
                })
        }
    }

    // RSASSA-PKCS1-v1_5 with SHA-size
    sealed class RSAPKCS1(oid: ObjectIdentifier, override val algorithm: SignatureAlgorithm.RSA) :
        X509SignatureAlgorithm(oid) {
        override val digest get() = algorithm.digest
        override val parameters get() = listOf(Asn1Null)
    }

    abstract val digest: Digest

    object ES256 : ECDSA(KnownOIDs.ecdsaWithSHA256, SignatureAlgorithm.ECDSAwithSHA256, Digest.SHA256)
    object ES384 : ECDSA(KnownOIDs.ecdsaWithSHA384, SignatureAlgorithm.ECDSAwithSHA384, Digest.SHA384)
    object ES512 : ECDSA(KnownOIDs.ecdsaWithSHA512, SignatureAlgorithm.ECDSAwithSHA512, Digest.SHA512)

    object PS256 : RSAPSS(SignatureAlgorithm.RSAwithSHA256andPSSPadding)
    object PS384 : RSAPSS(SignatureAlgorithm.RSAwithSHA384andPSSPadding)
    object PS512 : RSAPSS(SignatureAlgorithm.RSAwithSHA512andPSSPadding)

    object RS1 : RSAPKCS1(KnownOIDs.sha1WithRSAEncryption, SignatureAlgorithm.RSA(Digest.SHA1, RSAPadding.PKCS1))
    object RS256 : RSAPKCS1(KnownOIDs.sha256WithRSAEncryption, SignatureAlgorithm.RSAwithSHA256andPKCS1Padding)
    object RS384 : RSAPKCS1(KnownOIDs.sha384WithRSAEncryption, SignatureAlgorithm.RSAwithSHA384andPKCS1Padding)
    object RS512 : RSAPKCS1(KnownOIDs.sha512WithRSAEncryption, SignatureAlgorithm.RSAwithSHA512andPKCS1Padding)

    companion object : Asn1Decodable<Asn1Sequence, X509SignatureAlgorithm> {

        val entries = setOf(
            ES256, ES384, ES512,
            PS256, PS384, PS512,
            RS1, RS256, RS384, RS512
        )

        @Throws(Asn1OidException::class)
        private fun fromOid(oid: ObjectIdentifier) = catching { entries.first { it.oid == oid } }.getOrElse {
            throw Asn1OidException("Unsupported OID: $oid", oid)
        }

        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Sequence): X509SignatureAlgorithm =
            X509SignatureAlgorithmDescription.doDecode(src).let {
                (it as? X509SignatureAlgorithm)
                    ?: throw Asn1OidException("Unsupported OID: ${it.oid}", it.oid)
            }

        @Throws(Asn1Exception::class)
        private fun parsePssParams(src: Asn1Structure.Iterator): X509SignatureAlgorithm = runRethrowing {
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
