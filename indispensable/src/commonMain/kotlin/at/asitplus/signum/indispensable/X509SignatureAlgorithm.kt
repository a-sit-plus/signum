package at.asitplus.signum.indispensable
/*
import at.asitplus.catching
import at.asitplus.signum.Enumerable
import at.asitplus.signum.Enumeration
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.RsaSsaPssParams
import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.encoding.Asn1.Null
import at.asitplus.awesn1.runRethrowing
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.ExplicitlyTagged
import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.contract

sealed class X509SignatureAlgorithmDescription(
    override val oid: ObjectIdentifier
) : Asn1Encodable<Asn1Sequence>, Identifiable {

    /** Additional algorithm parameters, if any. */
    abstract val parameters: List<Asn1Element>

    fun toAlgorithmIdentifier() = X509AlgorithmIdentifier(oid, parameters)

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
        X509SignatureAlgorithmDescription(oid) {
        override fun toString() = "Unknown($oid)"
    }

    companion object : Asn1Decodable<Asn1Sequence, X509SignatureAlgorithmDescription> {
        fun fromAlgorithmIdentifier(identifier: X509AlgorithmIdentifier): X509SignatureAlgorithmDescription =
            runRethrowing {
                val parameter = identifier.parameters
                val params = when {
                    parameter == null -> Asn1.Sequence { }
                    identifier.oid == KnownOIDs.rsaPSS -> parameter.asSequence()
                    else -> Asn1.Sequence { +parameter }
                }
                catching { SignatureAlgorithm(identifier).toX509SignatureAlgorithm().getOrThrow() }.getOrNull()
                    ?: Unknown(identifier.oid, params.children)
            }

        override fun doDecode(src: Asn1Sequence): X509SignatureAlgorithmDescription =
            fromAlgorithmIdentifier(X509AlgorithmIdentifier(src))
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
) : X509SignatureAlgorithmDescription(oid), SpecializedSignatureAlgorithm, Enumerable {

    // ECDSA with SHA-size
    sealed class ECDSA(oid: ObjectIdentifier, val digest: Digest) :
        X509SignatureAlgorithm(oid) {
        override val parameters get() = emptyList<Asn1Element>()
        override val algorithm get() = SignatureAlgorithm.ECDSA(digest, null)
        override fun toString() = algorithm.toString()

        companion object : Enumeration<ECDSA> {
            override val entries: Set<ECDSA> by lazy {
                setOf(
                    ES256, ES384, ES512,
                )
            }
        }
    }

    @Deprecated("Use type check", replaceWith = ReplaceWith("this is X509SignatureAlgorithm.ECDSA"))
    val isEc get() = this is ECDSA

    // RSASSA-PSS with SHA-size
    sealed class RSAPSS(val digest: Digest) : X509SignatureAlgorithm(KnownOIDs.rsaPSS) {

        override val parameters by lazy {
            val hashAlgorithm = X509AlgorithmIdentifier(digest.oid, Null())
            listOf(
                DER.encodeToTlv(
                    RsaSsaPssParams.serializer(),
                    RsaSsaPssParams(
                        taggedHashAlgorithm = ExplicitlyTagged(hashAlgorithm),
                        taggedMaskGenAlgorithm = ExplicitlyTagged(
                            X509AlgorithmIdentifier(KnownOIDs.pkcs1_MGF, hashAlgorithm.element)
                        ),
                        taggedSaltLength = ExplicitlyTagged(Asn1Integer(digest.outputLength.bytes)),
                    )
                )
            )
        }

        override val algorithm get() =
            SignatureAlgorithm.RSA(digest, RSAPadding.PSS(digest, saltLength = digest.outputLength.bytes.toUInt()))

        override fun toString() = algorithm.toString()

        companion object : Enumeration<RSAPSS> {
            override val entries: Set<RSAPSS> by lazy {
                setOf(
                    PS256, PS384, PS512
                )
            }
        }
    }

    // RSASSA-PKCS1-v1_5 with SHA-size
    sealed class RSAPKCS1(oid: ObjectIdentifier, val digest: Digest) :
        X509SignatureAlgorithm(oid) {
        override val parameters get() = listOf(Asn1Null)
        override val algorithm get() = SignatureAlgorithm.RSA(digest, RSAPadding.PKCS1)

        companion object : Enumeration<RSAPKCS1> {
            override val entries: Set<RSAPKCS1> by lazy {
                setOf(
                    RS1, RS256, RS384, RS512
                )
            }
        }
    }

    object ES256 : ECDSA(KnownOIDs.ecdsaWithSHA256, Digest.SHA256)
    object ES384 : ECDSA(KnownOIDs.ecdsaWithSHA384, Digest.SHA384)
    object ES512 : ECDSA(KnownOIDs.ecdsaWithSHA512, Digest.SHA512)

    object PS256 : RSAPSS(Digest.SHA256)
    object PS384 : RSAPSS(Digest.SHA384)
    object PS512 : RSAPSS(Digest.SHA512)

    object RS1 : RSAPKCS1(KnownOIDs.sha1WithRSAEncryption, Digest.SHA1)
    object RS256 : RSAPKCS1(KnownOIDs.sha256WithRSAEncryption, Digest.SHA256)
    object RS384 : RSAPKCS1(KnownOIDs.sha384WithRSAEncryption, Digest.SHA384)
    object RS512 : RSAPKCS1(KnownOIDs.sha512WithRSAEncryption, Digest.SHA512)


    companion object : Asn1Decodable<Asn1Sequence, X509SignatureAlgorithm>,
        Enumeration<X509SignatureAlgorithm> {

        //make it lazy to break init cycle that causes the weirdest nullpointer ever
        override val entries: Set<X509SignatureAlgorithm> by lazy {
            ECDSA.entries + RSAPKCS1.entries + RSAPSS.entries
        }

        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Sequence): X509SignatureAlgorithm =
            X509SignatureAlgorithmDescription.doDecode(src).let {
                (it as? X509SignatureAlgorithm)
                    ?: throw Asn1OidException("Unsupported OID: ${it.oid}", it.oid)
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

            is RSAPadding.PSS -> when (this.padding) {
                X509SignatureAlgorithm.PS256.algorithm.padding -> X509SignatureAlgorithm.PS256
                X509SignatureAlgorithm.PS384.algorithm.padding -> X509SignatureAlgorithm.PS384
                X509SignatureAlgorithm.PS512.algorithm.padding -> X509SignatureAlgorithm.PS512
                else -> throw IllegalArgumentException("Digest ${this.digest} is unsupported by X.509 RSA-PSS")
            }
        }
    }
}

/** Finds a X.509 signature algorithm matching this algorithm. Curve restrictions are not preserved. */
fun SpecializedSignatureAlgorithm.toX509SignatureAlgorithm() =
    this.algorithm.toX509SignatureAlgorithm()
*/