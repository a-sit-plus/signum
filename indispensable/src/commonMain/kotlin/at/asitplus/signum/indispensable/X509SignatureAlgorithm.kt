package at.asitplus.signum.indispensable

import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.SignatureAlgorithmIdentifier
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.encoding.Asn1.ExplicitlyTagged
import at.asitplus.awesn1.encoding.Asn1.Null
import at.asitplus.awesn1.encoding.decodeToInt
import at.asitplus.catching
import at.asitplus.signum.Enumerable
import at.asitplus.signum.Enumeration
import at.asitplus.signum.UnsupportedCryptoException

@Deprecated(
    "Moved to awesn1 crypto raw model.",
    ReplaceWith(
        "SignatureAlgorithmIdentifier",
        "at.asitplus.awesn1.crypto.SignatureAlgorithmIdentifier"
    )
)
typealias X509SignatureAlgorithmDescription = SignatureAlgorithmIdentifier

/** Checks whether this raw identifier maps to a supported Signum X.509 signature algorithm. */
fun SignatureAlgorithmIdentifier.isSupported(): Boolean = toSupportedOrNull() != null

/** Throws if the [SignatureAlgorithmIdentifier] is unsupported. */
fun SignatureAlgorithmIdentifier.requireSupported(): X509SignatureAlgorithm {
    return toSupportedOrNull()
        ?: throw UnsupportedCryptoException("Unsupported X.509 signature algorithm (OID = $oid)")
}

/** Maps a raw identifier to Signum's semantic [SignatureAlgorithm]. */
fun SignatureAlgorithmIdentifier.toSignatureAlgorithmOrNull(): SignatureAlgorithm? =
    toSupportedOrNull()?.algorithm

/** Throws if the [SignatureAlgorithmIdentifier] cannot be mapped to a supported Signum [SignatureAlgorithm]. */
fun SignatureAlgorithmIdentifier.requireSignatureAlgorithm(): SignatureAlgorithm =
    requireSupported().algorithm

// future: open
sealed class X509SignatureAlgorithm(
    oid: ObjectIdentifier
) : SignatureAlgorithmIdentifier(oid), SpecializedSignatureAlgorithm, Enumerable {

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
            val shaOid = digest.oid
            val shaLength = digest.outputLength
            listOf(Asn1.Sequence {
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
                    +Asn1.Int(shaLength.bytes)
                }
            })
        }

        override val algorithm get() = SignatureAlgorithm.RSA(digest, RSAPadding.PSS)

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

        // make it lazy to break init cycle that causes the weirdest nullpointer ever
        override val entries: Set<X509SignatureAlgorithm> by lazy {
            ECDSA.entries + RSAPKCS1.entries + RSAPSS.entries
        }

        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Sequence): X509SignatureAlgorithm =
            SignatureAlgorithmIdentifier.decodeFromTlv(src).requireSupported()

        internal fun parsePssParams(parameters: List<Asn1Element>): X509SignatureAlgorithm? = runCatching {
            require(parameters.size == 1) { "RSA-PSS params must contain exactly one element" }
            val (algSequence, mgfSequence, saltLen) = parameters.single().asSequence().decodeRethrowing {
                Triple(
                    next().asExplicitlyTagged().verifyTag(0u).single().asSequence(),
                    next().asExplicitlyTagged().verifyTag(1u).single().asSequence(),
                    next().asExplicitlyTagged().verifyTag(2u).single().asPrimitive().decodeToInt()
                )
            }

            val (sigAlg, tagged) = algSequence.decodeRethrowing { next().asPrimitive().readOid() to next().tag }

            if (tagged != Asn1Element.Tag.NULL) {
                throw Asn1TagMismatchException(Asn1Element.Tag.NULL, tagged, "PSS Params not supported yet")
            }

            val (mgfOid, mgfParams) = mgfSequence.decodeRethrowing {
                next().asPrimitive().readOid() to next().asSequence()
            }

            if (mgfOid != KnownOIDs.pkcs1_MGF) throw IllegalArgumentException("Illegal OID: $mgfOid")

            val (innerHash, innerTagged) = mgfParams.decodeRethrowing { next().asPrimitive().readOid() to next().tag }

            if (innerHash != sigAlg) throw IllegalArgumentException("HashFunction mismatch! Expected: $sigAlg, is: $innerHash")
            if (innerTagged != Asn1Element.Tag.NULL) throw IllegalArgumentException("PSS Params not supported yet")

            when (sigAlg) {
                KnownOIDs.sha_256 -> PS256.also {
                    if (saltLen != 256 / 8) throw IllegalArgumentException("Non-recommended salt length used: $saltLen")
                }
                KnownOIDs.sha_384 -> PS384.also {
                    if (saltLen != 384 / 8) throw IllegalArgumentException("Non-recommended salt length used: $saltLen")
                }
                KnownOIDs.sha_512 -> PS512.also {
                    if (saltLen != 512 / 8) throw IllegalArgumentException("Non-recommended salt length used: $saltLen")
                }
                else -> throw IllegalArgumentException("Unsupported OID: $sigAlg")
            }
        }.getOrNull()
    }
}

private fun SignatureAlgorithmIdentifier.toSupportedOrNull(): X509SignatureAlgorithm? = when (oid) {
    KnownOIDs.rsaPSS -> X509SignatureAlgorithm.parsePssParams(parameters)
    else -> X509SignatureAlgorithm.entries.firstOrNull { it.oid == oid }?.takeIf { candidate ->
        when (candidate) {
            is X509SignatureAlgorithm.ECDSA -> parameters.isEmpty()
            is X509SignatureAlgorithm.RSAPKCS1 ->
                parameters.isEmpty() || (parameters.size == 1 && parameters.single() == Asn1Null)
            is X509SignatureAlgorithm.RSAPSS -> parameters == candidate.parameters
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

/** Finds a raw signature algorithm identifier matching this semantic Signum signature algorithm. */
fun SignatureAlgorithm.toSignatureAlgorithmIdentifier() =
    toX509SignatureAlgorithm().map { it as SignatureAlgorithmIdentifier }

/** Finds a raw signature algorithm identifier matching this semantic Signum signature algorithm. */
fun SpecializedSignatureAlgorithm.toSignatureAlgorithmIdentifier() =
    algorithm.toSignatureAlgorithmIdentifier()
