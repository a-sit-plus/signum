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

class X509SignatureAlgorithm(
    override val raw: SignatureAlgorithmIdentifier,
    override val algorithm: SignatureAlgorithm,
) : SignatureAlgorithmIdentifier(raw.oid, raw.parameters),
    SpecializedSignatureAlgorithm,
    Awesn1Backed<SignatureAlgorithmIdentifier>,
    Enumerable {

    override fun toString() = algorithm.toString()

    companion object : Asn1Decodable<Asn1Sequence, X509SignatureAlgorithm>,
        Enumeration<X509SignatureAlgorithm> {

        private fun ecdsa(digest: Digest, oid: ObjectIdentifier) =
            X509SignatureAlgorithm(
                raw = SignatureAlgorithmIdentifier(oid, emptyList()),
                algorithm = EcdsaSignatureAlgorithm(digest, null)
            )

        private fun rsaPkcs1(digest: Digest, oid: ObjectIdentifier) =
            X509SignatureAlgorithm(
                raw = SignatureAlgorithmIdentifier(oid, listOf(Asn1Null)),
                algorithm = RsaSignatureAlgorithm(digest, RsaSignaturePadding.PKCS1)
            )

        private fun rsaPss(digest: Digest): X509SignatureAlgorithm {
            val shaOid = digest.oid
            val shaLength = digest.outputLength
            return X509SignatureAlgorithm(
                raw = SignatureAlgorithmIdentifier(
                    KnownOIDs.rsaPSS,
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
                ),
                algorithm = RsaSignatureAlgorithm(digest, RsaSignaturePadding.PSS)
            )
        }

        val ES256 = ecdsa(Digest.SHA256, KnownOIDs.ecdsaWithSHA256)
        val ES384 = ecdsa(Digest.SHA384, KnownOIDs.ecdsaWithSHA384)
        val ES512 = ecdsa(Digest.SHA512, KnownOIDs.ecdsaWithSHA512)

        val PS256 = rsaPss(Digest.SHA256)
        val PS384 = rsaPss(Digest.SHA384)
        val PS512 = rsaPss(Digest.SHA512)

        val RS1 = rsaPkcs1(Digest.SHA1, KnownOIDs.sha1WithRSAEncryption)
        val RS256 = rsaPkcs1(Digest.SHA256, KnownOIDs.sha256WithRSAEncryption)
        val RS384 = rsaPkcs1(Digest.SHA384, KnownOIDs.sha384WithRSAEncryption)
        val RS512 = rsaPkcs1(Digest.SHA512, KnownOIDs.sha512WithRSAEncryption)

        override val entries: Set<X509SignatureAlgorithm> by lazy {
            setOf(ES256, ES384, ES512, PS256, PS384, PS512, RS1, RS256, RS384, RS512)
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
        when (candidate.algorithm) {
            is EcdsaSignatureAlgorithm -> parameters.isEmpty()
            is RsaSignatureAlgorithm -> when (candidate.algorithm.padding) {
                RsaSignaturePadding.PKCS1 ->
                    parameters.isEmpty() || (parameters.size == 1 && parameters.single() == Asn1Null)
                RsaSignaturePadding.PSS -> parameters == candidate.parameters
                else -> false
            }
            else -> false
        }
    }
}

/** Finds a X.509 signature algorithm matching this algorithm. Curve restrictions are not preserved. */
fun SignatureAlgorithm.toX509SignatureAlgorithm() = catching {
    when (this) {
        is EcdsaSignatureAlgorithm -> when (this.digest) {
            Digest.SHA256 -> X509SignatureAlgorithm.ES256
            Digest.SHA384 -> X509SignatureAlgorithm.ES384
            Digest.SHA512 -> X509SignatureAlgorithm.ES512
            else -> throw IllegalArgumentException("Digest ${this.digest} is unsupported by X.509 EC")
        }

        is RsaSignatureAlgorithm -> when (this.padding) {
            RsaSignaturePadding.PKCS1 -> when (this.digest) {
                Digest.SHA1 -> X509SignatureAlgorithm.RS1
                Digest.SHA256 -> X509SignatureAlgorithm.RS256
                Digest.SHA384 -> X509SignatureAlgorithm.RS384
                Digest.SHA512 -> X509SignatureAlgorithm.RS512
            }

            RsaSignaturePadding.PSS -> when (this.digest) {
                Digest.SHA256 -> X509SignatureAlgorithm.PS256
                Digest.SHA384 -> X509SignatureAlgorithm.PS384
                Digest.SHA512 -> X509SignatureAlgorithm.PS512
                else -> throw IllegalArgumentException("Digest ${this.digest} is unsupported by X.509 RSA-PSS")
            }

            else -> throw IllegalArgumentException("Padding ${this.padding} is unsupported by X.509 RSA")
        }

        else -> throw IllegalArgumentException("$this is unsupported by X.509")
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
