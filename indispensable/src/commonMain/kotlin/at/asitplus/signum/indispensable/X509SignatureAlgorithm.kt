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
import kotlinx.serialization.Serializable

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
    x509BuiltInMappings
    return toSupportedOrNull()
        ?: throw UnsupportedCryptoException("Unsupported X.509 signature algorithm (OID = $oid)")
}

/** Maps a raw identifier to Signum's semantic [SignatureAlgorithm]. */
fun SignatureAlgorithmIdentifier.toSignatureAlgorithmOrNull(): SignatureAlgorithm? =
    toSupportedOrNull()?.algorithm

/** Throws if the [SignatureAlgorithmIdentifier] cannot be mapped to a supported Signum [SignatureAlgorithm]. */
fun SignatureAlgorithmIdentifier.requireSignatureAlgorithm(): SignatureAlgorithm =
    requireSupported().algorithm

@Serializable(with = X509SignatureAlgorithmAsn1Serializer::class)
class X509SignatureAlgorithm(
    override val raw: SignatureAlgorithmIdentifier,
    override val algorithm: SignatureAlgorithm,
) : SignatureAlgorithmIdentifier(raw.oid, raw.parameters),
    SpecializedSignatureAlgorithm,
    Awesn1Backed<SignatureAlgorithmIdentifier, Asn1Sequence, SignatureAlgorithmIdentifier.Companion>,
    Enumerable {

    override fun encodeToTlv() = raw.encodeToTlv()

    override fun toString() = algorithm.toString()

    companion object : Enumeration<X509SignatureAlgorithm> {
        val ES256: X509SignatureAlgorithm get() = x509EcdsaSha256
        val ES384: X509SignatureAlgorithm get() = x509EcdsaSha384
        val ES512: X509SignatureAlgorithm get() = x509EcdsaSha512

        val PS256: X509SignatureAlgorithm get() = x509RsaSha256Pss
        val PS384: X509SignatureAlgorithm get() = x509RsaSha384Pss
        val PS512: X509SignatureAlgorithm get() = x509RsaSha512Pss

        val RS1: X509SignatureAlgorithm get() = x509RsaSha1Pkcs1
        val RS256: X509SignatureAlgorithm get() = x509RsaSha256Pkcs1
        val RS384: X509SignatureAlgorithm get() = x509RsaSha384Pkcs1
        val RS512: X509SignatureAlgorithm get() = x509RsaSha512Pkcs1

        override val entries: Set<X509SignatureAlgorithm>
            get() {
                x509BuiltInMappings
                return setOf(ES256, ES384, ES512, PS256, PS384, PS512, RS1, RS256, RS384, RS512)
            }

        fun register(raw: SignatureAlgorithmIdentifier, algorithm: SignatureAlgorithm): X509SignatureAlgorithm =
            X509SignatureAlgorithm(raw, algorithm).also {
                AlgorithmRegistry.registerSignatureAlgorithm(algorithm)
                AlgorithmRegistry.registerX509SignatureMapping(raw, algorithm)
            }
    }
}

object X509SignatureAlgorithmAsn1Serializer :
    Awesn1BackedSerializer<X509SignatureAlgorithm, SignatureAlgorithmIdentifier>(
        rawSerializer = SignatureAlgorithmIdentifier,
        encodeAs = { it.raw },
        decodeAs = SignatureAlgorithmIdentifier::requireSupported,
    )

@Deprecated(
    "Use X509SignatureAlgorithm.ES256.",
    ReplaceWith("X509SignatureAlgorithm.ES256", "at.asitplus.signum.indispensable.X509SignatureAlgorithm")
)
val ES256: X509SignatureAlgorithm get() = X509SignatureAlgorithm.ES256
@Deprecated(
    "Use X509SignatureAlgorithm.ES384.",
    ReplaceWith("X509SignatureAlgorithm.ES384", "at.asitplus.signum.indispensable.X509SignatureAlgorithm")
)
val ES384: X509SignatureAlgorithm get() = X509SignatureAlgorithm.ES384
@Deprecated(
    "Use X509SignatureAlgorithm.ES512.",
    ReplaceWith("X509SignatureAlgorithm.ES512", "at.asitplus.signum.indispensable.X509SignatureAlgorithm")
)
val ES512: X509SignatureAlgorithm get() = X509SignatureAlgorithm.ES512

@Deprecated(
    "Use X509SignatureAlgorithm.PS256.",
    ReplaceWith("X509SignatureAlgorithm.PS256", "at.asitplus.signum.indispensable.X509SignatureAlgorithm")
)
val PS256: X509SignatureAlgorithm get() = X509SignatureAlgorithm.PS256
@Deprecated(
    "Use X509SignatureAlgorithm.PS384.",
    ReplaceWith("X509SignatureAlgorithm.PS384", "at.asitplus.signum.indispensable.X509SignatureAlgorithm")
)
val PS384: X509SignatureAlgorithm get() = X509SignatureAlgorithm.PS384
@Deprecated(
    "Use X509SignatureAlgorithm.PS512.",
    ReplaceWith("X509SignatureAlgorithm.PS512", "at.asitplus.signum.indispensable.X509SignatureAlgorithm")
)
val PS512: X509SignatureAlgorithm get() = X509SignatureAlgorithm.PS512

@Deprecated(
    "Use X509SignatureAlgorithm.RS1.",
    ReplaceWith("X509SignatureAlgorithm.RS1", "at.asitplus.signum.indispensable.X509SignatureAlgorithm")
)
val RS1: X509SignatureAlgorithm get() = X509SignatureAlgorithm.RS1
@Deprecated(
    "Use X509SignatureAlgorithm.RS256.",
    ReplaceWith("X509SignatureAlgorithm.RS256", "at.asitplus.signum.indispensable.X509SignatureAlgorithm")
)
val RS256: X509SignatureAlgorithm get() = X509SignatureAlgorithm.RS256
@Deprecated(
    "Use X509SignatureAlgorithm.RS384.",
    ReplaceWith("X509SignatureAlgorithm.RS384", "at.asitplus.signum.indispensable.X509SignatureAlgorithm")
)
val RS384: X509SignatureAlgorithm get() = X509SignatureAlgorithm.RS384
@Deprecated(
    "Use X509SignatureAlgorithm.RS512.",
    ReplaceWith("X509SignatureAlgorithm.RS512", "at.asitplus.signum.indispensable.X509SignatureAlgorithm")
)
val RS512: X509SignatureAlgorithm get() = X509SignatureAlgorithm.RS512

private fun x509Ecdsa(digest: Digest, oid: ObjectIdentifier) =
    X509SignatureAlgorithm(
        raw = SignatureAlgorithmIdentifier(oid, emptyList()),
        algorithm = EcdsaSignatureAlgorithm(digest, null)
    )

private fun x509RsaPkcs1(digest: Digest, oid: ObjectIdentifier) =
    X509SignatureAlgorithm(
        raw = SignatureAlgorithmIdentifier(oid, listOf(Asn1Null)),
        algorithm = RsaSignatureAlgorithm(digest, RsaSignaturePadding.PKCS1)
    )

private fun x509RsaPss(digest: Digest): X509SignatureAlgorithm {
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

private val x509EcdsaSha256 = x509Ecdsa(Digest.SHA256, KnownOIDs.ecdsaWithSHA256)
private val x509EcdsaSha384 = x509Ecdsa(Digest.SHA384, KnownOIDs.ecdsaWithSHA384)
private val x509EcdsaSha512 = x509Ecdsa(Digest.SHA512, KnownOIDs.ecdsaWithSHA512)

private val x509RsaSha256Pss = x509RsaPss(Digest.SHA256)
private val x509RsaSha384Pss = x509RsaPss(Digest.SHA384)
private val x509RsaSha512Pss = x509RsaPss(Digest.SHA512)

private val x509RsaSha1Pkcs1 = x509RsaPkcs1(Digest.SHA1, KnownOIDs.sha1WithRSAEncryption)
private val x509RsaSha256Pkcs1 = x509RsaPkcs1(Digest.SHA256, KnownOIDs.sha256WithRSAEncryption)
private val x509RsaSha384Pkcs1 = x509RsaPkcs1(Digest.SHA384, KnownOIDs.sha384WithRSAEncryption)
private val x509RsaSha512Pkcs1 = x509RsaPkcs1(Digest.SHA512, KnownOIDs.sha512WithRSAEncryption)

private val x509BuiltInMappings = run {
    listOf(
        x509EcdsaSha256,
        x509EcdsaSha384,
        x509EcdsaSha512,
        x509RsaSha256Pss,
        x509RsaSha384Pss,
        x509RsaSha512Pss,
        x509RsaSha1Pkcs1,
        x509RsaSha256Pkcs1,
        x509RsaSha384Pkcs1,
        x509RsaSha512Pkcs1,
    ).forEach {
        AlgorithmRegistry.registerX509SignatureMapping(it.raw, it.algorithm, false)
    }
}

private fun parsePssSignatureAlgorithm(parameters: List<Asn1Element>): SignatureAlgorithm? = runCatching {
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
        KnownOIDs.sha_256 -> SignatureAlgorithm.RSA_SHA256_PSS.also {
            if (saltLen != 256 / 8) throw IllegalArgumentException("Non-recommended salt length used: $saltLen")
        }
        KnownOIDs.sha_384 -> SignatureAlgorithm.RSA_SHA384_PSS.also {
            if (saltLen != 384 / 8) throw IllegalArgumentException("Non-recommended salt length used: $saltLen")
        }
        KnownOIDs.sha_512 -> SignatureAlgorithm.RSA_SHA512_PSS.also {
            if (saltLen != 512 / 8) throw IllegalArgumentException("Non-recommended salt length used: $saltLen")
        }
        else -> throw IllegalArgumentException("Unsupported OID: $sigAlg")
    }
}.getOrNull()

private fun SignatureAlgorithmIdentifier.toSupportedOrNull(): X509SignatureAlgorithm? {
    x509BuiltInMappings
    val algorithm = when (oid) {
        KnownOIDs.rsaPSS -> parsePssSignatureAlgorithm(parameters)
        else -> AlgorithmRegistry.findSignatureAlgorithm(this)
    } ?: return null
    return X509SignatureAlgorithm(raw = this, algorithm = algorithm)
}

/** Finds a X.509 signature algorithm matching this algorithm. Curve restrictions are not preserved. */
fun SignatureAlgorithm.toX509SignatureAlgorithm() = catching {
    x509BuiltInMappings
    val raw = AlgorithmRegistry.findX509SignatureIdentifier(this)
        ?: throw UnsupportedCryptoException("$this is unsupported by X.509")
    val semantic = AlgorithmRegistry.findSignatureAlgorithm(raw) ?: this
    X509SignatureAlgorithm(raw, semantic)
}

/** Finds a X.509 signature algorithm matching this algorithm. Curve restrictions are not preserved. */
fun SpecializedSignatureAlgorithm.toX509SignatureAlgorithm() =
    this.algorithm.toX509SignatureAlgorithm()

/** Finds a raw signature algorithm identifier matching this semantic Signum signature algorithm. */
fun SignatureAlgorithm.toSignatureAlgorithmIdentifier() =
    toX509SignatureAlgorithm().map { it.raw }

/** Finds a raw signature algorithm identifier matching this semantic Signum signature algorithm. */
fun SpecializedSignatureAlgorithm.toSignatureAlgorithmIdentifier() =
    algorithm.toSignatureAlgorithmIdentifier()
