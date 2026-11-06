package at.asitplus.signum.indispensable.sign

import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.RsaSsaPssParams
import at.asitplus.awesn1.crypto.RsaSsaPssParams.Companion.invoke
import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.signum.Signum
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.finangleSourceRepresentation

val EcdsaAlgorithm.asn1Representation: X509AlgorithmIdentifier
    get() = run {
        X509AlgorithmIdentifier(
            oid = when (digest) {
                Digest.SHA1 -> KnownOIDs.ecdsaWithSHA1
                Digest.SHA256 -> KnownOIDs.ecdsaWithSHA256
                Digest.SHA384 -> KnownOIDs.ecdsaWithSHA384
                Digest.SHA512 -> KnownOIDs.ecdsaWithSHA512
                else -> throw IllegalArgumentException("Unsupported digest: $digest")
            },
            parameters = null
        )
    }

val RsaAlgorithm.asn1Representation: X509AlgorithmIdentifier
    get() = run {
        when (val currentParameters = parameters) {
            is RsaAlgorithm.Parameters.Pkcs1Padded -> X509AlgorithmIdentifier(
                when (currentParameters.digest) {
                    Digest.SHA1 -> KnownOIDs.sha1WithRSAEncryption
                    Digest.SHA256 -> KnownOIDs.sha256WithRSAEncryption
                    Digest.SHA384 -> KnownOIDs.sha384WithRSAEncryption
                    Digest.SHA512 -> KnownOIDs.sha512WithRSAEncryption
                    else -> throw UnsupportedCryptoException("Unknown RSA digest ${currentParameters.digest}")
                },
                Asn1Null
            )

            is RsaAlgorithm.Parameters.PssPadded ->
                    X509AlgorithmIdentifier(currentParameters.toAsn1(), Signum.Der)
        }
    }

interface SignatureAlgorithmsProvider {
    /** Return the ASN.1 representation, or null if this provider does not support the value. */
    fun encodeToAsn1(value: SignatureAlgorithm): X509AlgorithmIdentifier? = null

    /** Parse a [SignatureAlgorithm] from its [X509AlgorithmIdentifier] form */
    fun decodeFromAsn1(algorithmIdentifier: X509AlgorithmIdentifier): SignatureAlgorithm?
}

fun EcdsaAlgorithm.Companion.fromAsn1Representation(src: X509AlgorithmIdentifier): EcdsaAlgorithm =
    EcdsaAlgorithm(
        run {
            require(src.parameters == null)
            when (src.oid) {
                KnownOIDs.ecdsaWithSHA1 -> Digest.SHA1
                KnownOIDs.ecdsaWithSHA256 -> Digest.SHA256
                KnownOIDs.ecdsaWithSHA384 -> Digest.SHA384
                KnownOIDs.ecdsaWithSHA512 -> Digest.SHA512
                else -> throw IllegalArgumentException("Unsupported algorithm ${src.oid}")
            }
        },
        requiredCurve = null,
        // TODO: the usual
    ).apply { @OptIn(SignumInternals::class) finangleSourceRepresentation(src) }

operator fun EcdsaAlgorithm.Companion.invoke(src: X509AlgorithmIdentifier): EcdsaAlgorithm = fromAsn1Representation(src)

fun RsaAlgorithm.Companion.fromAsn1Representation(src: X509AlgorithmIdentifier): RsaAlgorithm =
    RsaAlgorithm(run {
        val oid = src.oid
        if (oid == KnownOIDs.rsaPSS) {
            RsaAlgorithm.Parameters.PssPadded(RsaSsaPssParams.of(src, Signum.Der))
        } else {
            when (oid) {
                KnownOIDs.sha1WithRSAEncryption -> Digest.SHA1
                KnownOIDs.sha256WithRSAEncryption -> Digest.SHA256
                KnownOIDs.sha384WithRSAEncryption -> Digest.SHA384
                KnownOIDs.sha512WithRSAEncryption -> Digest.SHA512
                else -> throw IllegalArgumentException("Unsupported algorithm ${src.oid}")
            }.let { digest ->
                require(src.parameters == Asn1Null)
                RsaAlgorithm.Parameters.Pkcs1Padded(digest)
            }
        }
        // TODO: the usual
    }).apply { @OptIn(SignumInternals::class) finangleSourceRepresentation(src) }

operator fun RsaAlgorithm.Companion.invoke(src: X509AlgorithmIdentifier): RsaAlgorithm = fromAsn1Representation(src)
