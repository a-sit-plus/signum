package at.asitplus.signum.indispensable.sign

import at.asitplus.awesn1.Asn1Null
import at.asitplus.awesn1.crypto.RsaSsaPssParams
import at.asitplus.awesn1.rsaPSS
import at.asitplus.awesn1.KnownOIDs
import at.asitplus.awesn1.crypto.RsaSsaPssParams.Companion.invoke
import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.awesn1.ecdsaWithSHA1
import at.asitplus.awesn1.ecdsaWithSHA256
import at.asitplus.awesn1.ecdsaWithSHA384
import at.asitplus.awesn1.ecdsaWithSHA512
import at.asitplus.awesn1.sha1WithRSAEncryption
import at.asitplus.awesn1.sha256WithRSAEncryption
import at.asitplus.awesn1.sha384WithRSAEncryption
import at.asitplus.awesn1.sha512WithRSAEncryption
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.pki.X509
import at.asitplus.signum.indispensable.digest.Digest

import at.asitplus.signum.ServiceLoader

/** Original model first; fresh values are converted only when X.509 is requested. */
val SignatureAlgorithm.asn1Representation: X509AlgorithmIdentifier
    get() = representations[X509] as? X509AlgorithmIdentifier ?: when (this) {
        is EcdsaAlgorithm -> asn1Representation
        is RsaAlgorithm -> asn1Representation
        else -> throw UnsupportedCryptoException("No X.509 representation for ${this::class.simpleName}")
    }

fun SignatureAlgorithm.Companion.fromAsn1Representation(src: X509AlgorithmIdentifier): SignatureAlgorithm =
    ServiceLoader.load<SignatureAlgorithmsProvider>().get(src, SignatureAlgorithmsProvider::getAlgorithm)

operator fun SignatureAlgorithm.Companion.invoke(src: X509AlgorithmIdentifier): SignatureAlgorithm =
    fromAsn1Representation(src)

val EcdsaAlgorithm.asn1Representation: X509AlgorithmIdentifier
    get() = representations[X509] as? X509AlgorithmIdentifier ?: run {
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
    get() = representations[X509] as? X509AlgorithmIdentifier ?: run {
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
                X509AlgorithmIdentifier(currentParameters.asn1Representation)
        }
    }

interface SignatureAlgorithmsProvider {
    /** Parse a [SignatureAlgorithm] from its [X509AlgorithmIdentifier] form */
    fun getAlgorithm(algorithmIdentifier: X509AlgorithmIdentifier): SignatureAlgorithm?
}

fun EcdsaAlgorithm.Companion.fromAsn1Representation(src: X509AlgorithmIdentifier): EcdsaAlgorithm =
    EcdsaAlgorithm({
        EcdsaAlgorithm.Params(when (src.oid) {
            KnownOIDs.ecdsaWithSHA1 -> Digest.SHA1
            KnownOIDs.ecdsaWithSHA256 -> Digest.SHA256
            KnownOIDs.ecdsaWithSHA384 -> Digest.SHA384
            KnownOIDs.ecdsaWithSHA512 -> Digest.SHA512
            else -> throw IllegalArgumentException("Unsupported algorithm ${src.oid}")
        }, null).also {
            require(src.parameters == null)
        }
    }, mapOf(X509 to src))

operator fun EcdsaAlgorithm.Companion.invoke(src: X509AlgorithmIdentifier): EcdsaAlgorithm = fromAsn1Representation(src)

fun RsaAlgorithm.Companion.fromAsn1Representation(src: X509AlgorithmIdentifier): RsaAlgorithm =
    RsaAlgorithm({
        val oid = src.oid
        if (oid == KnownOIDs.rsaPSS) {
            RsaAlgorithm.Parameters.PssPadded(RsaSsaPssParams.of(src))
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
    }, mapOf(X509 to src))

operator fun RsaAlgorithm.Companion.invoke(src: X509AlgorithmIdentifier): RsaAlgorithm = fromAsn1Representation(src)
