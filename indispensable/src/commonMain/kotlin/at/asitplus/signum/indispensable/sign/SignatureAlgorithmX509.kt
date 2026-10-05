package at.asitplus.signum.indispensable.sign

import at.asitplus.signum.Signum

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

import at.asitplus.signum.indispensable.installIndispensable

/** Original model first; fresh values are converted only when X.509 is requested. */
val SignatureAlgorithm.asn1Representation: X509AlgorithmIdentifier
    get() = representations[X509] as? X509AlgorithmIdentifier ?: run {
        Signum.installIndispensable()
        Signum.load<SignatureAlgorithmsProvider>().get(this, SignatureAlgorithmsProvider::encodeToAsn1)
    }

fun SignatureAlgorithm.Companion.fromAsn1Representation(src: X509AlgorithmIdentifier): SignatureAlgorithm =
    Signum.load<SignatureAlgorithmsProvider>().get(src, SignatureAlgorithmsProvider::getAlgorithm)

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
                // Nested conversion uses the application-wide DER configuration (docs/docs/default-der.md).
                X509AlgorithmIdentifier(currentParameters.asn1Representation, Signum.Der)
        }
    }

interface SignatureAlgorithmsProvider {
    /** Return the ASN.1 representation, or null if this provider does not support the value. */
    fun encodeToAsn1(value: SignatureAlgorithm): X509AlgorithmIdentifier? = null

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
            // Nested conversion uses the application-wide DER configuration (docs/docs/default-der.md).
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
    }, mapOf(X509 to src))

operator fun RsaAlgorithm.Companion.invoke(src: X509AlgorithmIdentifier): RsaAlgorithm = fromAsn1Representation(src)
