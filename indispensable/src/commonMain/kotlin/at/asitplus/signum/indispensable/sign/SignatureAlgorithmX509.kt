package at.asitplus.signum.indispensable.sign

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Null
import at.asitplus.awesn1.KnownOIDs
import at.asitplus.awesn1.crypto.RsaSsaPssParams.Companion.invoke
import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.awesn1.ecdsaWithSHA1
import at.asitplus.awesn1.ecdsaWithSHA256
import at.asitplus.awesn1.ecdsaWithSHA384
import at.asitplus.awesn1.ecdsaWithSHA512
import at.asitplus.awesn1.serialization.Der
import at.asitplus.awesn1.sha1WithRSAEncryption
import at.asitplus.awesn1.sha256WithRSAEncryption
import at.asitplus.awesn1.sha384WithRSAEncryption
import at.asitplus.awesn1.sha512WithRSAEncryption
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.SignatureAlgorithmX509Serializer
import at.asitplus.signum.indispensable.EcdsaAlgorithmX509Serializer
import at.asitplus.signum.indispensable.RsaAlgorithmX509Serializer
import at.asitplus.signum.indispensable.pki.X509
import at.asitplus.signum.indispensable.digest.Digest

import at.asitplus.signum.ServiceLoader
import at.asitplus.awesn1.serialization.DER

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

fun EcdsaAlgorithm.Companion.fromAsn1Representation(src: X509AlgorithmIdentifier) = EcdsaAlgorithm(src)
fun RsaAlgorithm.Companion.fromAsn1Representation(src: X509AlgorithmIdentifier) = RsaAlgorithm(src)

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

// Compatibility while the remaining consumers migrate to format operations.
fun SignatureAlgorithm.encodeToDer(der: Der = DER) =
    der.encodeToByteArray(SignatureAlgorithmX509Serializer, this)
fun SignatureAlgorithm.encodeToTlv(der: Der = DER) =
    der.encodeToTlv(SignatureAlgorithmX509Serializer, this)
fun SignatureAlgorithm.Companion.decodeFromTlv(src: X509AlgorithmIdentifier, der: Der = DER) = fromAsn1Representation(src)
fun SignatureAlgorithm.Companion.decodeFromTlv(src: Asn1Element, der: Der = DER) =
    der.decodeFromTlv(SignatureAlgorithmX509Serializer, src)
fun SignatureAlgorithm.Companion.decodeFromDer(src: ByteArray, der: Der = DER) =
    der.decodeFromByteArray(SignatureAlgorithmX509Serializer, src)
fun EcdsaAlgorithm.Companion.decodeFromTlv(src: X509AlgorithmIdentifier, der: Der = DER) = fromAsn1Representation(src)
fun EcdsaAlgorithm.Companion.decodeFromTlv(src: Asn1Element, der: Der = DER) =
    der.decodeFromTlv(EcdsaAlgorithmX509Serializer, src)
fun RsaAlgorithm.Companion.decodeFromTlv(src: X509AlgorithmIdentifier, der: Der = DER) = fromAsn1Representation(src)
fun RsaAlgorithm.Companion.decodeFromTlv(src: Asn1Element, der: Der = DER) =
    der.decodeFromTlv(RsaAlgorithmX509Serializer, src)

interface SignatureAlgorithmsProvider {
    /** Parse a [SignatureAlgorithm] from its [X509AlgorithmIdentifier] form */
    fun getAlgorithm(algorithmIdentifier: X509AlgorithmIdentifier): SignatureAlgorithm?
}
