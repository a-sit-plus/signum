package at.asitplus.signum.indispensable

import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.awesn1.crypto.X509SignatureValue
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.Der
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.indispensable.integrity.SignatureAlgorithm
import at.asitplus.signum.indispensable.integrity.SpecializedSignatureAlgorithm

/**
 * Algorithm-agnostic signature value. X.509 algorithm context lives in [X509Signature].
 */
interface CryptoSignature : DerEncodable<X509SignatureValue> {

    /**
     * Well-defined signatures that can be encoded into raw bytes.
     */
    interface RawByteEncodable : CryptoSignature {
        val rawByteArray: ByteArray
    }

    private class X509Unparsed(override val asn1Representation: X509SignatureValue) : CryptoSignature

    val humanReadableString: String get() = "${this::class.simpleName ?: "CryptoSignature"}(signature=${encodeToTlv().prettyPrint()})"

    companion object : DerDecodable<X509SignatureValue, CryptoSignature> {
        operator fun invoke(signatureAlgorithm: SignatureAlgorithm, asn1Representation: X509SignatureValue, der: Der = DER) =
            decodeFromTlv(asn1Representation, der).withSignatureAlgorithm(signatureAlgorithm)
        operator fun invoke(x509Algorithm: X509AlgorithmIdentifier, asn1Representation: X509SignatureValue, der: Der = DER) =
            decodeFromTlv(asn1Representation, der).withX509Algorithm(x509Algorithm)
        override fun decodeFromTlv(element: X509SignatureValue, der: Der): CryptoSignature =
            X509Unparsed(element)
    }
}

val CryptoSignature.jcaSignatureBytes: ByteArray get() = asn1Representation.rawBytes
val CryptoSignature.iosEncoded get() = asn1Representation.rawBytes

fun CryptoSignature.Companion.parseFromJca(
    input: ByteArray,
    algorithm: SignatureAlgorithm
): CryptoSignature =
    CryptoSignature(algorithm, X509SignatureValue(input))

fun CryptoSignature.Companion.parseFromJca(
    input: ByteArray,
    algorithm: SpecializedSignatureAlgorithm
) = parseFromJca(input, algorithm.algorithm)

fun CryptoSignature.withSignatureAlgorithm(signatureAlgorithm: SignatureAlgorithm) =
    ServiceLoader.load<CryptoSignatureProvider>().get(signatureAlgorithm) {
        parseCryptoSignature(it, this@withSignatureAlgorithm)
    }

fun CryptoSignature.withSignatureAlgorithm(signatureAlgorithm: SpecializedSignatureAlgorithm) =
    withSignatureAlgorithm(signatureAlgorithm.algorithm)

fun CryptoSignature.withX509Algorithm(x509Algorithm: X509AlgorithmIdentifier) =
    ServiceLoader.load<CryptoSignatureProvider>().get(x509Algorithm) {
        parseCryptoSignature(it, this@withX509Algorithm)
    }

// @Service
interface CryptoSignatureProvider {
    /**
     * If the provider knows how to parse a signature for this [SignatureAlgorithm], it should try to parse
     * the provided [signature] as such.
     * Type checking is encouraged if re-parsing is expensive; if the signature is already of a suitable known type,
     * any (partial) parsing already done might be reused.
     *
     * If the [signatureAlgorithm] is unknown, `null` should be returned. */
    fun parseCryptoSignature(signatureAlgorithm: SignatureAlgorithm, signature: CryptoSignature): CryptoSignature?

    /**
     * If the provider recognizes this [X509AlgorithmIdentifier], it should try to parse the provided [signature].
     * Type checking is encouraged if re-parsing is expensive. If the signature is already of a suitable known type,
     * any (partial) parsing already done might be reused.
     *
     * If the [X509AlgorithmIdentifier] is unknown, `null` should be returned.
     */
    fun parseCryptoSignature(x509Algorithm: X509AlgorithmIdentifier, signature: CryptoSignature): CryptoSignature?
}
