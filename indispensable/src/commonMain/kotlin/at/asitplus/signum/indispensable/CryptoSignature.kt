package at.asitplus.signum.indispensable

import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.awesn1.crypto.X509SignatureValue
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.Der
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.indispensable.integrity.SignatureAlgorithm
import at.asitplus.signum.indispensable.integrity.SpecializedSignatureAlgorithm
import at.asitplus.signum.indispensable.sign.ECDSASignature
import at.asitplus.signum.indispensable.sign.RSASignature

/**
 * Parsed signature value. Unparsed values are [DerEncodable]<[X509SignatureValue]>.
 */
interface CryptoSignature : DerEncodable<X509SignatureValue> {

    /**
     * Well-defined signatures that can be encoded into raw bytes.
     */
    interface RawByteEncodable : CryptoSignature {
        val rawByteArray: ByteArray
    }

    private class X509Unparsed(override val asn1Representation: X509SignatureValue) : DerEncodable<X509SignatureValue>

    val humanReadableString: String get() = "${this::class.simpleName ?: "CryptoSignature"}(signature=${encodeToTlv().prettyPrint()})"

    @Deprecated(message = "Signature types migrated out of CryptoSignature as part of providerization",
        replaceWith = ReplaceWith("ECDSASignature"))
    typealias EC = ECDSASignature
    @Deprecated(message = "Signature types migrated out of CryptoSignature as part of providerization",
        replaceWith = ReplaceWith("RSASignature"))
    typealias RSA = RSASignature

    companion object : DerDecodable<X509SignatureValue, DerEncodable<X509SignatureValue>> {
        init { Indispensable.init() }
        operator fun invoke(signatureAlgorithm: SignatureAlgorithm, asn1Representation: X509SignatureValue, der: Der = DER) =
            decodeFromTlv(asn1Representation, der).withSignatureAlgorithm(signatureAlgorithm)
        operator fun invoke(x509Algorithm: X509AlgorithmIdentifier, asn1Representation: X509SignatureValue, der: Der = DER) =
            decodeFromTlv(asn1Representation, der).withX509Algorithm(x509Algorithm)
        override fun decodeFromTlv(element: X509SignatureValue, der: Der): DerEncodable<X509SignatureValue> =
            X509Unparsed(element)
    }
}

val CryptoSignature.jcaSignatureBytes: ByteArray get() = asn1Representation.rawBytes
val CryptoSignature.iosEncoded get() = asn1Representation.rawBytes

fun CryptoSignature.Companion.parseFromJca(input: ByteArray) =
    CryptoSignature.decodeFromTlv(X509SignatureValue(input))

fun CryptoSignature.Companion.parseFromJca(
    input: ByteArray,
    algorithm: SignatureAlgorithm
): CryptoSignature =
    CryptoSignature(algorithm, X509SignatureValue(input))

fun CryptoSignature.Companion.parseFromJca(
    input: ByteArray,
    algorithm: SpecializedSignatureAlgorithm
) = parseFromJca(input, algorithm.algorithm)

fun DerEncodable<X509SignatureValue>.withSignatureAlgorithm(signatureAlgorithm: SignatureAlgorithm) =
    ServiceLoader.load<SignatureFormatProvider>().get(signatureAlgorithm) {
        parseCryptoSignature(it, this@withSignatureAlgorithm.asn1Representation)
    }

fun DerEncodable<X509SignatureValue>.withSignatureAlgorithm(signatureAlgorithm: SpecializedSignatureAlgorithm) =
    withSignatureAlgorithm(signatureAlgorithm.algorithm)

fun DerEncodable<X509SignatureValue>.withX509Algorithm(x509Algorithm: X509AlgorithmIdentifier) =
    ServiceLoader.load<SignatureFormatProvider>().get(x509Algorithm) {
        parseCryptoSignature(it, this@withX509Algorithm.asn1Representation)
    }

// @Service
interface SignatureFormatProvider {
    /**
     * If the provider recognizes this [SignatureAlgorithm], it should try to parse the provided [signature].
     * the provided [signature] as such.
     * If the [signatureAlgorithm] is unknown, `null` should be returned. */
    fun parseCryptoSignature(signatureAlgorithm: SignatureAlgorithm, signature: X509SignatureValue): CryptoSignature?

    /**
     * If the provider recognizes this [X509AlgorithmIdentifier], it should try to parse the provided [signature].
     * If the [X509AlgorithmIdentifier] is unknown, `null` should be returned.
     */
    fun parseCryptoSignature(x509Algorithm: X509AlgorithmIdentifier, signature: X509SignatureValue): CryptoSignature?
}
