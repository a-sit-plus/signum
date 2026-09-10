package at.asitplus.signum.indispensable

import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.awesn1.crypto.X509SignatureValue
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.Der
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.indispensable.sign.SignatureAlgorithm
import at.asitplus.signum.indispensable.sign.SpecializedSignatureAlgorithm
import at.asitplus.signum.indispensable.sign.EcdsaSignature
import at.asitplus.signum.indispensable.sign.RsaSignature

/**
 * Parsed signature value. Unparsed values are [DerEncodable]<[X509SignatureValue]>.
 */
interface CryptoSignature : DerEncodable<X509SignatureValue> {

    // TODO: providerize this; the names do not need to be preserved
    val joseBytes: ByteArray get() = TODO("providerize JOSE/COSE for generic provider-provided signature types")
    val coseBytes: ByteArray get() = joseBytes

    private class X509Unparsed(override val asn1Representation: X509SignatureValue) : DerEncodable<X509SignatureValue>

    val humanReadableString: String get() = "${this::class.simpleName ?: "CryptoSignature"}(signature=${encodeToTlv().prettyPrint()})"

    @Deprecated(message = "Signature types migrated out of CryptoSignature as part of providerization",
        replaceWith = ReplaceWith("EcdsaSignature"))
    typealias EC = EcdsaSignature
    @Deprecated(message = "Signature types migrated out of CryptoSignature as part of providerization",
        replaceWith = ReplaceWith("RsaSignature"))
    typealias RSA = RsaSignature

    companion object : DerDecodable<X509SignatureValue, DerEncodable<X509SignatureValue>> {
        init { Indispensable.init() }
        operator fun invoke(signatureAlgorithm: SignatureAlgorithm, asn1Representation: X509SignatureValue, der: Der = DER) =
            decodeFromTlv(asn1Representation, der).withSignatureAlgorithm(signatureAlgorithm)
        operator fun invoke(x509Algorithm: X509AlgorithmIdentifier, asn1Representation: X509SignatureValue, der: Der = DER) =
            decodeFromTlv(asn1Representation, der).withX509Algorithm(x509Algorithm)
        override fun decodeFromTlv(element: X509SignatureValue, der: Der): DerEncodable<X509SignatureValue> =
            X509Unparsed(element)
        /** Loads the raw signature bytes (the *content* of the X509SignatureValue BIT STRING) */
        fun fromRawSignatureValue(sigBytes: ByteArray) =
            decodeFromTlv(X509SignatureValue(sigBytes))
    }
}

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
