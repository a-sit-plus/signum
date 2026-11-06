package at.asitplus.signum.indispensable

import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.awesn1.crypto.X509SignatureValue
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.Signum
import at.asitplus.signum.indispensable.sign.EcdsaSignature
import at.asitplus.signum.indispensable.sign.RsaSignature
import at.asitplus.signum.indispensable.sign.SignatureAlgorithm
import at.asitplus.signum.indispensable.sign.SpecializedSignatureAlgorithm

/**
 * Parsed signature value. Unparsed values are [SignatureValue].
 */
interface CryptoSignature : WithSourceRepresentation, AbstractSignature {

    override fun withSignatureAlgorithm(signatureAlgorithm: SignatureAlgorithm) =
        // TODO: this copies the old behavior (always going via asn1) for fully-defined sigs
        // maybe we want to be more nuanced here?
        CryptoSignature.fromAsn1(toAsn1())
            .withSignatureAlgorithm(signatureAlgorithm)

    // TODO: providerize this; the names do not need to be preserved
    val joseBytes: ByteArray get() = TODO("providerize JOSE/COSE for generic provider-provided signature types")
    val coseBytes: ByteArray get() = joseBytes

    val humanReadableString: String get() = "${this::class.simpleName ?: "CryptoSignature"}(signature=${toAsn1.TLV().prettyPrint()})"

    @Deprecated(message = "Signature types migrated out of CryptoSignature as part of providerization",
        replaceWith = ReplaceWith("EcdsaSignature"))
    typealias EC = EcdsaSignature
    @Deprecated(message = "Signature types migrated out of CryptoSignature as part of providerization",
        replaceWith = ReplaceWith("RsaSignature"))
    typealias RSA = RsaSignature

    companion object {
        init { Signum.installIndispensable() }
        operator fun invoke(signatureAlgorithm: SignatureAlgorithm, asn1Representation: X509SignatureValue) =
            fromAsn1(asn1Representation).withSignatureAlgorithm(signatureAlgorithm)
        operator fun invoke(x509Algorithm: X509AlgorithmIdentifier, asn1Representation: X509SignatureValue) =
            fromAsn1(asn1Representation).withX509Algorithm(x509Algorithm)
        /** Loads the raw signature bytes (the *content* of the X509SignatureValue BIT STRING) */
        fun fromRawSignatureValue(sigBytes: ByteArray) =
            fromAsn1(X509SignatureValue(sigBytes))
    }
}

fun AbstractSignature.withSignatureAlgorithm(signatureAlgorithm: SpecializedSignatureAlgorithm) =
    withSignatureAlgorithm(signatureAlgorithm.algorithm)

fun AbstractSignature.withX509Algorithm(x509Algorithm: X509AlgorithmIdentifier) =
    ServiceLoader.load<SignatureFormatProvider>().get(x509Algorithm) {
        parseCryptoSignature(it, this@withX509Algorithm.toAsn1())
    }

// @Service
interface SignatureFormatProvider {
    /** Return the ASN.1 representation, or null if this provider does not support the value. */
    fun encodeToAsn1(value: CryptoSignature): X509SignatureValue? = null

    /**
     * If the provider recognizes this [SignatureAlgorithm], it should try to parse the provided [signature].
     * the provided [signature] as such.
     * If the [signatureAlgorithm] is unknown, `null` should be returned. */
    // TODO: do we want this to stay pegged to asn1?
    fun parseCryptoSignature(signatureAlgorithm: SignatureAlgorithm, signature: X509SignatureValue): CryptoSignature?

    /**
     * If the provider recognizes this [X509AlgorithmIdentifier], it should try to parse the provided [signature].
     * If the [X509AlgorithmIdentifier] is unknown, `null` should be returned.
     */
    fun parseCryptoSignature(x509Algorithm: X509AlgorithmIdentifier, signature: X509SignatureValue): CryptoSignature?
}

/** A potentially-malleable signature, which needs algorithm information to be fully specified. */
interface AbstractSignature : WithSourceRepresentation {
    fun withSignatureAlgorithm(signatureAlgorithm: SignatureAlgorithm): CryptoSignature
    companion object
}

/** An uninterpreted signature; supply an algorithm before verification. */
