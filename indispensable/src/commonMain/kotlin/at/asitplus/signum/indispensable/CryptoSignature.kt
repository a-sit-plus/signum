package at.asitplus.signum.indispensable

import at.asitplus.signum.Signum

import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.awesn1.crypto.X509SignatureValue
import at.asitplus.signum.indispensable.sign.SignatureAlgorithm
import at.asitplus.signum.indispensable.sign.SpecializedSignatureAlgorithm
import at.asitplus.signum.indispensable.sign.EcdsaSignature
import at.asitplus.signum.indispensable.sign.RsaSignature

/**
 * Parsed signature value. Unparsed values are [SignatureValue].
 */
interface CryptoSignature : Encodable {

    // TODO: providerize this; the names do not need to be preserved
    val joseBytes: ByteArray get() = TODO("providerize JOSE/COSE for generic provider-provided signature types")
    val coseBytes: ByteArray get() = joseBytes

        val humanReadableString: String get() = "${this::class.simpleName ?: "CryptoSignature"}(signature=${Signum.Der.encodeToTlv(X509SignatureValue.serializer(), asn1Representation).prettyPrint()})"

    @Deprecated(message = "Signature types migrated out of CryptoSignature as part of providerization",
        replaceWith = ReplaceWith("EcdsaSignature"))
    typealias EC = EcdsaSignature
    @Deprecated(message = "Signature types migrated out of CryptoSignature as part of providerization",
        replaceWith = ReplaceWith("RsaSignature"))
    typealias RSA = RsaSignature

    companion object : Decodable<SignatureValue> {
        init { Signum.installIndispensable() }
        operator fun invoke(signatureAlgorithm: SignatureAlgorithm, asn1Representation: X509SignatureValue) =
            fromAsn1Representation(asn1Representation).withSignatureAlgorithm(signatureAlgorithm)
        operator fun invoke(x509Algorithm: X509AlgorithmIdentifier, asn1Representation: X509SignatureValue) =
            fromAsn1Representation(asn1Representation).withX509Algorithm(x509Algorithm)
        fun fromAsn1Representation(element: X509SignatureValue): SignatureValue =
            SignatureValue(element)
        /** Loads the raw signature bytes (the *content* of the X509SignatureValue BIT STRING) */
        fun fromRawSignatureValue(sigBytes: ByteArray) =
            fromAsn1Representation(X509SignatureValue(sigBytes))
    }
}

fun SignatureValue.withSignatureAlgorithm(signatureAlgorithm: SignatureAlgorithm) =
    Signum.load<SignatureFormatProvider>().get(signatureAlgorithm) {
        parseCryptoSignature(it, this@withSignatureAlgorithm.asn1Representation)
    }

fun SignatureValue.withSignatureAlgorithm(signatureAlgorithm: SpecializedSignatureAlgorithm) =
    withSignatureAlgorithm(signatureAlgorithm.algorithm)

fun SignatureValue.withX509Algorithm(x509Algorithm: X509AlgorithmIdentifier) =
    Signum.load<SignatureFormatProvider>().get(x509Algorithm) {
        parseCryptoSignature(it, this@withX509Algorithm.asn1Representation)
    }

// @Service
interface SignatureFormatProvider {
    /** Return the ASN.1 representation, or null if this provider does not support the value. */
    fun encodeToAsn1(value: CryptoSignature): X509SignatureValue? = null

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

/** An uninterpreted BIT STRING; supply an algorithm before verification. */
class SignatureValue internal constructor(model: X509SignatureValue) : Encodable {
    override val sourceRepresentation: Pair<Encodable.Representation, Any>? = at.asitplus.signum.indispensable.pki.X509 to model
    companion object : Decodable<SignatureValue> {
        fun fromAsn1Representation(model: X509SignatureValue) = SignatureValue(model)
    }
}
