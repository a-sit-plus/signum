package at.asitplus.signum.indispensable.sign

import at.asitplus.signum.Signum
import at.asitplus.awesn1.serialization.decodeFromTlv

import at.asitplus.awesn1.Asn1Null
import at.asitplus.awesn1.Asn1OctetString
import at.asitplus.awesn1.KnownOIDs
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.RsaParams
import at.asitplus.awesn1.crypto.RsaPkcs1PaddingParams
import at.asitplus.awesn1.crypto.RsaSsaPssParams
import at.asitplus.awesn1.crypto.RsaSsaPssParams.Companion.DEFAULT_TRAILER_FIELD
import at.asitplus.awesn1.crypto.RsaSsaPssParams.Companion.invoke
import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.awesn1.ecdsaWithSHA1
import at.asitplus.awesn1.ecdsaWithSHA256
import at.asitplus.awesn1.ecdsaWithSHA384
import at.asitplus.awesn1.ecdsaWithSHA512
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.rsaPSS
import at.asitplus.awesn1.runRethrowing
import at.asitplus.signum.indispensable.digest.asn1Representation
import at.asitplus.awesn1.sha1
import at.asitplus.awesn1.sha1WithRSAEncryption
import at.asitplus.awesn1.sha256WithRSAEncryption
import at.asitplus.awesn1.sha384WithRSAEncryption
import at.asitplus.awesn1.sha512WithRSAEncryption
import at.asitplus.awesn1.sha_224
import at.asitplus.awesn1.sha_256
import at.asitplus.awesn1.sha_384
import at.asitplus.awesn1.sha_512
import at.asitplus.signum.Enumerable
import at.asitplus.signum.Enumeration
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.Encodable
import at.asitplus.signum.indispensable.Decodable
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.digest.Digest

class EcdsaAlgorithm internal constructor(
    digestProvider: () -> Digest?,
    requiredCurveProvider: () -> ECCurve?,
    override val representations: Map<Encodable.Representation, Any>,
) : SignatureAlgorithm, Enumerable {

    constructor(
        /** The digest to apply to the data, or `null` to directly process the raw data. */
        digest: Digest?,
        /** Whether this algorithm specifies a particular curve to use, or `null` for any curve. */
        requiredCurve: ECCurve? = null
    ) : this({ digest }, { requiredCurve }, emptyMap())

    /** The digest to apply to the data, or `null` to directly process the raw data. */
    val digest by lazy(digestProvider)
    override val preHashedSignatureFormat get() = digest

    /** Whether this algorithm specifies a particular curve to use, or `null` for any curve. */
    val requiredCurve by lazy(requiredCurveProvider)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is EcdsaAlgorithm) return false
        return digest == other.digest && requiredCurve == other.requiredCurve
    }

    override fun hashCode() = 31 * (digest?.hashCode() ?: 0) + (requiredCurve?.hashCode() ?: 0)

    companion object : Enumeration<EcdsaAlgorithm>, Decodable<EcdsaAlgorithm> {
        override val entries by lazy { listOf(withSHA256, withSHA384, withSHA512) }

        val withSHA256 = EcdsaAlgorithm(Digest.SHA256)
        val withSHA384 = EcdsaAlgorithm(Digest.SHA384)
        val withSHA512 = EcdsaAlgorithm(Digest.SHA512)

    }
}

class RsaAlgorithm internal constructor(
    paramsProvider: () -> Parameters<*>,
    override val representations: Map<Encodable.Representation, Any>,
) : SignatureAlgorithm, Enumerable {

    constructor(
        /** The RSA signature parameters to apply to the data. */
        parameters: Parameters<*>
    ) : this({ parameters }, emptyMap())

    /**
     * Convenience Ctor to use defaults aside digest
     */
    constructor(padding: Padding, digest: Digest) : this(Parameters(padding, digest))

    /** The RSA signature parameters to apply to the data. */
    val parameters by lazy(paramsProvider)

    /** The digest to apply to the data. */
    val digest get() = parameters.digest
    override val preHashedSignatureFormat get() = digest

    /** minimum key size, in full bytes, for these RSA parameters */
    val minimumKeySize get(): Int = when (val params = parameters) {
        is Parameters.Pkcs1Padded -> {
            11 + Asn1.Sequence {
                /**
                 * RFC 8017 Page 71:
                 *  -- Exception: When formatting the DigestInfoValue in EMSA-PKCS1-v1_5
                 *  -- (see Section 9.2), the parameters field associated with id-sha1,
                 *  -- id-sha224, id-sha256, id-sha384, id-sha512, id-sha512-224, and
                 *  -- id-sha512-256 SHALL have a value of type NULL.  This is to
                 *  -- maintain compatibility with existing implementations and with the
                 *  -- numeric information values already published for EMSA-PKCS1-v1_5,
                 *  -- which are also reflected in IEEE 1363a.
                 */
                +(params.digest.asn1Representation.let {
                    val exceptions = sequenceOf(
                        KnownOIDs.sha1, KnownOIDs.sha_224, KnownOIDs.sha_256, KnownOIDs.sha_384,
                        KnownOIDs.sha_512 /* TODO: sha512-224, sha512-256 */)
                    if (it.parameters == null && exceptions.contains(it.oid))
                        X509AlgorithmIdentifier(it.oid, Asn1Null)
                    else it
                })
                +Asn1OctetString(ByteArray(params.digest.outputLength.bytes.toInt()))
            }.overallLength
        }
        is Parameters.PssPadded -> {
            params.digest.outputLength.bytes.toInt() + params.saltLength.toInt() + 1 + params.trailerField
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is RsaAlgorithm) return false
        return (parameters == other.parameters)
    }

    override fun hashCode() = parameters.hashCode()

    enum class Padding {
        PKCS1,
        PSS
    }

    companion object : Enumeration<RsaAlgorithm>, Decodable<RsaAlgorithm> {
        val withSHA256andPKCS1Padding = RsaAlgorithm(Parameters.Pkcs1Padded(Digest.SHA256))
        val withSHA384andPKCS1Padding = RsaAlgorithm(Parameters.Pkcs1Padded(Digest.SHA384))
        val withSHA512andPKCS1Padding = RsaAlgorithm(Parameters.Pkcs1Padded(Digest.SHA512))
        val withSHA256andPSSPadding = RsaAlgorithm(Parameters.PssPadded(Digest.SHA256))
        val withSHA384andPSSPadding = RsaAlgorithm(Parameters.PssPadded(Digest.SHA384))
        val withSHA512andPSSPadding = RsaAlgorithm(Parameters.PssPadded(Digest.SHA512))
        override val entries by lazy {
            listOf(withSHA256andPKCS1Padding, withSHA384andPKCS1Padding, withSHA512andPKCS1Padding,
                   withSHA256andPSSPadding,   withSHA384andPSSPadding,   withSHA512andPSSPadding)
        }

    }

    sealed interface Parameters<out T : RsaParams> : Encodable {

        val type: Padding
        val digest: Digest

        class Pkcs1Padded(override val digest: Digest) :
            Parameters<RsaPkcs1PaddingParams> //TODO: do we want to keep cursed encodings? I don't think so in this case, because re-encoding a cursed encoding will only ever be part of a larger structure that already has it
        {
            override val type: Padding get() = Padding.PKCS1
            override fun equals(other: Any?): Boolean {
                if (this === other) return true
                if (other !is Pkcs1Padded) return false
                return digest == other.digest
            }

            override fun hashCode(): Int =
                digest.hashCode()

            companion object {
                val SHA1 = Pkcs1Padded(Digest.SHA1)
                val SHA256 = Pkcs1Padded(Digest.SHA256)
                val SHA384 = Pkcs1Padded(Digest.SHA384)
                val SHA512 = Pkcs1Padded(Digest.SHA512)

                val entries = setOf(SHA1, SHA256, SHA384, SHA512)
            }
        }

        class PssPadded internal constructor(
            digestProvider: () -> Digest,
            mgfAlgorithmProvider: () -> MaskGenerationFunction,
            saltLengthProvider: () -> UInt,
            trailerFieldProvider: () -> Int,
            override val representations: Map<Encodable.Representation, Any>,
        ) : Parameters<RsaSsaPssParams> {
            constructor(
                digest: Digest = Digest.SHA1,
                mgfAlgorithm: MaskGenerationFunction = MaskGenerationFunction.Pkcs1Mgf1(digest),
                saltLength: UInt = digest.outputLength.bytes,
                trailerField: Int = DEFAULT_TRAILER_FIELD,
            ) : this({ digest }, { mgfAlgorithm }, { saltLength }, { trailerField }, emptyMap())

            override val type: Padding get() = Padding.PSS
            override val digest: Digest by lazy(digestProvider)
            val mgfAlgorithm by lazy(mgfAlgorithmProvider)
            val saltLength by lazy(saltLengthProvider)
            val trailerField by lazy(trailerFieldProvider)

            override fun equals(other: Any?): Boolean {
                if (this === other) return true
                if (other !is PssPadded) return false
                return digest == other.digest &&
                        mgfAlgorithm == other.mgfAlgorithm &&
                        saltLength == other.saltLength &&
                        trailerField == other.trailerField
            }

            override fun hashCode(): Int {
                var result = digest.hashCode()
                result = 31 * result + mgfAlgorithm.hashCode()
                result = 31 * result + saltLength.hashCode()
                result = 31 * result + trailerField
                return result
            }

            sealed class MaskGenerationFunction(val oid: ObjectIdentifier) : Encodable {
                data class Pkcs1Mgf1(val digest: Digest = Digest.SHA1) : MaskGenerationFunction(oid) {
                    companion object {
                        val oid: ObjectIdentifier = ObjectIdentifier("1.2.840.113549.1.1.8")
                    }
                }

                companion object : Decodable<MaskGenerationFunction> {
                    fun fromAsn1Representation(element: X509AlgorithmIdentifier): MaskGenerationFunction =
                        runRethrowing {
                            when (element.oid) {
                                Pkcs1Mgf1.oid ->
                                                                        Pkcs1Mgf1(Digest.fromAsn1Representation(Signum.Der.decodeFromTlv(X509AlgorithmIdentifier.serializer(), element.parameters!!)))
                                else -> throw UnsupportedCryptoException("Unrecognized MGF OID ${element.oid}")
                            }
                        }
                }
            }

            companion object : Decodable<PssPadded> {
                val DEFAULT_SHA256 = PssPadded(digest = Digest.SHA256)
                val DEFAULT_SHA384 = PssPadded(digest = Digest.SHA384)
                val DEFAULT_SHA512 = PssPadded(digest = Digest.SHA512)
            }
        }

        companion object {

            operator fun invoke(padding: Padding, digest: Digest) = when (padding) {
                Padding.PSS -> PssPadded(digest = digest)
                Padding.PKCS1 -> Pkcs1Padded(digest = digest)
            }

            val entries by lazy {
                Pkcs1Padded.entries + setOf(
                    PssPadded.DEFAULT_SHA512,
                    PssPadded.DEFAULT_SHA256,
                    PssPadded.DEFAULT_SHA384
                )
            }
        }
    }

}

object IndispensableSignatureAlgorithmsProvider : SignatureAlgorithmsProvider {
    override fun encodeToAsn1(value: SignatureAlgorithm): X509AlgorithmIdentifier? = when (value) {
        is EcdsaAlgorithm -> value.asn1Representation
        is RsaAlgorithm -> value.asn1Representation
        else -> null
    }

    override fun getAlgorithm(algorithmIdentifier: X509AlgorithmIdentifier): SignatureAlgorithm? = when (algorithmIdentifier.oid) {
        KnownOIDs.ecdsaWithSHA1,
        KnownOIDs.ecdsaWithSHA256,
        KnownOIDs.ecdsaWithSHA384,
        KnownOIDs.ecdsaWithSHA512 -> EcdsaAlgorithm(algorithmIdentifier)

        KnownOIDs.sha1WithRSAEncryption,
        KnownOIDs.sha256WithRSAEncryption,
        KnownOIDs.sha384WithRSAEncryption,
        KnownOIDs.sha512WithRSAEncryption,
        KnownOIDs.rsaPSS -> RsaAlgorithm(algorithmIdentifier)

        else -> null
    }
}
