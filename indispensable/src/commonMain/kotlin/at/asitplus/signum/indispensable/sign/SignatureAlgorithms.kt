package at.asitplus.signum.indispensable.sign

import at.asitplus.awesn1.Asn1Null
import at.asitplus.awesn1.Asn1OctetString
import at.asitplus.awesn1.Identifiable
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
import at.asitplus.awesn1.serialization.Der
import at.asitplus.awesn1.sha1
import at.asitplus.awesn1.sha1WithRSAEncryption
import at.asitplus.awesn1.sha256WithRSAEncryption
import at.asitplus.awesn1.sha384WithRSAEncryption
import at.asitplus.awesn1.sha512WithRSAEncryption
import at.asitplus.awesn1.sha_224
import at.asitplus.awesn1.sha_256
import at.asitplus.awesn1.sha_384
import at.asitplus.awesn1.sha_512
import at.asitplus.signum.Enumeration
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.DerDecodable
import at.asitplus.signum.indispensable.DerEncodable
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.decodeFromTlv
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.integrity.SignatureAlgorithm
import at.asitplus.signum.indispensable.integrity.SignatureAlgorithmsProvider
import at.asitplus.signum.internals.orLazy

class ECDSAAlgorithm private constructor(
    private val providedParams: Params?,
    private val providedAsn1: X509AlgorithmIdentifier?,
) : SignatureAlgorithm {
    constructor(
        /** The digest to apply to the data, or `null` to directly process the raw data. */
        digest: Digest?,
        /** Whether this algorithm specifies a particular curve to use, or `null` for any curve. */
        requiredCurve: ECCurve? = null
    ) : this(Params(digest, requiredCurve), null)

    constructor(asn1Representation: X509AlgorithmIdentifier) : this(null, asn1Representation)

    private data class Params(val digest: Digest?, val curve: ECCurve?)

    private val params by providedParams orLazy {
        Params(when(providedAsn1!!.oid) {
            KnownOIDs.ecdsaWithSHA1 -> Digest.SHA1
            KnownOIDs.ecdsaWithSHA256 -> Digest.SHA256
            KnownOIDs.ecdsaWithSHA384 -> Digest.SHA384
            KnownOIDs.ecdsaWithSHA512 -> Digest.SHA512
            else -> throw IllegalArgumentException("Unsupported algorithm ${providedAsn1.oid}")
        }, null).also {
            require(providedAsn1.parameters == null)
        }
    }

    /** The digest to apply to the data, or `null` to directly process the raw data. */
    val digest get() = params.digest

    /** Whether this algorithm specifies a particular curve to use, or `null` for any curve. */
    val requiredCurve get() = params.curve

    override val asn1Representation: X509AlgorithmIdentifier by providedAsn1 orLazy {
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

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ECDSAAlgorithm) return false
        return params == other.params
    }

    override fun hashCode() = params.hashCode()

    companion object : Enumeration<ECDSAAlgorithm>, DerDecodable<X509AlgorithmIdentifier, ECDSAAlgorithm> {
        override val entries by lazy { listOf(withSHA256, withSHA384, withSHA512) }

        val withSHA256 = ECDSAAlgorithm(Digest.SHA256)
        val withSHA384 = ECDSAAlgorithm(Digest.SHA384)
        val withSHA512 = ECDSAAlgorithm(Digest.SHA512)

        override fun decodeFromTlv(
            element: X509AlgorithmIdentifier,
            der: Der
        ) = ECDSAAlgorithm(element)

    }
}

class RSAAlgorithm private constructor(
    providedParams: Parameters<*>?,
    private val providedAsn1: X509AlgorithmIdentifier?,
) : SignatureAlgorithm {

    constructor(
        /** The RSA signature parameters to apply to the data. */
        parameters: Parameters<*>
    ) : this(parameters, null)

    constructor(asn1Representation: X509AlgorithmIdentifier) : this(null, asn1Representation)

    /**
     * Convenience Ctor to use defaults aside digest
     */
    constructor(padding: Padding, digest: Digest) : this(Parameters(padding, digest))

    /** The RSA signature parameters to apply to the data. */
    val parameters: Parameters<*> by providedParams orLazy {
        val oid = providedAsn1!!.oid
        if (oid == KnownOIDs.rsaPSS) {
            Parameters.PssPadded(RsaSsaPssParams.of(providedAsn1))
        } else {
            when (oid) {
                KnownOIDs.sha1WithRSAEncryption -> Digest.SHA1
                KnownOIDs.sha256WithRSAEncryption -> Digest.SHA256
                KnownOIDs.sha384WithRSAEncryption -> Digest.SHA384
                KnownOIDs.sha512WithRSAEncryption -> Digest.SHA512
                // TODO: do we want to sub-providerize part of RSA here?
                //  or just let anyone who wants other-RSA do the legwork?
                else -> throw IllegalArgumentException("Unsupported algorithm ${providedAsn1.oid}")
            }.let { digest ->
                require(providedAsn1.parameters == Asn1Null)
                Parameters.Pkcs1Padded(digest)
            }
        }
    }

    /** The digest to apply to the data. */
    val digest get() = parameters.digest

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

    override val asn1Representation: X509AlgorithmIdentifier by providedAsn1 orLazy {
        when (val currentParameters = parameters) {
            is Parameters.Pkcs1Padded -> X509AlgorithmIdentifier(
                when (currentParameters.digest) {
                    Digest.SHA1 -> KnownOIDs.sha1WithRSAEncryption
                    Digest.SHA256 -> KnownOIDs.sha256WithRSAEncryption
                    Digest.SHA384 -> KnownOIDs.sha384WithRSAEncryption
                    Digest.SHA512 -> KnownOIDs.sha512WithRSAEncryption
                    else -> TODO("providerize")
                },
                Asn1Null
            )

            is Parameters.PssPadded ->
                X509AlgorithmIdentifier(currentParameters.asn1Representation)
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is RSAAlgorithm) return false
        return (parameters == other.parameters)
    }

    override fun hashCode() = parameters.hashCode()


    enum class Padding {
        PKCS1,
        PSS
    }

    companion object : Enumeration<RSAAlgorithm>, DerDecodable<X509AlgorithmIdentifier, RSAAlgorithm> {
        val withSHA256andPKCS1Padding = RSAAlgorithm(Parameters.Pkcs1Padded(Digest.SHA256))
        val withSHA384andPKCS1Padding = RSAAlgorithm(Parameters.Pkcs1Padded(Digest.SHA384))
        val withSHA512andPKCS1Padding = RSAAlgorithm(Parameters.Pkcs1Padded(Digest.SHA512))
        val withSHA256andPSSPadding = RSAAlgorithm(Parameters.PssPadded(Digest.SHA256))
        val withSHA384andPSSPadding = RSAAlgorithm(Parameters.PssPadded(Digest.SHA384))
        val withSHA512andPSSPadding = RSAAlgorithm(Parameters.PssPadded(Digest.SHA512))
        override val entries by lazy {
            listOf(withSHA256andPKCS1Padding, withSHA384andPKCS1Padding, withSHA512andPKCS1Padding,
                   withSHA256andPSSPadding,   withSHA384andPSSPadding,   withSHA512andPSSPadding)
        }

        override fun decodeFromTlv(
            element: X509AlgorithmIdentifier,
            der: Der
        ) = RSAAlgorithm(element)
    }


    sealed interface Parameters<T : RsaParams> : DerEncodable<T> {

        val type: Padding
        val digest: Digest

        class Pkcs1Padded(override val digest: Digest) :
            Parameters<RsaPkcs1PaddingParams> //TODO: do we want to keep cursed encodings? I don't think so in this case, because re-encoding a cursed encoding will only ever be part of a larger structure that already has it
        {
            override val asn1Representation: RsaPkcs1PaddingParams get() = RsaPkcs1PaddingParams
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

        class PssPadded private constructor(
            private val providedParams: Content?,
            private val rsaSsaPssParams: RsaSsaPssParams?
        ) : Parameters<RsaSsaPssParams> {
            constructor(
                digest: Digest = Digest.SHA1,
                mgfAlgorithm: MaskGenerationFunction = MaskGenerationFunction.Pkcs1Mgf1(digest),
                saltLength: UInt = digest.outputLength.bytes,
                trailerField: Int = DEFAULT_TRAILER_FIELD
            ) : this(Content(digest, mgfAlgorithm, saltLength, trailerField), null)

            constructor(asn1Representation: RsaSsaPssParams) : this(null, asn1Representation)

            private data class Content(
                val digest: Digest,
                val mgfAlgorithm: MaskGenerationFunction,
                val saltLength: UInt,
                val trailerField: Int,
            )

            override val asn1Representation: RsaSsaPssParams by rsaSsaPssParams orLazy {
                requireNotNull(providedParams)
                RsaSsaPssParams(
                    hashAlgorithm = providedParams.digest.asn1Representation,
                    maskGenAlgorithm = providedParams.mgfAlgorithm.asn1Representation,
                    saltLength = providedParams.saltLength.also { require(it <= Int.MAX_VALUE.toUInt()) }.toInt(),
                    trailerField = providedParams.trailerField
                )

            }

            private val params by providedParams orLazy {
                Content(
                    Digest.decodeFromTlv(rsaSsaPssParams!!.hashAlgorithm),
                    MaskGenerationFunction.decodeFromTlv(rsaSsaPssParams.maskGenAlgorithm),
                    rsaSsaPssParams.saltLength.let { require(it >= 0); it.toUInt() },
                    rsaSsaPssParams.trailerField
                )
            }

            override val type: Padding get() = Padding.PSS
            override val digest: Digest get() = params.digest
            val mgfAlgorithm get() = params.mgfAlgorithm
            val saltLength get() = params.saltLength
            val trailerField get() = params.trailerField

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

            sealed class MaskGenerationFunction(override val oid: ObjectIdentifier) : Identifiable, DerEncodable<X509AlgorithmIdentifier> {
                data class Pkcs1Mgf1(val digest: Digest = Digest.SHA1) : MaskGenerationFunction(oid) {
                    override val asn1Representation: X509AlgorithmIdentifier
                        get() = X509AlgorithmIdentifier(oid, digest.asn1Representation.element)
                    companion object : Identifiable {
                        override val oid: ObjectIdentifier = ObjectIdentifier("1.2.840.113549.1.1.8")
                    }
                }

                companion object : DerDecodable<X509AlgorithmIdentifier, MaskGenerationFunction> {
                    override fun decodeFromTlv(element: X509AlgorithmIdentifier, der: Der): MaskGenerationFunction =
                        runRethrowing {
                            // TODO: providerize
                            when (element.oid) {
                                Pkcs1Mgf1.oid ->
                                    Pkcs1Mgf1(Digest.decodeFromTlv(element.parameters!!, der))
                                else -> throw UnsupportedCryptoException("Unrecognized MGF OID ${element.oid}")
                            }
                        }
                }
            }

            companion object : DerDecodable<RsaSsaPssParams, PssPadded> {
                val DEFAULT_SHA256 = PssPadded(digest = Digest.SHA256)
                val DEFAULT_SHA384 = PssPadded(digest = Digest.SHA384)
                val DEFAULT_SHA512 = PssPadded(digest = Digest.SHA512)
                override fun decodeFromTlv(
                    element: RsaSsaPssParams,
                    der: Der
                ) = PssPadded(element)
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
    override fun getAlgorithms() = (ECDSAAlgorithm.entries + RSAAlgorithm.entries)

    override fun getAlgorithm(algorithmIdentifier: X509AlgorithmIdentifier) = when (algorithmIdentifier.oid) {
        KnownOIDs.ecdsaWithSHA1,
        KnownOIDs.ecdsaWithSHA256,
        KnownOIDs.ecdsaWithSHA384,
        KnownOIDs.ecdsaWithSHA512 -> ECDSAAlgorithm(algorithmIdentifier)

        KnownOIDs.sha1WithRSAEncryption,
        KnownOIDs.sha256WithRSAEncryption,
        KnownOIDs.sha384WithRSAEncryption,
        KnownOIDs.sha512WithRSAEncryption,
        KnownOIDs.rsaPSS -> RSAAlgorithm(algorithmIdentifier)

        else -> null
    }
}
