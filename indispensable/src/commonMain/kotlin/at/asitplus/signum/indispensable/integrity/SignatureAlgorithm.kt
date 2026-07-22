package at.asitplus.signum.indispensable.integrity

import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.RsaParams
import at.asitplus.awesn1.crypto.RsaPkcs1PaddingParams
import at.asitplus.awesn1.crypto.RsaSsaPssParams
import at.asitplus.awesn1.crypto.RsaSsaPssParams.Companion.DEFAULT_TRAILER_FIELD
import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.Der
import at.asitplus.awesn1.serialization.decodeFromTlv
import at.asitplus.awesn1.serialization.encodeToTlv
import at.asitplus.signum.Enumeration
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.DerDecodable
import at.asitplus.signum.indispensable.DerEncodable
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.Indispensable
import at.asitplus.signum.indispensable.decodeFromTlv
import at.asitplus.signum.internals.orLazy
import at.asitplus.signum.internals.orLazyNullable
import kotlinx.serialization.KSerializer

//for now, we just replicate the pattern, but since everything is sealed, we don't actually parse
interface SignatureAlgorithm : DataIntegrityAlgorithm, DerEncodable<X509AlgorithmIdentifier> {

    class ECDSA private constructor(
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

        /** The digest to apply to the data, or `null` to directly process the raw data. */
        val digest: Digest? by providedParams.orLazyNullable(
            provided = { digest },
            fallback = {
                when (providedAsn1!!.oid) {
                    KnownOIDs.ecdsaWithSHA1 -> Digest.SHA1
                    KnownOIDs.ecdsaWithSHA256 -> Digest.SHA256
                    KnownOIDs.ecdsaWithSHA384 -> Digest.SHA384
                    KnownOIDs.ecdsaWithSHA512 -> Digest.SHA512
                    else -> throw IllegalArgumentException("Unsupported algorithm ${providedAsn1.oid}")
                }
            }
        )

        /** Whether this algorithm specifies a particular curve to use, or `null` for any curve. */
        val requiredCurve: ECCurve? by providedParams.orLazyNullable(
            provided = { curve },
            fallback = { null },
        )

        override val asn1Representation: X509AlgorithmIdentifier by providedAsn1 orLazy {
            X509AlgorithmIdentifier(
                oid = when (digest) {
                    Digest.SHA1 -> KnownOIDs.ecdsaWithSHA1
                    Digest.SHA256 -> KnownOIDs.ecdsaWithSHA256
                    Digest.SHA384 -> KnownOIDs.ecdsaWithSHA384
                    Digest.SHA512 -> KnownOIDs.ecdsaWithSHA512
                    else -> throw IllegalArgumentException("Unsupported digest: $digest")
                },
                parameters = emptyList()
            )
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is ECDSA) return false
            return (digest == other.digest && requiredCurve == other.requiredCurve)
        }

        override fun hashCode(): Int {
            var result = digest.hashCode()
            result = 31 * result + (requiredCurve?.hashCode() ?: 0)
            return result
        }

        companion object : Enumeration<ECDSA>, DerDecodable<X509AlgorithmIdentifier, ECDSA> {
            override val entries: Set<ECDSA> by lazy {
                setOf(
                    ECDSAwithSHA256,
                    ECDSAwithSHA384,
                    ECDSAwithSHA512
                )
            }

            override fun decodeFromTlv(
                element: X509AlgorithmIdentifier,
                der: Der
            ) = ECDSA(element)

        }
    }

    class RSA private constructor(
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

        /** The digest to apply to the data. */
        val digest: Digest by providedParams?.digest orLazy {
            when (providedAsn1!!.oid) {
                KnownOIDs.sha1WithRSAEncryption -> Digest.SHA1
                KnownOIDs.sha256WithRSAEncryption -> Digest.SHA256
                KnownOIDs.sha384WithRSAEncryption -> Digest.SHA384
                KnownOIDs.sha512WithRSAEncryption -> Digest.SHA512
                KnownOIDs.rsaPSS -> Parameters.PssPadded(providedAsn1.rsaSsaPssParams!!).digest
                else -> throw IllegalArgumentException("Unsupported algorithm ${providedAsn1.oid}")
            }
        }

        /** The RSA signature parameters to apply to the data. */
        val parameters: Parameters<*> by providedParams orLazy {
            when (providedAsn1!!.oid) {
                KnownOIDs.sha1WithRSAEncryption -> Parameters.Pkcs1Padded(Digest.SHA1)
                KnownOIDs.sha256WithRSAEncryption -> Parameters.Pkcs1Padded(Digest.SHA256)
                KnownOIDs.sha384WithRSAEncryption -> Parameters.Pkcs1Padded(Digest.SHA384)
                KnownOIDs.sha512WithRSAEncryption -> Parameters.Pkcs1Padded(Digest.SHA512)
                KnownOIDs.rsaPSS -> Parameters.PssPadded(providedAsn1.rsaSsaPssParams!!)
                else -> throw IllegalArgumentException("Unsupported algorithm ${providedAsn1.oid}")
            }
        }

        /** minimum key size, in full bytes, for these RSA parameters */
        val minimumKeySize get(): Int = when (val params = parameters) {
            is Parameters.Pkcs1Padded -> {
                11 + Asn1.Sequence {
                    +params.digest.asn1Representation.element
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
                    listOf(Asn1Null)
                )

                is Parameters.PssPadded -> X509AlgorithmIdentifier(
                    KnownOIDs.rsaPSS,
                    listOf(DER.encodeToTlv(currentParameters.asn1Representation))
                )
            }
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is RSA) return false
            return (parameters == other.parameters)
        }

        override fun hashCode() = parameters.hashCode()


        enum class Padding {
            PKCS1,
            PSS
        }

        companion object : Enumeration<RSA>, DerDecodable<X509AlgorithmIdentifier, RSA> {
            override val entries: Set<RSA> by lazy {
                setOf(
                    RSAwithSHA256andPSSPadding,
                    RSAwithSHA384andPSSPadding,
                    RSAwithSHA512andPSSPadding,

                    RSAwithSHA256andPKCS1Padding,
                    RSAwithSHA384andPKCS1Padding,
                    RSAwithSHA512andPKCS1Padding
                )
            }

            override fun decodeFromTlv(
                element: X509AlgorithmIdentifier,
                der: Der
            ) = RSA(element)
        }


        sealed interface Parameters<T : RsaParams> : DerEncodable<T> {

            abstract val type: Padding
            abstract val digest: Digest

            class Pkcs1Padded(override val digest: Digest) :
                Parameters<RsaPkcs1PaddingParams> //TODO: wo we want to keep cursed encodings? I don't think so in this case, because re-encoding a cursed encoding will only ever be part of a larger structure that already has it
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
                private val providedParams: PssParams?, private val rsaSsaPssParams: RsaSsaPssParams?
            ) : Parameters<RsaSsaPssParams> {
                constructor(
                    digest: Digest = Digest.SHA1,
                    mgfAlgorithm: MaskGenerationFunction = MaskGenerationFunction.Pkcs1Mgf1(digest),
                    saltLength: UInt = digest.outputLength.bytes,
                    trailerField: Int = DEFAULT_TRAILER_FIELD
                ) : this(PssParams(digest, mgfAlgorithm, saltLength, trailerField), null)

                constructor(asn1Representation: RsaSsaPssParams) : this(null, asn1Representation)

                override val asn1Representation: RsaSsaPssParams by rsaSsaPssParams orLazy {
                    requireNotNull(providedParams)
                    RsaSsaPssParams(
                        hashAlgorithm = providedParams.digest.asn1Representation,
                        maskGenAlgorithm = providedParams.mgfAlgorithm.asn1Representation,
                        saltLength = providedParams.saltLength.also { require(it <= Int.MAX_VALUE.toUInt()) }.toInt(),
                        trailerField = providedParams.trailerField
                    )

                }

                override val type: Padding get() = Padding.PSS
                override val digest: Digest by providedParams?.digest orLazy {
                    Digest.decodeFromTlv(rsaSsaPssParams!!.effectiveHashAlgorithm)
                }

                val mgfAlgorithm: MaskGenerationFunction by providedParams?.mgfAlgorithm orLazy {
                    MaskGenerationFunction.decodeFromTlv(rsaSsaPssParams!!.effectiveMaskGenAlgorithm)
                }

                val saltLength: UInt by providedParams?.saltLength orLazy {
                    rsaSsaPssParams!!.effectiveSaltLength.let {
                        require(it >= 0)
                        it.toUInt()
                    }
                }
                val trailerField: Int by providedParams?.trailerField orLazy { rsaSsaPssParams!!.effectiveTrailerField }

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


                private data class PssParams(
                    val digest: Digest,
                    val mgfAlgorithm: MaskGenerationFunction,
                    val saltLength: UInt,
                    val trailerField: Int,
                )

                sealed class MaskGenerationFunction(override val oid: ObjectIdentifier) : Identifiable, DerEncodable<X509AlgorithmIdentifier> {
                    data class Pkcs1Mgf1(val digest: Digest = Digest.SHA1) : MaskGenerationFunction(oid) {
                        override val asn1Representation: X509AlgorithmIdentifier
                            get() = X509AlgorithmIdentifier(oid, listOf(digest.asn1Representation.element))
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
                    val DEFAULT_SAH256 = PssPadded(digest = Digest.SHA256)
                    val DEFAULT_SAH384 = PssPadded(digest = Digest.SHA384)
                    val DEFAULT_SAH512 = PssPadded(digest = Digest.SHA512)
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
                        PssPadded.DEFAULT_SAH512,
                        PssPadded.DEFAULT_SAH256,
                        PssPadded.DEFAULT_SAH384
                    )
                }
            }
        }

    }

    companion object : Enumeration<SignatureAlgorithm> {
        init { Indispensable.init() }
        val ECDSAwithSHA256 = ECDSA(Digest.SHA256, null)
        val ECDSAwithSHA384 = ECDSA(Digest.SHA384, null)
        val ECDSAwithSHA512 = ECDSA(Digest.SHA512, null)

        val RSAwithSHA256andPKCS1Padding = RSA(RSA.Parameters.Pkcs1Padded(Digest.SHA256))
        val RSAwithSHA384andPKCS1Padding = RSA(RSA.Parameters.Pkcs1Padded(Digest.SHA384))
        val RSAwithSHA512andPKCS1Padding = RSA(RSA.Parameters.Pkcs1Padded(Digest.SHA512))

        val RSAwithSHA256andPSSPadding = RSA(RSA.Parameters.PssPadded.DEFAULT_SAH256)
        val RSAwithSHA384andPSSPadding = RSA(RSA.Parameters.PssPadded.DEFAULT_SAH384)
        val RSAwithSHA512andPSSPadding = RSA(RSA.Parameters.PssPadded.DEFAULT_SAH512)

        override val entries: Iterable<SignatureAlgorithm> by lazy {
            ECDSA.entries + RSA.entries
        }

        operator fun invoke(identifier: X509AlgorithmIdentifier): SignatureAlgorithm =
            runRethrowing {
                when (identifier.oid) {
                    KnownOIDs.ecdsaWithSHA256,
                    KnownOIDs.ecdsaWithSHA384,
                    KnownOIDs.ecdsaWithSHA512 -> ECDSA(identifier)

                    KnownOIDs.sha1WithRSAEncryption,
                    KnownOIDs.sha256WithRSAEncryption,
                    KnownOIDs.sha384WithRSAEncryption,
                    KnownOIDs.sha512WithRSAEncryption -> RSA(identifier)

                    KnownOIDs.rsaPSS -> RSA(identifier)

                    else -> throw Asn1OidException("Unsupported OID: ${identifier.oid}", identifier.oid)
                }
            }

    }
}

interface SpecializedSignatureAlgorithm : SpecializedDataIntegrityAlgorithm {
    override val algorithm: SignatureAlgorithm
}
