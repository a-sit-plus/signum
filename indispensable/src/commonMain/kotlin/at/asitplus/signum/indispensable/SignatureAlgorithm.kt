package at.asitplus.signum.indispensable

import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.RsaParams
import at.asitplus.awesn1.crypto.RsaPkcs1PaddingParams
import at.asitplus.awesn1.crypto.RsaSsaPssParams
import at.asitplus.awesn1.crypto.RsaSsaPssParams.Companion.DEFAULT_SALT_LENGTH
import at.asitplus.awesn1.crypto.RsaSsaPssParams.Companion.DEFAULT_TRAILER_FIELD
import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.Der
import at.asitplus.awesn1.serialization.ExplicitlyTagged
import at.asitplus.signum.Enumeration
import at.asitplus.signum.indispensable.SignatureAlgorithm.RSA
import at.asitplus.signum.internals.orLazy
import at.asitplus.signum.internals.orLazyNullable
import kotlinx.serialization.KSerializer

private infix fun RSA.Parameters<*>.sameSignatureParametersAs(other: RSA.Parameters<*>): Boolean =
    when {
        this === other -> true
        this is RSA.Parameters.PssPadded && other is RSA.Parameters.PssPadded ->
            digest == other.digest &&
                    mgfAlgorithm == other.mgfAlgorithm &&
                    saltLength == other.saltLength &&
                    trailerField == other.trailerField

        else -> this == other
    }

private fun RSA.Parameters<*>.signatureParametersHashCode(): Int =
    when (this) {
        is RSA.Parameters.PssPadded -> {
            var result = digest.hashCode()
            result = 31 * result + mgfAlgorithm.hashCode()
            result = 31 * result + saltLength.hashCode()
            result = 31 * result + trailerField
            result
        }

        else -> hashCode()
    }

//for now, we just replicate the pattern, but since everything is sealed, we don't actually parse
sealed interface SignatureAlgorithm : DataIntegrityAlgorithm, DerEncodable<X509AlgorithmIdentifier> {

    //TODO: extensible
    enum class Kind {
        EC, RSA
    }


    val kind: Kind

    class ECDSA(
        private val providedParams: Pair<Digest?, ECCurve?>?,
        private val providedAsn1: X509AlgorithmIdentifier?,
    ) : SignatureAlgorithm {

        constructor(
            /** The digest to apply to the data, or `null` to directly process the raw data. */
            digest: Digest?,
            /** Whether this algorithm specifies a particular curve to use, or `null` for any curve. */
            requiredCurve: ECCurve?
        ) : this(digest to requiredCurve, null)


        constructor(asn1Representation: X509AlgorithmIdentifier) : this(null, asn1Representation)

        override val kind: Kind get() = Kind.EC

        /** The digest to apply to the data, or `null` to directly process the raw data. */
        val digest: Digest? by providedParams.orLazyNullable(
            provided = { first },
            fallback = {
                when (providedAsn1!!.oid) {
                    KnownOIDs.ecdsaWithSHA256 -> Digest.SHA256
                    KnownOIDs.ecdsaWithSHA384 -> Digest.SHA384
                    KnownOIDs.ecdsaWithSHA512 -> Digest.SHA512
                    else -> throw IllegalArgumentException("Unuspported algorithm ${providedAsn1.oid}")
                }
            }
        )

        /** Whether this algorithm specifies a particular curve to use, or `null` for any curve. */
        val requiredCurve: ECCurve? by providedParams.orLazyNullable(
            provided = { second },
            fallback = { null },
        )

        override val asn1Representation: X509AlgorithmIdentifier by providedAsn1 orLazy {
            X509AlgorithmIdentifier(
                when (digest) {
                    Digest.SHA256 -> KnownOIDs.ecdsaWithSHA256
                    Digest.SHA384 -> KnownOIDs.ecdsaWithSHA384
                    Digest.SHA512 -> KnownOIDs.ecdsaWithSHA512
                    else -> throw IllegalArgumentException("Unsupported digest: $digest")
                }
            )
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is ECDSA) return false
            val thisIsAsn1Backed = providedAsn1 != null
            val otherIsAsn1Backed = other.providedAsn1 != null

            if (thisIsAsn1Backed && otherIsAsn1Backed) {
                return asn1Representation == other.asn1Representation
            }

            if (!thisIsAsn1Backed && !otherIsAsn1Backed) {
                return hasSamePropertiesAs(other)
            }

            if (asn1Representation == other.asn1Representation) return true

            return runCatching {
                hasSamePropertiesAs(other)
            }.getOrDefault(false)
        }

        private fun hasSamePropertiesAs(other: ECDSA): Boolean =
            digest == other.digest && requiredCurve == other.requiredCurve

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
                serializer: KSerializer<X509AlgorithmIdentifier>,
                src: Asn1Element,
                der: Der
            ) = ECDSA(der.decodeFromTlv(serializer, src))

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

        val padding get() = parameters.type

        /**
         * Convenience Ctor to use defaults aside digest
         */
        constructor(padding: Padding, digest: Digest) : this(Parameters(padding, digest))

        override val kind: Kind get() = Kind.RSA

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

        override val asn1Representation: X509AlgorithmIdentifier by providedAsn1 orLazy {
            when (val currentParameters = parameters) {
                is Parameters.Pkcs1Padded -> X509AlgorithmIdentifier(
                    when (currentParameters.digest) {
                        Digest.SHA1 -> KnownOIDs.sha1WithRSAEncryption
                        Digest.SHA256 -> KnownOIDs.sha256WithRSAEncryption
                        Digest.SHA384 -> KnownOIDs.sha384WithRSAEncryption
                        Digest.SHA512 -> KnownOIDs.sha512WithRSAEncryption
                    },
                    Asn1Null
                )

                is Parameters.PssPadded -> X509AlgorithmIdentifier(
                    KnownOIDs.rsaPSS,
                    DER.encodeToTlv(RsaSsaPssParams.serializer(), currentParameters.asn1Representation)
                )
            }
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is RSA) return false
            val thisIsAsn1Backed = providedAsn1 != null
            val otherIsAsn1Backed = other.providedAsn1 != null

            if (thisIsAsn1Backed && otherIsAsn1Backed) {
                return asn1Representation == other.asn1Representation
            }

            if (!thisIsAsn1Backed && !otherIsAsn1Backed) {
                return hasSamePropertiesAs(other)
            }

            if (asn1Representation == other.asn1Representation) return true

            return runCatching {
                hasSamePropertiesAs(other)
            }.getOrDefault(false)
        }

        private fun hasSamePropertiesAs(other: RSA): Boolean =
            parameters sameSignatureParametersAs other.parameters

        override fun hashCode(): Int {
            return parameters.signatureParametersHashCode()
        }


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
                serializer: KSerializer<X509AlgorithmIdentifier>,
                src: Asn1Element,
                der: Der
            ) = RSA(der.decodeFromTlv(serializer, src))
        }


        sealed class Parameters<T : RsaParams> : DerEncodable<T> {

            abstract val type: Padding
            abstract val digest: Digest

            class Pkcs1Padded(override val digest: Digest) :
                Parameters<RsaPkcs1PaddingParams>() //TODO: wo we want to keep cursed encodings? I don't think so in this case, because re-encoding a cursed encoding will only ever be part of a larger structure that already has it
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
            ) : Parameters<RsaSsaPssParams>() {
                constructor(
                    digest: Digest = Digest.SHA1,
                    mgfAlgorithm: MGF = MGF.PKCS1_MGF1,
                    saltLength: UInt = DEFAULT_SALT_LENGTH.toUInt(),
                    trailerField: Int = DEFAULT_TRAILER_FIELD
                ) : this(PssParams(digest, mgfAlgorithm, saltLength, trailerField), null)

                constructor(asn1Representation: RsaSsaPssParams) : this(null, asn1Representation)

                override val asn1Representation: RsaSsaPssParams by rsaSsaPssParams orLazy {
                    requireNotNull(providedParams)
                    RsaSsaPssParams(
                        ExplicitlyTagged(X509AlgorithmIdentifier(providedParams.digest.oid, Asn1Null)),
                        ExplicitlyTagged(
                            X509AlgorithmIdentifier(
                                providedParams.mgfAlgorithm.oid,
                                Asn1.Sequence { +providedParams.digest.oid; +Asn1Null })
                        ),
                        ExplicitlyTagged(Asn1Integer(providedParams.saltLength)),
                        ExplicitlyTagged(Asn1Integer(providedParams.trailerField))
                    )

                }

                override val type: Padding get() = Padding.PSS
                override val digest: Digest by providedParams?.digest orLazy {
                    Digest.entries.first { it.oid == rsaSsaPssParams!!.effectiveHashAlgorithm.oid }
                }

                val mgfAlgorithm: MGF by providedParams?.mgfAlgorithm orLazy { MGF.entries.first { it.oid == rsaSsaPssParams!!.effectiveMaskGenAlgorithm.oid } }

                val saltLength: UInt by providedParams?.saltLength orLazy {
                    rsaSsaPssParams!!.effectiveSaltLength.let {
                        require(it > 0)
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
                    val mgfAlgorithm: MGF,
                    val saltLength: UInt,
                    val trailerField: Int,
                )

                enum class MGF(override val oid: ObjectIdentifier) : Identifiable {
                    PKCS1_MGF1(ObjectIdentifier("1.2.840.113549.1.1.8"))
                }

                companion object : DerDecodable<RsaSsaPssParams, PssPadded> {
                    val DEFAULT_SAH256 = PssPadded(digest = Digest.SHA256)
                    val DEFAULT_SAH384 = PssPadded(digest = Digest.SHA384)
                    val DEFAULT_SAH512 = PssPadded(digest = Digest.SHA512)
                    override fun decodeFromTlv(
                        serializer: KSerializer<RsaSsaPssParams>,
                        src: Asn1Element,
                        der: Der
                    ) = PssPadded(der.decodeFromTlv(serializer, src))
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

        //TODO: extensible
        fun kindByOID(oid: ObjectIdentifier): Kind = when (oid) {
            KnownOIDs.ecdsaWithSHA256, KnownOIDs.ecdsaWithSHA384, KnownOIDs.ecdsaWithSHA512 -> Kind.EC
            KnownOIDs.sha1WithRSAEncryption, KnownOIDs.sha256WithRSAEncryption, KnownOIDs.sha384WithRSAEncryption, KnownOIDs.sha512WithRSAEncryption, KnownOIDs.rsaPSS -> Kind.RSA
            else -> throw IllegalArgumentException("Unknown OID $oid")


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
