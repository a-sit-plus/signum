package at.asitplus.signum.indispensable

import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.RsaParams
import at.asitplus.awesn1.crypto.RsaPkcs1PaddingParams
import at.asitplus.awesn1.crypto.RsaSsaPssParams
import at.asitplus.awesn1.crypto.RsaSsaPssParams.Companion.DEFAULT_SALT_LENGTH
import at.asitplus.awesn1.crypto.RsaSsaPssParams.Companion.DEFAULT_TRAILER_FIELD
import at.asitplus.awesn1.crypto.RsaSsaPssParams.Companion.RSA_SSA_PSS_OID
import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.Der
import at.asitplus.awesn1.serialization.ExplicitlyTagged
import at.asitplus.signum.Enumeration
import at.asitplus.signum.internals.orLazy
import at.asitplus.signum.internals.orLazyNullable
import kotlinx.serialization.KSerializer

private infix fun RSAPadding<*>.sameSignaturePaddingAs(other: RSAPadding<*>): Boolean =
    when {
        this === other -> true
        this is RSAPadding.PSS && other is RSAPadding.PSS ->
            mgfAlgorithm == other.mgfAlgorithm &&
                saltLength == other.saltLength &&
                trailerField == other.trailerField

        else -> this == other
    }

private fun RSAPadding<*>.signaturePaddingHashCode(): Int =
    when (this) {
        is RSAPadding.PSS -> {
            var result = mgfAlgorithm.hashCode()
            result = 31 * result + saltLength.hashCode()
            result = 31 * result + trailerField
            result
        }

        else -> hashCode()
    }

sealed class RSAPadding<T : RsaParams> : DerEncodable<T> {
    object PKCS1 :
        RSAPadding<RsaPkcs1PaddingParams>() //TODO: wo we want to keep cursed encodings? I don't think so in this case, because re-encoding a cursed encoding will only ever be part of a larger structure that already has it
        , DerDecodable<RsaPkcs1PaddingParams, PKCS1> {
        override val asn1Representation: RsaPkcs1PaddingParams get() = RsaPkcs1PaddingParams
        override fun decodeFromTlv(
            serializer: KSerializer<RsaPkcs1PaddingParams>,
            src: Asn1Element,
            der: Der
        ): PKCS1 {
            der.decodeFromTlv(serializer, src)
            return this
        }

    }

    class PSS private constructor(
        private val providedParams: PssParams?, private val rsaSsaPssParams: RsaSsaPssParams?
    ) : RSAPadding<RsaSsaPssParams>(), Identifiable {
        constructor(
            hashAlgorithm: Digest = Digest.SHA1,
            mgfAlgorithm: MGF = MGF.PKCS1_MGF1,
            saltLength: UInt = DEFAULT_SALT_LENGTH.toUInt(),
            trailerField: Int = DEFAULT_TRAILER_FIELD
        ) : this(PssParams(hashAlgorithm, mgfAlgorithm, saltLength, trailerField), null)

        constructor(asn1Representation: RsaSsaPssParams) : this(null, asn1Representation)

        override val asn1Representation: RsaSsaPssParams by rsaSsaPssParams orLazy {
            requireNotNull(providedParams)
            RsaSsaPssParams(
                ExplicitlyTagged(X509AlgorithmIdentifier(providedParams.hashAlgorithm.oid, Asn1Null)),
                ExplicitlyTagged(
                    X509AlgorithmIdentifier(
                        providedParams.mgfAlgorithm.oid,
                        Asn1.Sequence { +providedParams.hashAlgorithm.oid; +Asn1Null })
                ),
                ExplicitlyTagged(Asn1Integer(providedParams.saltLength)),
                ExplicitlyTagged(Asn1Integer(providedParams.trailerField))
            )

        }

        val hashAlgorithm: Digest by providedParams?.hashAlgorithm orLazy {
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

        override val oid: ObjectIdentifier
            get() = RSA_SSA_PSS_OID

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is PSS) return false
            return hashAlgorithm == other.hashAlgorithm &&
                mgfAlgorithm == other.mgfAlgorithm &&
                saltLength == other.saltLength &&
                trailerField == other.trailerField
        }

        override fun hashCode(): Int {
            var result = hashAlgorithm.hashCode()
            result = 31 * result + mgfAlgorithm.hashCode()
            result = 31 * result + saltLength.hashCode()
            result = 31 * result + trailerField
            return result
        }


        private data class PssParams(
            val hashAlgorithm: Digest,
            val mgfAlgorithm: MGF,
            val saltLength: UInt,
            val trailerField: Int,
        )

        enum class MGF(override val oid: ObjectIdentifier) : Identifiable {
            PKCS1_MGF1(ObjectIdentifier("1.2.840.113549.1.1.8"))
        }

        companion object : DerDecodable<RsaSsaPssParams, PSS> {
            val DEFAULT = PSS()
            override fun decodeFromTlv(
                serializer: KSerializer<RsaSsaPssParams>,
                src: Asn1Element,
                der: Der
            ) = PSS(der.decodeFromTlv(serializer, src))
        }
    }

    companion object : DerDecodable<RsaParams, RSAPadding<RsaParams>> {
        override fun decodeFromTlv(
            serializer: KSerializer<RsaParams>,
            src: Asn1Element,
            der: Der
        ): RSAPadding<RsaParams> =
            when (val decoded = der.decodeFromTlv(serializer, src)) {
                is RsaPkcs1PaddingParams -> PKCS1
                is RsaSsaPssParams -> PSS(decoded)
            } as RSAPadding<RsaParams>
    }
}

//for now, we just replicate the pattern, but since everything is sealed, we don't actually parse
sealed interface SignatureAlgorithm : DataIntegrityAlgorithm, DerEncodable<X509AlgorithmIdentifier> {

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
            return digest == other.digest && requiredCurve == other.requiredCurve
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
                serializer: KSerializer<X509AlgorithmIdentifier>,
                src: Asn1Element,
                der: Der
            ) = ECDSA(der.decodeFromTlv(serializer, src))

        }
    }

    class RSA(
        private val providedParams: Pair<Digest, RSAPadding<*>>?,
        private val providedAsn1: X509AlgorithmIdentifier?,
    ) : SignatureAlgorithm {

        constructor(
            /** The digest to apply to the data. */
            digest: Digest,
            /** The padding to apply to the data. */
            padding: RSAPadding<*>
        ) : this(digest to padding, null)

        constructor(asn1Representation: X509AlgorithmIdentifier) : this(null, asn1Representation)

        /** The digest to apply to the data. */
        val digest: Digest by providedParams?.first orLazy {
            when (providedAsn1!!.oid) {
                KnownOIDs.sha1WithRSAEncryption -> Digest.SHA1
                KnownOIDs.sha256WithRSAEncryption -> Digest.SHA256
                KnownOIDs.sha384WithRSAEncryption -> Digest.SHA384
                KnownOIDs.sha512WithRSAEncryption -> Digest.SHA512
                KnownOIDs.rsaPSS -> RSAPadding.PSS(providedAsn1.rsaSsaPssParams!!).hashAlgorithm
                else -> throw IllegalArgumentException("Unsupported algorithm ${providedAsn1.oid}")
            }
        }

        /** The padding to apply to the data. */
        val padding: RSAPadding<*> by providedParams?.second orLazy {
            when (providedAsn1!!.oid) {
                KnownOIDs.sha1WithRSAEncryption,
                KnownOIDs.sha256WithRSAEncryption,
                KnownOIDs.sha384WithRSAEncryption,
                KnownOIDs.sha512WithRSAEncryption -> RSAPadding.PKCS1

                KnownOIDs.rsaPSS -> RSAPadding.PSS(providedAsn1.rsaSsaPssParams!!)
                else -> throw IllegalArgumentException("Unsupported algorithm ${providedAsn1.oid}")
            }
        }

        override val asn1Representation: X509AlgorithmIdentifier by providedAsn1 orLazy {
            when (val currentPadding = padding) {
                RSAPadding.PKCS1 -> X509AlgorithmIdentifier(
                    when (digest) {
                        Digest.SHA1 -> KnownOIDs.sha1WithRSAEncryption
                        Digest.SHA256 -> KnownOIDs.sha256WithRSAEncryption
                        Digest.SHA384 -> KnownOIDs.sha384WithRSAEncryption
                        Digest.SHA512 -> KnownOIDs.sha512WithRSAEncryption
                    },
                    Asn1Null
                )

                is RSAPadding.PSS -> X509AlgorithmIdentifier(
                    KnownOIDs.rsaPSS,
                    DER.encodeToTlv(RsaSsaPssParams.serializer(), currentPadding.asn1Representation)
                )
            }
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is RSA) return false
            return digest == other.digest && padding.sameSignaturePaddingAs(other.padding)
        }

        override fun hashCode(): Int {
            var result = digest.hashCode()
            result = 31 * result + padding.signaturePaddingHashCode()
            return result
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
    }

    companion object : Enumeration<SignatureAlgorithm> {
        val ECDSAwithSHA256 = ECDSA(Digest.SHA256, null)
        val ECDSAwithSHA384 = ECDSA(Digest.SHA384, null)
        val ECDSAwithSHA512 = ECDSA(Digest.SHA512, null)

        val RSAwithSHA256andPKCS1Padding = RSA(Digest.SHA256, RSAPadding.PKCS1)
        val RSAwithSHA384andPKCS1Padding = RSA(Digest.SHA384, RSAPadding.PKCS1)
        val RSAwithSHA512andPKCS1Padding = RSA(Digest.SHA512, RSAPadding.PKCS1)

        val RSAwithSHA256andPSSPadding = RSA(Digest.SHA256, RSAPadding.PSS.DEFAULT)
        val RSAwithSHA384andPSSPadding = RSA(Digest.SHA384, RSAPadding.PSS.DEFAULT)
        val RSAwithSHA512andPSSPadding = RSA(Digest.SHA512, RSAPadding.PSS.DEFAULT)

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
