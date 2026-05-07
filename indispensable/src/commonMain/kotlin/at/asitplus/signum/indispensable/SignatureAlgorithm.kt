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
import at.asitplus.awesn1.serialization.Der
import at.asitplus.awesn1.serialization.ExplicitlyTagged
import at.asitplus.signum.Enumeration
import at.asitplus.signum.internals.orLazy
import kotlinx.serialization.KSerializer

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

sealed interface SignatureAlgorithm : DataIntegrityAlgorithm {

    data class ECDSA(
        /** The digest to apply to the data, or `null` to directly process the raw data. */
        val digest: Digest?,
        /** Whether this algorithm specifies a particular curve to use, or `null` for any curve. */
        val requiredCurve: ECCurve?
    ) : SignatureAlgorithm {

        companion object : Enumeration<ECDSA> {
            override val entries: Set<ECDSA> by lazy {
                setOf(
                    ECDSAwithSHA256,
                    ECDSAwithSHA384,
                    ECDSAwithSHA512
                )
            }
        }
    }

    data class RSA(
        /** The digest to apply to the data. */
        val digest: Digest,
        /** The padding to apply to the data. */
        val padding: RSAPadding<*>
    ) : SignatureAlgorithm {

        companion object : Enumeration<RSA> {
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

    }
}

interface SpecializedSignatureAlgorithm : SpecializedDataIntegrityAlgorithm {
    override val algorithm: SignatureAlgorithm
}
