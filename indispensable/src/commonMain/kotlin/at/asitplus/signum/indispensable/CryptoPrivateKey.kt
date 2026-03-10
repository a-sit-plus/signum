package at.asitplus.signum.indispensable

import at.asitplus.KmmResult
import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.EcPrivateKey
import at.asitplus.awesn1.crypto.EncryptedPrivateKeyInfo
import at.asitplus.awesn1.crypto.PrivateKeyInfo
import at.asitplus.awesn1.crypto.RsaOtherPrimeInfo
import at.asitplus.awesn1.crypto.RsaPrivateKey
import at.asitplus.awesn1.encoding.*
import at.asitplus.catching
import at.asitplus.signum.ecmath.times
import at.asitplus.signum.indispensable.PublicKey.EC.Companion.asPublicKey
import at.asitplus.signum.indispensable.asn1.Int
import at.asitplus.signum.indispensable.asn1.LabelPemDecodable
import at.asitplus.signum.indispensable.asn1.decodeToBigInteger
import at.asitplus.signum.indispensable.asn1.toAsn1Integer
import at.asitplus.signum.indispensable.asn1.toBigInteger
import at.asitplus.signum.indispensable.misc.ANSIECPrefix
import at.asitplus.signum.internals.checkedAs
import at.asitplus.signum.internals.checkedAsFn
import at.asitplus.signum.internals.ensureSize
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign

private object EB_STRINGS {
    const val GENERIC_PRIVATE_KEY_PKCS8 = "PRIVATE KEY"
    const val RSA_PRIVATE_KEY_PKCS1 = "RSA PRIVATE KEY"
    const val EC_PRIVATE_KEY_SEC1 = "EC PRIVATE KEY"
    const val ENCRYPTED_PRIVATE_KEY = "ENCRYPTED PRIVATE KEY"
}

/**
 * PKCS#8 Representation of a private key structure as per [RFC 5208](https://datatracker.ietf.org/doc/html/rfc5208)
 * Equality checks are performed wrt. cryptographic properties.
 */
sealed interface PrivateKey : Asn1PemEncodable<Asn1Sequence>, Identifiable, Awesn1Backed<PrivateKeyInfo> {

    sealed interface WithPublicKey<T : PublicKey> : PrivateKey {
        /** [PublicKey] matching this private key. */
        val publicKey: T
    }

    /** optional attributes relevant when PKCS#8-encoding a private key */
    val attributes: List<Asn1Element>?

    /** Encodes this private key into a PKCS#8-encoded private key. This is the default. */
    val asPKCS8: Asn1PemEncodable<Asn1Sequence> get() = this

    sealed class Impl(
        override val raw: PrivateKeyInfo,
    ) : PrivateKey {
        /** optional attributes relevant when PKCS#8-encoding a private key */
        override val attributes: List<Asn1Element>? get() = raw.attributes

        override val pemLabel get() = EB_STRINGS.GENERIC_PRIVATE_KEY_PKCS8

        /**
         * PKCS#8 encoding of a private key:
         * ```asn1
         * PrivateKeyInfo ::= SEQUENCE {
         *   version                   Version,
         *   privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
         *   privateKey                PrivateKey,
         *   attributes           [0]  IMPLICIT Attributes OPTIONAL
         * }
         *
         * Version ::= INTEGER
         *
         * PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
         *
         * PrivateKey ::= OCTET STRING
         *
         * Attributes ::= SET OF Attribute
         * ```
         *
         * @throws Asn1StructuralException if `this` is [EC.WithoutPublicKey], such as decoded from minimal SEC1
         */

        @Throws(Asn1Exception::class)
        override fun encodeToTlv() = raw.encodeToTlv()
    }

    /**
     * PKCS#1 RSA Private key representation as per [RFC 8017](https://datatracker.ietf.org/doc/html/rfc8017/#appendix-A.1.2) augmented with optional [attributes].
     * Attributes are never PKCS#1 encoded, but are relevant when PKCS#8-encoding a private key.
     */
    class RSA
    /** @throws IllegalArgumentException in case invalid parameters are provided*/
    @Throws(IllegalArgumentException::class)
    constructor(
        override val raw: PrivateKeyInfo,
    ) : PrivateKey.Impl(raw), PrivateKey.WithPublicKey<PublicKey.RSA>, PrivateKey {
        private val rawPrivateKey by lazy {
            require(raw.algorithmOid == oid) { "Unknown Algorithm: ${raw.algorithmOid}" }
            require(raw.algorithmParameters.size == 1) { "RSA private key algorithm identifier must contain NULL params" }
            raw.algorithmParameters.single().asPrimitive().readNull()
            raw.decodeRsaPrivateKey()
        }

        constructor(
            publicKey: PublicKey.RSA,
            privateKey: BigInteger,
            prime1: BigInteger,
            prime2: BigInteger,
            prime1exponent: BigInteger,
            prime2exponent: BigInteger,
            crtCoefficient: BigInteger,
            otherPrimeInfos: List<PrimeInfo>?,
            attributes: List<Asn1Element>? = null,
        ) : this(
            PrivateKeyInfo.rsa(
                RsaPrivateKey(
                    version = if (otherPrimeInfos != null) 1 else 0,
                    modulus = publicKey.n,
                    publicExponent = publicKey.e,
                    privateExponent = privateKey.toAsn1Integer(),
                    prime1 = prime1.toAsn1Integer(),
                    prime2 = prime2.toAsn1Integer(),
                    exponent1 = prime1exponent.toAsn1Integer(),
                    exponent2 = prime2exponent.toAsn1Integer(),
                    coefficient = crtCoefficient.toAsn1Integer(),
                    otherPrimeInfos = otherPrimeInfos?.map {
                        RsaOtherPrimeInfo(
                            prime = it.prime.toAsn1Integer(),
                            exponent = it.exponent.toAsn1Integer(),
                            coefficient = it.coefficient.toAsn1Integer(),
                        )
                    }
                ),
                attributes
            )
        )

        override val publicKey: PublicKey.RSA by lazy { PublicKey.RSA(rawPrivateKey.modulus, rawPrivateKey.publicExponent) }
        /** d: the private key such that d*e = 1 mod phi(n) */
        val privateKey get() = rawPrivateKey.privateExponent.toBigInteger()
        /** p: the first prime factor */
        val prime1 get() = rawPrivateKey.prime1.toBigInteger()
        /** q: the second prime factor */
        val prime2 get() = rawPrivateKey.prime2.toBigInteger()
        /** dP: the first factor's CRT exponent */
        val prime1exponent get() = rawPrivateKey.exponent1.toBigInteger()
        /** dQ: the second factor's CRT exponent */
        val prime2exponent get() = rawPrivateKey.exponent2.toBigInteger()
        /** qInv: the factors' CRT coefficient (q^(-1) mod p) */
        val crtCoefficient get() = rawPrivateKey.coefficient.toBigInteger()
        /** information about additional prime factors: triples (r_i, d_i, t_i) of prime factor, exponent, coefficient */
        val otherPrimeInfos: List<PrimeInfo>? get() = rawPrivateKey.otherPrimeInfos?.map {
            PrimeInfo(
                prime = it.prime.toBigInteger(),
                exponent = it.exponent.toBigInteger(),
                coefficient = it.coefficient.toBigInteger(),
            )
        }

        override val oid = RSA.oid

        override fun equals(other: Any?): Boolean {
            if (other !is RSA) return false
            return publicKey.equalsCryptographically(other.publicKey)
        }

        override fun hashCode() = publicKey.hashCode()

        init {
            val n = publicKey.n.toBigInteger()
            val e = publicKey.e.toBigInteger()
            // the primes and exponents are intentionally swapped; see RFC 8017 sec 3.2 note 1
            val primeInfo1 = PrimeInfo(prime = prime2, exponent = prime2exponent, coefficient = BigInteger.ONE)
            val primeInfo2 = PrimeInfo(prime = prime1, exponent = prime1exponent, coefficient = crtCoefficient)

            var product = BigInteger.ONE
            (sequenceOf(primeInfo1, primeInfo2) + (otherPrimeInfos?.asSequence() ?: sequenceOf()))
                .forEachIndexed { i, info ->
                    val pminusone = info.prime - BigInteger.ONE
                    require(product.times(info.coefficient).mod(info.prime) == BigInteger.ONE)
                    { "t_$i != (r_0 * ... * r_${i-1})^(-1) mod r_$i" }
                    product *= info.prime
                    require(info.exponent == privateKey.mod(pminusone)) { "d_$i != d mod (p_$i - 1)" }
                    require(e.multiply(info.exponent).mod(pminusone) == BigInteger.ONE)
                }
            require(product == n) { "p1 * p2 * … * pk != n" }
        }

        /** Encodes this private key into a PKCS#1-encoded private key */
        val asPKCS1 = object : Asn1PemEncodable<Asn1Sequence> {
            override val pemLabel get() = EB_STRINGS.RSA_PRIVATE_KEY_PKCS1

            /**
             * ```asn1
             * RSAPrivateKey ::= SEQUENCE {
             *   version           Version,
             *   modulus           INTEGER,  -- n
             *   publicExponent    INTEGER,  -- e
             *   privateExponent   INTEGER,  -- d
             *   prime1            INTEGER,  -- p
             *   prime2            INTEGER,  -- q
             *   exponent1         INTEGER,  -- d mod (p-1)
             *   exponent2         INTEGER,  -- d mod (q-1)
             *   coefficient       INTEGER,  -- (inverse of q) mod p
             *   otherPrimeInfos   OtherPrimeInfos OPTIONAL
             * }
             * ```
             */
            override fun encodeToTlv() = rawPrivateKey.encodeToTlv()
        }

        /**
         * OtherPrimeInfos as per PKCS#1
         *
         * ```asn1
         * OtherPrimeInfo ::= SEQUENCE {
         *   prime             INTEGER,  -- ri
         *   exponent          INTEGER,  -- di
         *   coefficient       INTEGER   -- ti
         * }
         * ```
         */
        data class PrimeInfo(
            val prime: BigInteger,
            val exponent: BigInteger,
            val coefficient: BigInteger,
        ) : Asn1Encodable<Asn1Sequence> {

            internal val raw: RsaOtherPrimeInfo
                get() = RsaOtherPrimeInfo(
                    prime = prime.toAsn1Integer(),
                    exponent = exponent.toAsn1Integer(),
                    coefficient = coefficient.toAsn1Integer(),
                )

            internal constructor(raw: RsaOtherPrimeInfo) : this(
                prime = raw.prime.toBigInteger(),
                exponent = raw.exponent.toBigInteger(),
                coefficient = raw.coefficient.toBigInteger(),
            )

            @Throws(Asn1Exception::class)
            override fun encodeToTlv() = raw.encodeToTlv()

            companion object : Asn1Decodable<Asn1Sequence, PrimeInfo> {

                @Throws(Asn1Exception::class)
                override fun doDecode(src: Asn1Sequence): PrimeInfo =
                    PrimeInfo(RsaOtherPrimeInfo.decodeFromTlv(src))

            }
        }

        companion object : LabelPemDecodable<Asn1Sequence, RSA>(
            EB_STRINGS.GENERIC_PRIVATE_KEY_PKCS8 to checkedAsFn { source ->
                FromPKCS8.fromRaw(PrivateKeyInfo.decodeFromDer(source))
            },
            EB_STRINGS.RSA_PRIVATE_KEY_PKCS1 to checkedAsFn { source ->
                FromPKCS1.fromRaw(RsaPrivateKey.decodeFromDer(source))
            }
        ) {
            override fun doDecode(src: Asn1Sequence): RSA =
                checkedAs(PrivateKey.doDecode(src))

            val oid: ObjectIdentifier = KnownOIDs.rsaEncryption
        }

        object FromPKCS1 : Asn1Decodable<Asn1Sequence, RSA> {
            @Throws(Asn1Exception::class)
            override fun doDecode(src: Asn1Sequence): RSA = doDecode(src, null)

            /** PKCS1 decoding of an ASN.1 private key, optionally supporting attributes for later PKCS#8 encoding */
            @Throws(Asn1Exception::class)
            fun doDecode(src: Asn1Sequence, attributes: List<Asn1Element>? = null): RSA {
                return fromRaw(RsaPrivateKey.decodeFromTlv(src), attributes)
            }

            @Throws(Asn1Exception::class)
            fun fromRaw(raw: RsaPrivateKey, attributes: List<Asn1Element>? = null): RSA {
                val version = raw.version
                require(version == 0 || version == 1) { "RSA Private key VERSION must be 0 or 1" }
                if (raw.otherPrimeInfos != null) {
                    require(version == 1) { "OtherPrimeInfos is present. RSA private key version must be 1" }
                } else {
                    require(version == 0) { "OtherPrimeInfos is not present. RSA private key version must be 0" }
                }
                return RSA(PrivateKeyInfo.rsa(raw, attributes))
            }
        }

        override fun toString() = "RSA private key for public key $publicKey"
    }

    /**
     * SEC1 Elliptic Curve Private Key Structure as per [RFC 5915](https://datatracker.ietf.org/doc/html/rfc5915) augmented with optional [attributes].
     * Attributes are never SEC1 encoded, but are relevant when PKCS#8-encoding a private key.
     */
    sealed class EC protected constructor(
        override val raw: PrivateKeyInfo,
    ) : PrivateKey.Impl(raw), PrivateKey {
        protected val rawPrivateKey by lazy {
            require(raw.algorithmOid == oid) { "Unknown Algorithm: ${raw.algorithmOid}" }
            raw.decodeEcPrivateKey()
        }

        protected val rawCurveOid by lazy {
            raw.algorithmParameters.firstOrNull()?.let { ObjectIdentifier.decodeFromTlv(it.asPrimitive()) }
                ?: rawPrivateKey.parameters
        }

        val privateKey: BigInteger get() = BigInteger.fromByteArray(rawPrivateKey.privateKey, Sign.POSITIVE)

        override val oid = EC.oid

        abstract val privateKeyBytes: ByteArray

        override fun equals(other: Any?): Boolean {
            if (other !is EC) return false
            return (privateKey == other.privateKey)
        }

        override fun hashCode() = privateKey.hashCode()

        /** Encodes this private key into a SEC1-encoded private key */
        val asSEC1 = object : Asn1PemEncodable<Asn1Sequence> {
            override val pemLabel get() = EB_STRINGS.EC_PRIVATE_KEY_SEC1

            /**
             * ```asn1
             * ECPrivateKey ::= SEQUENCE {
             *   version INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
             *   privateKey OCTET STRING,
             *   parameters [0] ECDomainParameters {{ SECGCurveNames }} OPTIONAL,
             *   publicKey [1] BIT STRING OPTIONAL
             * }
             * ```
             */
            override fun encodeToTlv() = rawPrivateKey.encodeToTlv()
        }

        class WithPublicKey
        /** @throws IllegalArgumentException in case invalid parameters are provided*/
        @Throws(IllegalArgumentException::class)
        constructor(
            raw: PrivateKeyInfo,
        ) : EC(raw), PrivateKey.WithPublicKey<PublicKey.EC>, PrivateKey,
            KeyAgreementPrivateValue.ECDH {
            val curve: ECCurve by lazy {
                rawCurveOid?.let(ECCurve::withOid)
                    ?: throw Asn1StructuralException("Cannot determine curve from EC private key")
            }
            override val publicKey: PublicKey.EC by lazy {
                rawPrivateKey.publicKey?.let { PublicKey.EC.fromAnsiX963Bytes(curve, it.rawBytes) }
                    ?: curve.generator.times(privateKey).asPublicKey(preferCompressed = true)
            }
            val encodeCurve get() = rawPrivateKey.parameters != null
            val encodePublicKey get() = rawPrivateKey.publicKey != null

            constructor(
                privateKey: BigInteger,
            publicKey: PublicKey.EC,
                encodeCurve: Boolean,
                encodePublicKey: Boolean,
                attributes: List<Asn1Element>? = null,
            ) : this(
                PrivateKeyInfo.ec(
                    EcPrivateKey(
                        version = 1,
                        privateKey = privateKey.toByteArray().ensureSize(publicKey.curve.scalarLength.bytes),
                        parameters = if (encodeCurve) publicKey.curve.oid else null,
                        publicKey = if (encodePublicKey) Asn1BitString(publicKey.iosEncoded) else null,
                    ),
                    publicKey.curve.oid,
                    attributes,
                )
            )

            constructor(
                privateKey: BigInteger, curve: ECCurve,
                encodeCurve: Boolean, encodePublicKey: Boolean, attributes: List<Asn1Element>? = null,
            ) :
                    this(
                        privateKey, curve.generator.times(privateKey).asPublicKey(preferCompressed = true),
                        encodeCurve, encodePublicKey, attributes
                    )

            init {
                require(publicKey.publicPoint == privateKey.times(publicKey.curve.generator)) { "Public key must match the private key!" }
            }

            override fun toString(): String {
                return "EC private key for public key $publicKey"
            }

            override val privateKeyBytes: ByteArray
                get() = rawPrivateKey.privateKey

            override val publicValue get() = this.publicKey
        }

        class WithoutPublicKey constructor(
            raw: PrivateKeyInfo,
        ) : EC(raw) {
            val publicKeyBytes: Asn1BitString? get() = rawPrivateKey.publicKey
            private val curveOrderLengthInBytes: Int get() = rawPrivateKey.privateKey.size

            constructor(
                privateKey: BigInteger,
                publicKeyBytes: Asn1BitString?,
                attributes: List<Asn1Element>? = null,
                curveOrderLengthInBytes: Int,
            ) : this(
                PrivateKeyInfo.ec(
                    EcPrivateKey(
                        version = 1,
                        privateKey = privateKey.toByteArray().ensureSize(curveOrderLengthInBytes.toUInt()),
                        parameters = null,
                        publicKey = publicKeyBytes,
                    ),
                    null,
                    attributes,
                )
            )

            /** Creates a new [PrivateKey.EC.WithPublicKey] based on the passed curve. */
            fun withCurve(
                curve: ECCurve,
                encodeCurve: Boolean = true,
                encodePublicKey: Boolean = (this.publicKeyBytes != null)
            )
                    : WithPublicKey {
                require(curve.scalarLength.bytes.toInt() == curveOrderLengthInBytes)
                { "Encoded private key was padded to $curveOrderLengthInBytes bytes, but curve $curve needs padding to ${curve.scalarLength.bytes.toInt()} bytes" }
                val encodedPublicKey = publicKeyBytes
                return if (encodedPublicKey != null) {
                    PrivateKey.EC.WithPublicKey(
                        privateKey,
                        PublicKey.EC.fromAnsiX963Bytes(curve, encodedPublicKey.rawBytes),
                        encodeCurve,
                        encodePublicKey,
                        attributes,
                    )
                } else {
                    PrivateKey.EC.WithPublicKey(
                        privateKey,
                        curve,
                        encodeCurve,
                        encodePublicKey,
                        attributes,
                    )
                }
            }

            override fun equals(other: Any?): Boolean {
                if (this === other) return true
                if (other !is WithoutPublicKey) return false
                if (!super.equals(other)) return false

                if (curveOrderLengthInBytes != other.curveOrderLengthInBytes) return false

                return true
            }

            override fun hashCode(): Int {
                var result = super.hashCode()
                result = 31 * result + curveOrderLengthInBytes
                return result
            }

            override val privateKeyBytes: ByteArray
                get() = privateKey.toByteArray().ensureSize(curveOrderLengthInBytes)
        }


        companion object : LabelPemDecodable<Asn1Sequence, EC>(
            EB_STRINGS.GENERIC_PRIVATE_KEY_PKCS8 to checkedAsFn { source ->
                FromPKCS8.fromRaw(PrivateKeyInfo.decodeFromDer(source))
            },
            EB_STRINGS.EC_PRIVATE_KEY_SEC1 to checkedAsFn { source ->
                FromSEC1.fromRaw(EcPrivateKey.decodeFromDer(source))
            }
        ) {
            val oid: ObjectIdentifier = KnownOIDs.ecPublicKey

            @Throws(Asn1Exception::class)
            override fun doDecode(src: Asn1Sequence): EC =
                checkedAs(PrivateKey.doDecode(src))

            internal fun iosDecodeInternal(keyBytes: ByteArray): PrivateKey.EC.WithPublicKey {
                val crv = ECCurve.fromIosEncodedPrivateKeyLength(keyBytes.size)
                    ?: throw IllegalArgumentException("Unknown curve in iOS raw key")
                return EC.WithPublicKey(
                    BigInteger.fromByteArray(
                        keyBytes.sliceArray(crv.iosEncodedPublicKeyLength..<keyBytes.size),
                        Sign.POSITIVE
                    ),
                    encodeCurve = false,
                    encodePublicKey = true,
                    publicKey = PublicKey.fromIosEncoded(keyBytes.sliceArray(0..<crv.iosEncodedPublicKeyLength)) as PublicKey.EC
                )
            }
        }

        object FromSEC1 : Asn1Decodable<Asn1Sequence, EC> {

            override fun doDecode(src: Asn1Sequence): EC =
                doDecode(src, attributes = null)

            /**
             * SEC1 V2 decoding optionally supporting attributes for later PKCS#8 encoding
             */
            @Throws(Asn1Exception::class)
            fun doDecode(
                src: Asn1Sequence,
                attributes: List<Asn1Element>? = null,
            ): EC {
                return fromRaw(EcPrivateKey.decodeFromTlv(src), attributes)
            }

            @Throws(Asn1Exception::class)
            fun fromRaw(
                raw: EcPrivateKey,
                attributes: List<Asn1Element>? = null,
            ): EC {
                require(raw.version == 1) { "EC public key version must be 1" }
                val pkcs8 = PrivateKeyInfo.ec(raw, raw.parameters, attributes)
                return when (raw.parameters) {
                    null -> EC.WithoutPublicKey(pkcs8)
                    else -> EC.WithPublicKey(pkcs8)
                }
            }
        }
    }

    companion object :
        LabelPemDecodable<Asn1Sequence, PrivateKey>(
            EB_STRINGS.GENERIC_PRIVATE_KEY_PKCS8 to checkedAsFn { source ->
                FromPKCS8.fromRaw(PrivateKeyInfo.decodeFromDer(source))
            },
            EB_STRINGS.RSA_PRIVATE_KEY_PKCS1 to checkedAsFn { source ->
                RSA.FromPKCS1.fromRaw(RsaPrivateKey.decodeFromDer(source))
            },
            EB_STRINGS.EC_PRIVATE_KEY_SEC1 to checkedAsFn { source ->
                EC.FromSEC1.fromRaw(EcPrivateKey.decodeFromDer(source))
            }
        ), Asn1Decodable<Asn1Sequence, PrivateKey> by FromPKCS8 {
        fun fromRaw(raw: PrivateKeyInfo): PrivateKey = FromPKCS8.fromRaw(raw)

        /**
         * Tries to decode a private key as exported from iOS.
         * EC keys are exported [as padded raw bytes](https://developer.apple.com/documentation/security/seckeycopyexternalrepresentation(_:_:)?language=objc).
         * RSA keys are exported using PKCS#1 encoding
         */
        fun fromIosEncoded(keyBytes: ByteArray): KmmResult<PrivateKey.WithPublicKey<*>> = catching {
            if (keyBytes.first() == ANSIECPrefix.UNCOMPRESSED.prefixByte) PrivateKey.EC.iosDecodeInternal((keyBytes))
            else PrivateKey.RSA.FromPKCS1.fromRaw(RsaPrivateKey.decodeFromDer(keyBytes))
        }

    }

    object FromPKCS8 : Asn1Decodable<Asn1Sequence, PrivateKey> {
        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Sequence): PrivateKey {
            val raw = PrivateKeyInfo.decodeFromTlv(src)
            return fromRaw(raw)
        }

        @Throws(Asn1Exception::class)
        fun fromRaw(raw: PrivateKeyInfo): PrivateKey {
            require(raw.version == 0) { "PKCS#8 Private Key VERSION must be 0" }
            val algIdentifier = raw.algorithmOid
            val algParams = raw.algorithmParameters.singleOrNull()?.asPrimitive()

            val decoded = when (algIdentifier) {
                RSA.oid -> {
                    requireNotNull(algParams) { "RSA algorithm identifier must contain NULL parameters" }.readNull()
                    RSA(raw)
                }

                EC.oid -> {
                    if (algParams != null) {
                        val predefinedCurve = ECCurve.entries.first { it.oid == ObjectIdentifier.decodeFromTlv(algParams) }
                        val decoded = EC.WithPublicKey(raw)
                        require(decoded.curve == predefinedCurve)
                        decoded
                    } else {
                        EC.WithoutPublicKey(raw)
                    }
                }

                else -> throw IllegalArgumentException("Unknown Algorithm: $algIdentifier")
            }
            return decoded
        }
    }
}

@Deprecated(
    "Renamed to PrivateKey.",
    ReplaceWith("PrivateKey", "at.asitplus.signum.indispensable.PrivateKey")
)
typealias CryptoPrivateKey = PrivateKey

@Deprecated(
    "Moved to awesn1 crypto raw model.",
    ReplaceWith(
        "EncryptedPrivateKeyInfo",
        "at.asitplus.awesn1.crypto.EncryptedPrivateKeyInfo"
    )
)
typealias EncryptedPrivateKey = EncryptedPrivateKeyInfo
