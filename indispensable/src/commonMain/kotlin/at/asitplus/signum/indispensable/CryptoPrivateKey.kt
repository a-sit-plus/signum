package at.asitplus.signum.indispensable

import at.asitplus.KmmResult
import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.EcPrivateKey
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
@Deprecated(
    "Renamed to PrivateKey.",
    ReplaceWith("PrivateKey", "at.asitplus.signum.indispensable.PrivateKey")
)
typealias CryptoPrivateKey = PrivateKey
sealed interface PrivateKey : Asn1PemEncodable<Asn1Sequence>, Identifiable {

    sealed interface WithPublicKey<T : PublicKey> : PrivateKey {
        /** [PublicKey] matching this private key. */
        val publicKey: T
    }

    /** optional attributes relevant when PKCS#8-encoding a private key */
    val attributes: List<Asn1Element>?

    /** Encodes this private key into a PKCS#8-encoded private key. This is the default. */
    val asPKCS8: Asn1PemEncodable<Asn1Sequence> get() = this

    sealed class Impl(
        /** optional attributes relevant when PKCS#8-encoding a private key */
        override val attributes: List<Asn1Element>?,
        private val rawBacking: PrivateKeyInfo? = null,
    ) : PrivateKey, Awesn1Backed<PrivateKeyInfo> {
        protected abstract fun buildRaw(): PrivateKeyInfo

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

        override val raw: PrivateKeyInfo
            get() = rawBacking ?: buildRaw()
    }

    /**
     * PKCS#1 RSA Private key representation as per [RFC 8017](https://datatracker.ietf.org/doc/html/rfc8017/#appendix-A.1.2) augmented with optional [attributes].
     * Attributes are never PKCS#1 encoded, but are relevant when PKCS#8-encoding a private key.
     */
    class RSA
    /** @throws IllegalArgumentException in case invalid parameters are provided*/
    @Throws(IllegalArgumentException::class)
    constructor(
        /** The [PublicKey.RSA] (n,e) matching this private key */
        override val publicKey: PublicKey.RSA,
        /** d: the private key such that d*e = 1 mod phi(n) */
        val privateKey: BigInteger,
        /** p: the first prime factor */
        val prime1: BigInteger,
        /** q: the second prime factor */
        val prime2: BigInteger,
        /** dP: the first factor's CRT exponent */
        val prime1exponent: BigInteger,
        /** dQ: the second factor's CRT exponent */
        val prime2exponent: BigInteger,
        /** qInv: the factors' CRT coefficient (q^(-1) mod p) */
        val crtCoefficient: BigInteger,
        /** information about additional prime factors: triples (r_i, d_i, t_i) of prime factor, exponent, coefficient */
        val otherPrimeInfos: List<PrimeInfo>?,
        /** PKCS#8 attributes */
        attributes: List<Asn1Element>? = null,
        private val rawBacking: PrivateKeyInfo? = null,
    ) : PrivateKey.Impl(attributes, rawBacking), WithPublicKey<PublicKey.RSA> {
        override fun buildRaw() = PrivateKeyInfo.rsa(toRawPrivateKey(), attributes)

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
            override fun encodeToTlv() = toRawPrivateKey().encodeToTlv()
        }

        private fun toRawPrivateKey() = RsaPrivateKey(
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
        )

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

            @Throws(Asn1Exception::class)
            override fun encodeToTlv() = runRethrowing {
                Asn1.Sequence {
                    +Asn1.Int(prime)
                    +Asn1.Int(exponent)
                    +Asn1.Int(coefficient)
                }
            }

            companion object : Asn1Decodable<Asn1Sequence, PrimeInfo> {

                @Throws(Asn1Exception::class)
                override fun doDecode(src: Asn1Sequence): PrimeInfo = src.decodeRethrowing {
                    val prime = next().asPrimitive().decodeToBigInteger()
                    val exponent = next().asPrimitive().decodeToBigInteger()
                    val coefficient = next().asPrimitive().decodeToBigInteger()
                    PrimeInfo(prime, exponent, coefficient)
                }

            }
        }

        companion object : LabelPemDecodable<Asn1Sequence, RSA>(
            EB_STRINGS.GENERIC_PRIVATE_KEY_PKCS8 to checkedAsFn(FromPKCS8::decodeFromDer),
            EB_STRINGS.RSA_PRIVATE_KEY_PKCS1 to checkedAsFn(FromPKCS1::decodeFromDer)
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
            fun doDecode(src: Asn1Sequence, attributes: List<Asn1Element>? = null, rawBacking: PrivateKeyInfo? = null): RSA {
                val raw = RsaPrivateKey.decodeFromTlv(src)
                val version = raw.version
                require(version == 0 || version == 1) { "RSA Private key VERSION must be 0 or 1" }
                val otherPrimeInfos = raw.otherPrimeInfos?.map {
                    PrimeInfo(
                        prime = it.prime.toBigInteger(),
                        exponent = it.exponent.toBigInteger(),
                        coefficient = it.coefficient.toBigInteger(),
                    )
                }
                if (otherPrimeInfos != null) {
                    require(version == 1) { "OtherPrimeInfos is present. RSA private key version must be 1" }
                } else {
                    require(version == 0) { "OtherPrimeInfos is not present. RSA private key version must be 0" }
                }

                return RSA(
                    PublicKey.RSA(raw.modulus, raw.publicExponent),
                    raw.privateExponent.toBigInteger(),
                    raw.prime1.toBigInteger(),
                    raw.prime2.toBigInteger(),
                    raw.exponent1.toBigInteger(),
                    raw.exponent2.toBigInteger(),
                    raw.coefficient.toBigInteger(),
                    otherPrimeInfos,
                    attributes,
                    rawBacking,
                )
            }
        }

        override fun toString() = "RSA private key for public key $publicKey"
    }

    /**
     * SEC1 Elliptic Curve Private Key Structure as per [RFC 5915](https://datatracker.ietf.org/doc/html/rfc5915) augmented with optional [attributes].
     * Attributes are never SEC1 encoded, but are relevant when PKCS#8-encoding a private key.
     */
    sealed class EC(
        val privateKey: BigInteger,
        /** PKCS#8 attributes */
        attributes: List<Asn1Element>? = null,
        private val rawBacking: PrivateKeyInfo? = null,
    ) : PrivateKey.Impl(attributes, rawBacking) {
        override fun buildRaw() = when (this) {
            is WithPublicKey -> PrivateKeyInfo.ec(toRawPrivateKey(), curve.oid, attributes)
            is WithoutPublicKey ->
                throw Asn1StructuralException("Cannot PKCS#8-encode an EC key without curve. Use withCurve()!")
        }

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
            override fun encodeToTlv() = toRawPrivateKey().encodeToTlv()
        }

        private fun toRawPrivateKey() = when (this) {
            is WithPublicKey -> EcPrivateKey(
                version = 1,
                privateKey = privateKeyBytes,
                parameters = if (encodeCurve) curve.oid else null,
                publicKey = if (encodePublicKey) Asn1BitString(publicKey.iosEncoded) else null,
            )

            is WithoutPublicKey -> EcPrivateKey(
                version = 1,
                privateKey = privateKeyBytes,
                parameters = null,
                publicKey = publicKeyBytes,
            )
        }

        class WithPublicKey
        /** @throws IllegalArgumentException in case invalid parameters are provided*/
        @Throws(IllegalArgumentException::class)
        constructor(
            privateKey: BigInteger,
            override val publicKey: PublicKey.EC,
            val encodeCurve: Boolean,
            val encodePublicKey: Boolean,
            attributes: List<Asn1Element>? = null,
            rawBacking: PrivateKeyInfo? = null,
        ) : EC(privateKey, attributes, rawBacking), PrivateKey.WithPublicKey<PublicKey.EC>,
            KeyAgreementPrivateValue.ECDH {

            constructor(
                privateKey: BigInteger, curve: ECCurve,
                encodeCurve: Boolean, encodePublicKey: Boolean, attributes: List<Asn1Element>? = null
            ) :
                    this(
                        privateKey, curve.generator.times(privateKey).asPublicKey(preferCompressed = true),
                        encodeCurve, encodePublicKey, attributes
                    )

            init {
                require(publicKey.publicPoint == privateKey.times(publicKey.curve.generator)) { "Public key must match the private key!" }
            }

            val curve get() = publicKey.curve

            override fun toString(): String {
                return "EC private key for public key $publicKey"
            }

            override val privateKeyBytes: ByteArray
                get() = privateKey.toByteArray().ensureSize(curve.scalarLength.bytes)

            override val publicValue get() = this.publicKey
        }

        class WithoutPublicKey constructor(
            privateKey: BigInteger,
            val publicKeyBytes: Asn1BitString?,
            attributes: List<Asn1Element>? = null,
            private val curveOrderLengthInBytes: Int,
            rawBacking: PrivateKeyInfo? = null,
        ) : EC(privateKey, attributes, rawBacking) {

            /** Creates a new [PrivateKey.EC.WithPublicKey] based on the passed curve. */
            fun withCurve(
                curve: ECCurve,
                encodeCurve: Boolean = true,
                encodePublicKey: Boolean = (this.publicKeyBytes != null)
            )
                    : WithPublicKey {
                require(curve.scalarLength.bytes.toInt() == curveOrderLengthInBytes)
                { "Encoded private key was padded to $curveOrderLengthInBytes bytes, but curve $curve needs padding to ${curve.scalarLength.bytes.toInt()} bytes" }
                return if (publicKeyBytes != null) {
                    PrivateKey.EC.WithPublicKey(
                        privateKey,
                        PublicKey.EC.fromAnsiX963Bytes(curve, publicKeyBytes.rawBytes),
                        encodeCurve,
                        encodePublicKey,
                        attributes
                    )
                } else {
                    PrivateKey.EC.WithPublicKey(
                        privateKey,
                        curve,
                        encodeCurve,
                        encodePublicKey,
                        attributes
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
            EB_STRINGS.GENERIC_PRIVATE_KEY_PKCS8 to checkedAsFn(FromPKCS8::decodeFromDer),
            EB_STRINGS.EC_PRIVATE_KEY_SEC1 to checkedAsFn(FromSEC1::decodeFromDer)
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
                rawBacking: PrivateKeyInfo? = null,
            ): EC {
                val raw = EcPrivateKey.decodeFromTlv(src)
                require(raw.version == 1) { "EC public key version must be 1" }
                val privateKey = EC.WithoutPublicKey(
                    BigInteger.fromByteArray(raw.privateKey, Sign.POSITIVE),
                    raw.publicKey,
                    attributes,
                    raw.privateKey.size,
                    rawBacking,
                )
                return when (val curve = raw.parameters?.let(ECCurve::withOid)) {
                    null -> privateKey
                    else -> privateKey.withCurve(curve)
                }
            }
        }
    }

    companion object :
        LabelPemDecodable<Asn1Sequence, PrivateKey>(
            EB_STRINGS.GENERIC_PRIVATE_KEY_PKCS8 to checkedAsFn(FromPKCS8::decodeFromDer),
            EB_STRINGS.RSA_PRIVATE_KEY_PKCS1 to checkedAsFn(RSA.FromPKCS1::decodeFromDer),
            EB_STRINGS.EC_PRIVATE_KEY_SEC1 to checkedAsFn(EC.FromSEC1::decodeFromDer)
        ), Asn1Decodable<Asn1Sequence, PrivateKey> by FromPKCS8 {
        /**
         * Tries to decode a private key as exported from iOS.
         * EC keys are exported [as padded raw bytes](https://developer.apple.com/documentation/security/seckeycopyexternalrepresentation(_:_:)?language=objc).
         * RSA keys are exported using PKCS#1 encoding
         */
        fun fromIosEncoded(keyBytes: ByteArray): KmmResult<PrivateKey.WithPublicKey<*>> = catching {
            if (keyBytes.first() == ANSIECPrefix.UNCOMPRESSED.prefixByte) PrivateKey.EC.iosDecodeInternal((keyBytes))
            else PrivateKey.RSA.FromPKCS1.decodeFromTlv(Asn1Element.parse(keyBytes).asSequence())
        }

    }

    object FromPKCS8 : Asn1Decodable<Asn1Sequence, PrivateKey> {
        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Sequence): PrivateKey {
            val raw = PrivateKeyInfo.decodeFromTlv(src)
            require(raw.version == 0) { "PKCS#8 Private Key VERSION must be 0" }
            val (algIdentifier, algParams) = raw.privateKeyAlgorithm.decodeRethrowing {
                ObjectIdentifier.decodeFromTlv(next().asPrimitive()) to next().asPrimitive()
            }

            val privateKeyStructure = raw.privateKey.asEncapsulatingOctetString().decodeRethrowing { next().asSequence() }
            val attributes = raw.attributes

            val decoded = when (algIdentifier) {
                RSA.oid -> {
                    algParams.readNull()
                    RSA.FromPKCS1.doDecode(privateKeyStructure, attributes, raw)
                }

                EC.oid -> {
                    val predefinedCurve = ECCurve.entries.first { it.oid == ObjectIdentifier.decodeFromTlv(algParams) }
                    EC.FromSEC1.doDecode(privateKeyStructure, attributes, raw).let {
                        when (it) {
                            is EC.WithPublicKey -> it.also { require(it.curve == predefinedCurve) }
                            is EC.WithoutPublicKey -> it.withCurve(predefinedCurve, encodeCurve = false)
                        }
                    }
                }

                else -> throw IllegalArgumentException("Unknown Algorithm: $algIdentifier")
            }
            return decoded
        }
    }
}

/** Representation of an encrypted private key structure as per [RFC 5208](https://datatracker.ietf.org/doc/html/rfc5208) */
class EncryptedPrivateKey(val encryptionAlgorithm: ObjectIdentifier, val encryptedData: ByteArray) :
    Asn1PemEncodable<Asn1Sequence> {

    override val pemLabel get() = EB_STRINGS.ENCRYPTED_PRIVATE_KEY

    @Throws(Asn1Exception::class)
    override fun encodeToTlv(): Asn1Sequence = runRethrowing {
        Asn1.Sequence {
            +encryptionAlgorithm
            +Asn1.OctetString(encryptedData)
        }
    }

    companion object : LabelPemDecodable<Asn1Sequence, EncryptedPrivateKey>(EB_STRINGS.ENCRYPTED_PRIVATE_KEY) {

        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Sequence): EncryptedPrivateKey = src.decodeRethrowing {
            EncryptedPrivateKey(
                ObjectIdentifier.decodeFromTlv(next().asPrimitive()),
                next().asPrimitive().asOctetString().content
            )
        }
    }
}
