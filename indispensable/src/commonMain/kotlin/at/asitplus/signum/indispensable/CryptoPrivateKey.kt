package at.asitplus.signum.indispensable

import at.asitplus.KmmResult
import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.Pkcs1RsaOtherPrimeInfo
import at.asitplus.awesn1.crypto.Pkcs1RsaPrivateKeyInfo
import at.asitplus.awesn1.crypto.Pkcs8PrivateKeyInfo
import at.asitplus.awesn1.crypto.Sec1EcPrivateKeyInfo
import at.asitplus.catching
import at.asitplus.signum.ecmath.times
import at.asitplus.signum.indispensable.CryptoPublicKey.EC.Companion.asPublicKey
import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.misc.ANSIECPrefix
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
sealed interface CryptoPrivateKey : Identifiable {


    sealed interface WithPublicKey<T : CryptoPublicKey> : CryptoPrivateKey {
        /** [CryptoPublicKey] matching this private key. */
        val publicKey: T
    }

    /** optional attributes relevant when PKCS#8-encoding a private key */
    val attributes: Set<Asn1Element>?

    /** Encodes this private key into a PKCS#8-encoded private key. This is the default. */
    fun toPkcs8(): Pkcs8PrivateKeyInfo

    sealed class Impl(
        override val backing: Pkcs8PrivateKeyInfo,

        ) : Awesn1Backed<Pkcs8PrivateKeyInfo>, CryptoPrivateKey {


        /** optional attributes relevant when PKCS#8-encoding a private key */
        override val attributes: Set<Asn1Element>? get() = backing.attributes
        override fun toPkcs8(): Pkcs8PrivateKeyInfo = backing

        /**
         * PKCS#1 RSA Private key representation as per [RFC 8017](https://datatracker.ietf.org/doc/html/rfc8017/#appendix-A.1.2) augmented with optional [attributes].
         * Attributes are never PKCS#1 encoded, but are relevant when PKCS#8-encoding a private key.
         */

        companion object {
            fun fromPkcs8(pkcs8PrivateKeyInfo: Pkcs8PrivateKeyInfo): Impl = when (pkcs8PrivateKeyInfo.algorithmOid) {
                RSA.oid -> RSA(pkcs8PrivateKeyInfo.decodeRsaPrivateKey(), pkcs8PrivateKeyInfo.attributes)
                EC.oid -> pkcs8PrivateKeyInfo.decodeEcPrivateKey().let { sec1 ->
                    EC.fromSec1(sec1,pkcs8PrivateKeyInfo.attributes)
                }
                else -> throw IllegalArgumentException("OID ${pkcs8PrivateKeyInfo.algorithmOid} is not supported")
            }
        }
    }

    class RSA(val pkcs1: Pkcs1RsaPrivateKeyInfo, attributes: Set<Asn1Element>?) :
        CryptoPrivateKey.Impl(Pkcs8PrivateKeyInfo.rsa(privateKey = pkcs1, attributes = attributes)),
        WithPublicKey<CryptoPublicKey.RSA> {

        /** @throws IllegalArgumentException in case invalid parameters are provided*/
        @Throws(IllegalArgumentException::class)
        constructor(
            /** The [CryptoPublicKey.RSA] (n,e) matching this private key */
            publicKey: CryptoPublicKey.RSA,
            /** d: the private key such that d*e = 1 mod phi(n) */
            privateKey: BigInteger,
            /** p: the first prime factor */
            prime1: BigInteger,
            /** q: the second prime factor */
            prime2: BigInteger,
            /** dP: the first factor's CRT exponent */
            prime1exponent: BigInteger,
            /** dQ: the second factor's CRT exponent */
            prime2exponent: BigInteger,
            /** qInv: the factors' CRT coefficient (q^(-1) mod p) */
            crtCoefficient: BigInteger,
            /** information about additional prime factors: triples (r_i, d_i, t_i) of prime factor, exponent, coefficient */
            otherPrimeInfos: List<PrimeInfo>?,
            /** PKCS#8 attributes */
            attributes: Set<Asn1Element>? = null
        ) : this(
            Pkcs1RsaPrivateKeyInfo(
                rawVersion = Asn1Integer(if (otherPrimeInfos != null) 1 else 0),
                modulus = publicKey.n,
                publicExponent = publicKey.e,
                privateExponent = privateKey.toAsn1Integer() as Asn1Integer.Positive,
                prime1 = prime1.toAsn1Integer() as Asn1Integer.Positive,
                prime2 = prime2.toAsn1Integer() as Asn1Integer.Positive,
                exponent1 = prime1exponent.toAsn1Integer() as Asn1Integer.Positive,
                exponent2 = prime2exponent.toAsn1Integer() as Asn1Integer.Positive,
                coefficient = crtCoefficient.toAsn1Integer() as Asn1Integer.Positive,
                otherPrimeInfos = otherPrimeInfos?.map { it.backing }
            ),
            attributes
        )


        /** d: the private key such that d*e = 1 mod phi(n) */
        val privateKey: BigInteger by lazy { pkcs1.privateExponent.toBigInteger() }

        /** p: the first prime factor */
        val prime1: BigInteger by lazy { pkcs1.prime1.toBigInteger() }

        /** q: the second prime factor */
        val prime2: BigInteger by lazy { pkcs1.prime2.toBigInteger() }

        /** dP: the first factor's CRT exponent */
        val prime1exponent: BigInteger by lazy { pkcs1.exponent1.toBigInteger() }

        /** dQ: the second factor's CRT exponent */
        val prime2exponent: BigInteger by lazy { pkcs1.exponent2.toBigInteger() }

        /** qInv: the factors' CRT coefficient (q^(-1) mod p) */
        val crtCoefficient: BigInteger by lazy { pkcs1.coefficient.toBigInteger() }

        /** information about additional prime factors: triples (r_i, d_i, t_i) of prime factor, exponent, coefficient */
        val otherPrimeInfos: List<PrimeInfo>? by lazy { pkcs1.otherPrimeInfos?.map { PrimeInfo(it) } }


        /** The [CryptoPublicKey.RSA] (n,e) matching this private key */
        override val publicKey: CryptoPublicKey.RSA = CryptoPublicKey.RSA(pkcs1.modulus, pkcs1.publicExponent)

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
                    { "t_$i != (r_0 * ... * r_${i - 1})^(-1) mod r_$i" }
                    product *= info.prime
                    require(info.exponent == privateKey.mod(pminusone)) { "d_$i != d mod (p_$i - 1)" }
                    require(e.multiply(info.exponent).mod(pminusone) == BigInteger.ONE)
                }
            require(product == n) { "p1 * p2 * … * pk != n" }
        }

        fun toPkcs1() = pkcs1

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
        data class PrimeInfo(override val backing: Pkcs1RsaOtherPrimeInfo) : Awesn1Backed<Pkcs1RsaOtherPrimeInfo> {

            constructor(
                prime: BigInteger,
                exponent: BigInteger,
                coefficient: BigInteger,
            ) : this(
                Pkcs1RsaOtherPrimeInfo(
                    prime.toAsn1Integer() as Asn1Integer.Positive,
                    exponent.toAsn1Integer() as Asn1Integer.Positive,
                    coefficient.toAsn1Integer() as Asn1Integer.Positive
                )
            )

            val prime: BigInteger by lazy { backing.prime.toBigInteger() }
            val exponent: BigInteger by lazy { backing.exponent.toBigInteger() }
            val coefficient: BigInteger by lazy { backing.coefficient.toBigInteger() }


            companion object :
                Awesn1BackedSerializer<Pkcs1RsaOtherPrimeInfo, PrimeInfo>(
                    Pkcs1RsaOtherPrimeInfo.serializer(),
                    ::PrimeInfo
                )
        }

        companion object {
            val oid: ObjectIdentifier = KnownOIDs.rsaEncryption

            fun fromPkcs1(pkcs1: Pkcs1RsaPrivateKeyInfo, attributes: Set<Asn1Element>? = null): CryptoPrivateKey.RSA = RSA(pkcs1, attributes)
        }

        override fun toString() = "RSA private key for public key $publicKey"
    }

    /**
     * SEC1 Elliptic Curve Private Key Structure as per [RFC 5915](https://datatracker.ietf.org/doc/html/rfc5915) augmented with optional [attributes].
     * Attributes are never SEC1 encoded, but are relevant when PKCS#8-encoding a private key.
     */
    sealed class EC(
        val sec1: Sec1EcPrivateKeyInfo, attributes: Set<Asn1Element>?, curve: ECCurve?

    ) : CryptoPrivateKey.Impl(Pkcs8PrivateKeyInfo.ec(sec1, curve?.oid, attributes)) {


        constructor(
            privateKey: BigInteger,
            curve: ECCurve?,
            publicKey: CryptoPublicKey.EC?,
            /** PKCS#8 attributes */
            attributes: Set<Asn1Element>? = null
        ) : this(
            sec1 = Sec1EcPrivateKeyInfo(
                version = 1,
                privateKey = curve?.let { privateKey.toByteArray().ensureSize(it.scalarLength.bytes) }
                    ?: privateKey.toByteArray(),
                curve?.oid,
                publicKey?.toSubjectPublicKeyInfo()?.subjectPublicKey
            ), attributes, curve
        )

        constructor(
            privateKey: BigInteger,
            publicKeyEncoded: Asn1BitString?,
            /** PKCS#8 attributes */
            attributes: Set<Asn1Element>? = null
        ) : this(
            sec1 = Sec1EcPrivateKeyInfo(
                privateKey = privateKey.toByteArray(),
                parameters = null,
                publicKey = publicKeyEncoded,
            ), attributes, null
        )

        val privateKey: BigInteger by lazy { BigInteger.fromByteArray(sec1.privateKey, Sign.POSITIVE) }

        override val oid = EC.oid

        abstract val privateKeyBytes: ByteArray

        override fun equals(other: Any?): Boolean {
            if (other !is EC) return false
            return (privateKey == other.privateKey)
        }

        override fun hashCode() = privateKey.hashCode()

        fun toSec1() = sec1

        class WithPublicKey
        /** @throws IllegalArgumentException in case invalid parameters are provided*/
        @Throws(IllegalArgumentException::class)
        constructor(
            privateKey: BigInteger,
            override val publicKey: CryptoPublicKey.EC,
            val encodeCurve: Boolean,
            val encodePublicKey: Boolean,
            attributes: Set<Asn1Element>? = null
        ) : EC(
            privateKey = privateKey,
            attributes = attributes,
            curve = if (encodeCurve) publicKey.curve else null,
            publicKey = if (encodePublicKey) publicKey else null
        ), CryptoPrivateKey.WithPublicKey<CryptoPublicKey.EC>,
            KeyAgreementPrivateValue.ECDH {

            constructor(
                privateKey: BigInteger, curve: ECCurve,
                encodeCurve: Boolean, encodePublicKey: Boolean, attributes: Set<Asn1Element>? = null
            ) :
                    this(
                        privateKey = privateKey,
                        publicKey = curve.generator.times(privateKey).asPublicKey(preferCompressed = true),
                        encodeCurve,
                        encodePublicKey,
                        attributes
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
            attributes: Set<Asn1Element>? = null,
            private val curveOrderLengthInBytes: Int
        ) : EC(privateKey = privateKey, publicKeyEncoded = publicKeyBytes, attributes = attributes) {

            /** Creates a new [CryptoPrivateKey.EC.WithPublicKey] based on the passed curve. */
            fun withCurve(
                curve: ECCurve,
                encodeCurve: Boolean = true,
                encodePublicKey: Boolean = (this.publicKeyBytes != null)
            ): WithPublicKey {
                require(curve.scalarLength.bytes.toInt() == curveOrderLengthInBytes)
                { "Encoded private key was padded to $curveOrderLengthInBytes bytes, but curve $curve needs padding to ${curve.scalarLength.bytes.toInt()} bytes" }
                return if (publicKeyBytes != null) {
                    CryptoPrivateKey.EC.WithPublicKey(
                        privateKey,
                        CryptoPublicKey.EC.fromAnsiX963Bytes(curve, publicKeyBytes.rawBytes),
                        encodeCurve,
                        encodePublicKey,
                        attributes
                    )
                } else {
                    CryptoPrivateKey.EC.WithPublicKey(
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


        companion object
        //EB_STRINGS.GENERIC_PRIVATE_KEY_PKCS8 to checkedAsFn(FromPKCS8::decodeFromDer),
        // EB_STRINGS.EC_PRIVATE_KEY_SEC1 to checkedAsFn(FromSEC1::decodeFromDer)
        {
            val oid: ObjectIdentifier = KnownOIDs.ecPublicKey

            internal fun iosDecodeInternal(keyBytes: ByteArray): CryptoPrivateKey.EC.WithPublicKey {
                val crv = ECCurve.fromIosEncodedPrivateKeyLength(keyBytes.size)
                    ?: throw IllegalArgumentException("Unknown curve in iOS raw key")
                return EC.WithPublicKey(
                    BigInteger.fromByteArray(
                        keyBytes.sliceArray(crv.iosEncodedPublicKeyLength..<keyBytes.size),
                        Sign.POSITIVE
                    ),
                    encodeCurve = false,
                    encodePublicKey = true,
                    publicKey = CryptoPublicKey.fromIosEncoded(keyBytes.sliceArray(0..<crv.iosEncodedPublicKeyLength)) as CryptoPublicKey.EC
                )
            }


            fun fromSec1(sec1: Sec1EcPrivateKeyInfo, attributes: Set<Asn1Element>?): EC = runRethrowing {
                val curve: ECCurve? = sec1.parameters?.value?.let(ECCurve::withOid)
                val publicKey: Asn1BitString? = sec1.publicKey?.value
                val privateKey = EC.WithoutPublicKey(
                    BigInteger.fromByteArray(sec1.privateKey, Sign.POSITIVE),
                    publicKey,
                    attributes,
                    sec1.privateKey.size
                )
                when (curve) {
                    null -> privateKey
                    else -> privateKey.withCurve(curve)
                }
            }
        }
    }

    companion object

    //       EB_STRINGS.GENERIC_PRIVATE_KEY_PKCS8 to checkedAsFn(FromPKCS8::decodeFromDer),
    //     EB_STRINGS.RSA_PRIVATE_KEY_PKCS1 to checkedAsFn(RSA.FromPKCS1::decodeFromDer),
    //   EB_STRINGS.EC_PRIVATE_KEY_SEC1 to checkedAsFn(EC.FromSEC1::decodeFromDer)
    // Asn1Decodable<Asn1Sequence, CryptoPrivateKey> by FromPKCS8

    {
        /**
         * Tries to decode a private key as exported from iOS.
         * EC keys are exported [as padded raw bytes](https://developer.apple.com/documentation/security/seckeycopyexternalrepresentation(_:_:)?language=objc).
         * RSA keys are exported using PKCS#1 encoding
         */
        fun fromIosEncoded(keyBytes: ByteArray): KmmResult<CryptoPrivateKey.WithPublicKey<*>> = catching {
            if (keyBytes.first() == ANSIECPrefix.UNCOMPRESSED.prefixByte) CryptoPrivateKey.EC.iosDecodeInternal((keyBytes))
            TODO()
            //else CryptoPrivateKey.RSA.FromPKCS1.decodeFromTlv(Asn1Element.parse(keyBytes).asSequence())
        }


        fun fromPkcs8(pkcs8PrivateKeyInfo: Pkcs8PrivateKeyInfo): CryptoPrivateKey = Impl.fromPkcs8(pkcs8PrivateKeyInfo)

    }

}
