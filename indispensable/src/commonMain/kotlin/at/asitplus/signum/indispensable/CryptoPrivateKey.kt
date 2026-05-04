package at.asitplus.signum.indispensable

import at.asitplus.KmmResult
import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.Asn1PemDecodable
import at.asitplus.awesn1.Asn1PemEncodable
import at.asitplus.awesn1.Asn1Sequence
import at.asitplus.awesn1.Identifiable
import at.asitplus.awesn1.PemEncodable
import at.asitplus.awesn1.crypto.Pkcs1RsaOtherPrimeInfo
import at.asitplus.awesn1.crypto.Pkcs1RsaPrivateKeyInfo
import at.asitplus.awesn1.crypto.Pkcs8PrivateKeyInfo
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.encodeToTlv
import at.asitplus.catching
import at.asitplus.signum.ecmath.times
import at.asitplus.signum.indispensable.CryptoPublicKey.EC.Companion.asPublicKey
import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.misc.ANSIECPrefix
import at.asitplus.signum.internals.checkedAs
import at.asitplus.signum.internals.checkedAsFn
import at.asitplus.signum.internals.ensureSize
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import kotlin.collections.asSequence
import kotlin.collections.first
import kotlin.collections.map
import kotlin.map
import kotlin.ranges.first
import kotlin.sequences.asSequence
import kotlin.sequences.first
import kotlin.sequences.map
import kotlin.text.asSequence
import kotlin.text.first
import kotlin.text.map

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
sealed interface CryptoPrivateKey : Asn1PemEncodable<Asn1Sequence>, Identifiable {


    sealed interface WithPublicKey<T : CryptoPublicKey> : CryptoPrivateKey {
        /** [CryptoPublicKey] matching this private key. */
        val publicKey: T
    }

    /** optional attributes relevant when PKCS#8-encoding a private key */
    val attributes: Set<Asn1Element>?

    /** Encodes this private key into a PKCS#8-encoded private key. This is the default. */
    val asPKCS8: Asn1PemEncodable<Asn1Sequence> get() = this

    sealed class Impl(
        override val backing: Pkcs8PrivateKeyInfo,

        ) : Awesn1Backed<Pkcs8PrivateKeyInfo>, CryptoPrivateKey {
        override val pemLabel: String
            get() = EB_STRINGS.GENERIC_PRIVATE_KEY_PKCS8

        /** optional attributes relevant when PKCS#8-encoding a private key */
        override val attributes: Set<Asn1Element>? get() = backing.attributes

        /**
         * PKCS#1 RSA Private key representation as per [RFC 8017](https://datatracker.ietf.org/doc/html/rfc8017/#appendix-A.1.2) augmented with optional [attributes].
         * Attributes are never PKCS#1 encoded, but are relevant when PKCS#8-encoding a private key.
         */
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
                    version = if (otherPrimeInfos != null) 1 else 0,
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
            val prime1exponent: BigInteger by lazy { pkcs1.prime1.toBigInteger() }

            /** dQ: the second factor's CRT exponent */
            val prime2exponent: BigInteger by lazy { pkcs1.prime2.toBigInteger() }

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

            override fun encodeToTlv(): Asn1Sequence = runRethrowing { DER.encodeToTlv(backing) as Asn1Sequence }


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
                override fun encodeToTlv() = runRethrowing {
                    DER.encodeToTlv(pkcs1) as Asn1Sequence
                }
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

            companion object : Asn1PemDecodable<Asn1Sequence, RSA>(
                EB_STRINGS.GENERIC_PRIVATE_KEY_PKCS8 to checkedAsFn(FromPKCS8::decodeFromDer),
                EB_STRINGS.RSA_PRIVATE_KEY_PKCS1 to checkedAsFn(FromPKCS1::decodeFromDer)
            ) {
                override fun doDecode(src: Asn1Sequence): RSA =
                    checkedAs(CryptoPrivateKey.doDecode(src))

                val oid: ObjectIdentifier = KnownOIDs.rsaEncryption
            }

            object FromPKCS1 : Asn1Decodable<Asn1Sequence, RSA> {
                @Throws(Asn1Exception::class)
                override fun doDecode(src: Asn1Sequence): RSA = doDecode(src, null)

                /** PKCS1 decoding of an ASN.1 private key, optionally supporting attributes for later PKCS#8 encoding */
                @Throws(Asn1Exception::class)
                fun doDecode(src: Asn1Sequence, attributes: List<Asn1Element>? = null): RSA = src.decodeRethrowing {
                    val version = next().asPrimitive().decodeToInt()
                    require(version == 0 || version == 1) { "RSA Private key VERSION must be 0 or 1" }
                    val modulus = next().asPrimitive().decodeToAsn1Integer()
                    val publicExponent = next().asPrimitive().decodeToAsn1Integer()
                    val privateExponent = next().asPrimitive().decodeToBigInteger()
                    val prime1 = next().asPrimitive().decodeToBigInteger()
                    val prime2 = next().asPrimitive().decodeToBigInteger()
                    val exponent1 = next().asPrimitive().decodeToBigInteger()
                    val exponent2 = next().asPrimitive().decodeToBigInteger()
                    val coefficient = next().asPrimitive().decodeToBigInteger()

                    val otherPrimeInfos: List<PrimeInfo>? = if (hasNext()) {
                        require(version == 1) { "OtherPrimeInfos is present. RSA private key version must be 1" }
                        next().asSequence().children.map { PrimeInfo.decodeFromTlv(it.asSequence()) }
                    } else {
                        require(version == 0) { "OtherPrimeInfos is not present. RSA private key version must be 0" }
                        null
                    }

                    RSA(
                        CryptoPublicKey.RSA(modulus, publicExponent),
                        privateExponent,
                        prime1,
                        prime2,
                        exponent1,
                        exponent2,
                        coefficient,
                        otherPrimeInfos,
                        attributes
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
            attributes: List<Asn1Element>? = null
        ) : CryptoPrivateKey.Impl(attributes) {

            override val oid = EC.oid

            abstract val privateKeyBytes: ByteArray

            override fun equals(other: Any?): Boolean {
                if (other !is EC) return false
                return (privateKey == other.privateKey)
            }

            override fun hashCode() = privateKey.hashCode()

            /** Encodes this private key into a SEC1-encoded private key */
            val asSEC1 = object : PemEncodable<Asn1Sequence> {
                override val canonicalPEMBoundary get() = EB_STRINGS.EC_PRIVATE_KEY_SEC1

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
                override fun encodeToTlv() = runRethrowing {
                    Asn1.Sequence {
                        +Asn1.Int(1)
                        +Asn1OctetString(privateKeyBytes)
                        when (this@EC) {
                            is EC.WithPublicKey -> {
                                if (encodeCurve) +Asn1.ExplicitlyTagged(0uL) { +curve.oid }
                                if (encodePublicKey) +Asn1.ExplicitlyTagged(1uL) { +Asn1.BitString(publicKey.iosEncoded) }
                            }

                            is EC.WithoutPublicKey -> {
                                if (publicKeyBytes != null) +Asn1.ExplicitlyTagged(1uL) { +publicKeyBytes }
                            }
                        }

                    }
                }
            }

            class WithPublicKey
            /** @throws IllegalArgumentException in case invalid parameters are provided*/
            @Throws(IllegalArgumentException::class)
            constructor(
                privateKey: BigInteger,
                override val publicKey: CryptoPublicKey.EC,
                val encodeCurve: Boolean,
                val encodePublicKey: Boolean,
                attributes: List<Asn1Element>? = null
            ) : EC(privateKey, attributes), CryptoPrivateKey.WithPublicKey<CryptoPublicKey.EC>,
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
                private val curveOrderLengthInBytes: Int
            ) : EC(privateKey, attributes) {

                /** Creates a new [CryptoPrivateKey.EC.WithPublicKey] based on the passed curve. */
                fun withCurve(
                    curve: ECCurve,
                    encodeCurve: Boolean = true,
                    encodePublicKey: Boolean = (this.publicKeyBytes != null)
                )
                        : WithPublicKey {
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


            companion object : PemDecodable<Asn1Sequence, EC>(
                EB_STRINGS.GENERIC_PRIVATE_KEY_PKCS8 to checkedAsFn(FromPKCS8::decodeFromDer),
                EB_STRINGS.EC_PRIVATE_KEY_SEC1 to checkedAsFn(FromSEC1::decodeFromDer)
            ) {
                val oid: ObjectIdentifier = KnownOIDs.ecPublicKey

                @Throws(Asn1Exception::class)
                override fun doDecode(src: Asn1Sequence): EC =
                    checkedAs(CryptoPrivateKey.doDecode(src))

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
                    attributes: List<Asn1Element>? = null
                ): EC = src.decodeRethrowing {
                    val version = next().asPrimitive().decodeToInt()
                    require(version == 1) { "EC public key version must be 1" }
                    val privateKeyOctets = next().asOctetString().content

                    var curve: ECCurve? = null
                    var publicKey: Asn1BitString? = null
                    while (hasNext()) {
                        val elm = next().asExplicitlyTagged()
                        when (elm.tag.tagValue) {
                            0uL -> {
                                require(curve == null) { "Duplicate EC curve field in EC PrivateKey" }
                                require(publicKey == null) { "Field order violation in EC PrivateKey" }
                                require(elm.children.size == 1) { "Invalid EC curve field in EC PrivateKey" }
                                curve =
                                    ObjectIdentifier.decodeFromTlv(elm.children.first().asPrimitive())
                                        .let(ECCurve::withOid)
                            }

                            1uL -> {
                                require(publicKey == null) { "Duplicate public key field in EC PrivateKey" }
                                require(elm.children.size == 1) { "Invalid public key field in EC PrivateKey" }
                                publicKey = elm.children.first().asPrimitive().asAsn1BitString()
                            }

                            else -> throw Asn1Exception("Unknown optional field with tag ${elm.tag.tagValue} in EC PrivateKey")
                        }
                    }

                    val privateKey = EC.WithoutPublicKey(
                        BigInteger.fromByteArray(privateKeyOctets, Sign.POSITIVE),
                        publicKey,
                        attributes,
                        privateKeyOctets.size
                    )
                    when (curve) {
                        null -> privateKey
                        else -> privateKey.withCurve(curve)
                    }
                }
            }
        }

        companion object :
            PemDecodable<Asn1Sequence, CryptoPrivateKey>(
                EB_STRINGS.GENERIC_PRIVATE_KEY_PKCS8 to checkedAsFn(FromPKCS8::decodeFromDer),
                EB_STRINGS.RSA_PRIVATE_KEY_PKCS1 to checkedAsFn(RSA.FromPKCS1::decodeFromDer),
                EB_STRINGS.EC_PRIVATE_KEY_SEC1 to checkedAsFn(EC.FromSEC1::decodeFromDer)
            ), Asn1Decodable<Asn1Sequence, CryptoPrivateKey> by FromPKCS8 {
            /**
             * Tries to decode a private key as exported from iOS.
             * EC keys are exported [as padded raw bytes](https://developer.apple.com/documentation/security/seckeycopyexternalrepresentation(_:_:)?language=objc).
             * RSA keys are exported using PKCS#1 encoding
             */
            fun fromIosEncoded(keyBytes: ByteArray): KmmResult<CryptoPrivateKey.WithPublicKey<*>> = catching {
                if (keyBytes.first() == ANSIECPrefix.UNCOMPRESSED.prefixByte) CryptoPrivateKey.EC.iosDecodeInternal((keyBytes))
                else CryptoPrivateKey.RSA.FromPKCS1.decodeFromTlv(Asn1Element.parse(keyBytes).asSequence())
            }

        }

        object FromPKCS8 : Asn1Decodable<Asn1Sequence, CryptoPrivateKey> {
            @Throws(Asn1Exception::class)
            override fun doDecode(src: Asn1Sequence): CryptoPrivateKey = src.decodeRethrowing<CryptoPrivateKey> {
                require(next().asPrimitive().decodeToInt() == 0) { "PKCS#8 Private Key VERSION must be 0" }
                val (algIdentifier, algParams) = next().asSequence().decodeRethrowing {
                    ObjectIdentifier.decodeFromTlv(next().asPrimitive()) to next().asPrimitive()
                }

                val privateKeyStructure = next().asEncapsulatingOctetString().decodeRethrowing { next().asSequence() }
                val attributes: List<Asn1Element>? =
                    if (hasNext()) next().asStructure().assertTag(0uL).children
                    else null
                when (algIdentifier) {
                    RSA.oid -> {
                        algParams.readNull()
                        RSA.FromPKCS1.doDecode(privateKeyStructure, attributes)
                    }

                    EC.oid -> {
                        val predefinedCurve =
                            ECCurve.entries.first { it.oid == ObjectIdentifier.decodeFromTlv(algParams) }
                        EC.FromSEC1.doDecode(privateKeyStructure, attributes).let {
                            when (it) {
                                is EC.WithPublicKey -> it.also { require(it.curve == predefinedCurve) }
                                is EC.WithoutPublicKey -> it.withCurve(predefinedCurve, encodeCurve = false)
                            }
                        }
                    }

                    else -> throw IllegalArgumentException("Unknown Algorithm: $algIdentifier")
                }
            }
        }
    }

    /** Representation of an encrypted private key structure as per [RFC 5208](https://datatracker.ietf.org/doc/html/rfc5208) */
    class EncryptedPrivateKey(val encryptionAlgorithm: ObjectIdentifier, val encryptedData: ByteArray) :
        PemEncodable<Asn1Sequence> {

        override val canonicalPEMBoundary get() = EB_STRINGS.ENCRYPTED_PRIVATE_KEY

        @Throws(Asn1Exception::class)
        override fun encodeToTlv(): Asn1Sequence = runRethrowing {
            Asn1.Sequence {
                +encryptionAlgorithm
                +Asn1.OctetString(encryptedData)
            }
        }

        companion object : PemDecodable<Asn1Sequence, EncryptedPrivateKey>(EB_STRINGS.ENCRYPTED_PRIVATE_KEY) {

            @Throws(Asn1Exception::class)
            override fun doDecode(src: Asn1Sequence): EncryptedPrivateKey = src.decodeRethrowing {
                EncryptedPrivateKey(
                    ObjectIdentifier.decodeFromTlv(next().asPrimitive()),
                    next().asPrimitive().asOctetString().content
                )
            }
        }
    }
