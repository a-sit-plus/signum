package at.asitplus.signum.indispensable

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.ecmath.times
import at.asitplus.signum.indispensable.CryptoPublicKey.EC.Companion.asPublicKey
import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.encoding.*
import at.asitplus.signum.indispensable.misc.ANSIECPrefix
import at.asitplus.signum.indispensable.misc.ensureSize
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign

private object EB_STRINGS {
    const val GENERIC_PRIVATE_KEY_PKCS8 = "PRIVATE KEY"
    const val RSA_PRIVATE_KEY_PKCS1 = "RSA PRIVATE KEY"
    const val EC_PRIVATE_KEY_SEC1 = "EC PRIVATE KEY"
    const val ENCRYPTED_PRIVATE_KEY = "ENCRYPTED PRIVATE KEY"
}

private inline fun <O, reified T> checkedAs(v: O): T =
    v as? T
        ?: throw IllegalArgumentException("Expected type was ${T::class.simpleName}, but was really ${if (v == null) "<null>" else v!!::class.simpleName}")

private inline fun <I, O, reified T> checkedAsFn(crossinline fn: (I) -> O): (I) -> T = {
    checkedAs(fn(it))
}

/**
 * PKCS#8 Representation of a private key structure as per [RFC 5208](https://datatracker.ietf.org/doc/html/rfc5208)
 */
sealed class CryptoPrivateKey(
    /** optional attributes relevant when PKCS#8-encoding a private key */
    val attributes: List<Asn1Element>?
) : PemEncodable<Asn1Sequence>, Identifiable {

    sealed interface WithPublicKey<T : CryptoPublicKey> : PemEncodable<Asn1Sequence>, Identifiable {
        /** [CryptoPublicKey] matching this private key. */
        val publicKey: T
    }

    /** Encodes this private key into a PKCS#8-encoded private key. This is the default. */
    val asPKCS8: PemEncodable<Asn1Sequence> get() = this

    override val canonicalPEMBoundary get() = EB_STRINGS.GENERIC_PRIVATE_KEY_PKCS8

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
     * @throws Asn1StructuralException if an [at.asitplus.signum.indispensable.CryptoPrivateKey.EC.WithoutPublicKey] shall be encoded
     */

    @Throws(Asn1Exception::class)
    override fun encodeToTlv() = runRethrowing {
        Asn1.Sequence {
            +Asn1.Int(0)
            +Asn1.Sequence {
                when (this@CryptoPrivateKey) {
                    is RSA -> {
                        +RSA.oid
                        +Asn1.Null()
                    }

                    is EC.WithPublicKey -> {
                        +EC.oid
                        +curve.oid
                    }

                    is EC.WithoutPublicKey -> throw Asn1StructuralException("Cannot PKCS#8-encode an EC key without curve. Re-create it and specify a curve!")
                }
            }
            +Asn1.OctetStringEncapsulating {
                when (this@CryptoPrivateKey) {
                    is RSA -> +asPKCS1.encodeToTlv()
                    is EC -> +asSEC1.encodeToTlv()
                }
            }
            attributes?.let {
                +(Asn1.SetOf {
                    it.forEach { attr -> +attr }
                } withImplicitTag 0uL)
            }
        }
    }

    /**
     * PKCS#1 RSA Private key representation as per [RFC 8017](https://datatracker.ietf.org/doc/html/rfc8017/#appendix-A.1.2) augmented with optional [attributes].
     * Attributes are never SEC-1 encoded, but are relevant when PKCS#8-encoding a private key.
     *
     */
    class RSA
    /** @throws IllegalArgumentException in case invalid parameters are provided*/
    @Throws(IllegalArgumentException::class)
    constructor(
        /**
         * The [CryptoPublicKey.RSA] matching this private key
         */
        override val publicKey: CryptoPublicKey.RSA,
        val d: BigInteger,
        val p: BigInteger,
        val q: BigInteger,
        val dp: BigInteger,
        val dq: BigInteger,
        val qi: BigInteger,
        val otherPrimeInfos: List<OtherPrimeInfo>?,
        attributes: List<Asn1Element>? = null
    ) : CryptoPrivateKey(attributes), WithPublicKey<CryptoPublicKey.RSA> {

        override val oid = RSA.oid

        override fun equals(other: Any?): Boolean {
            if (other !is RSA) return false
            return publicKey.equalsCryptographically(other.publicKey)
        }

        override fun hashCode() = publicKey.hashCode()

        init {
            val one = BigInteger.ONE
            val n = publicKey.n.toBigInteger()
            val e = publicKey.e.toBigInteger()
            require(n == p * q) { "n == p * q" }
            require(dp == (d mod (p - one))) { "dp == (d mod (p - one))" }
            require(dq == (d mod (q - one))) { "dq == (d mod (q - one))" }
            require(qi == q.modInverse(p)) { "qi == q.modInverse(p)" }
            //Carmichael Totient!, not Euler Totient as per PKCS #1!
            require(one == (d.multiply(e).mod((p - 1).lcm(q - 1))))
        }

        private fun BigInteger.lcm(other: BigInteger): BigInteger {
            val mul = this * other
            val gcd = this.gcd(other)
            return mul / gcd
        }

        /** Encodes this private key into a PKCS#1-encoded private key */
        val asPKCS1 = object : PemEncodable<Asn1Sequence> {
            override val canonicalPEMBoundary get() = EB_STRINGS.RSA_PRIVATE_KEY_PKCS1

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
                Asn1.Sequence {
                    if (otherPrimeInfos != null) +Asn1.Int(1) else +Asn1.Int(0)
                    +publicKey.n
                    +publicKey.e
                    +Asn1.Int(d)
                    +Asn1.Int(p)
                    +Asn1.Int(q)
                    +Asn1.Int(dp)
                    +Asn1.Int(dq)
                    +Asn1.Int(qi)
                    otherPrimeInfos?.let {
                        +Asn1.Sequence {
                            it.forEach { info -> +info }
                        }
                    }
                }
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
        class OtherPrimeInfo(
            val prime: Asn1Integer,
            val exponent: Asn1Integer,
            val coefficient: Asn1Integer,
        ) : Asn1Encodable<Asn1Sequence> {

            @Throws(Asn1Exception::class)
            override fun encodeToTlv() = runRethrowing {
                Asn1.Sequence {
                    +prime
                    +exponent
                    +coefficient
                }
            }

            companion object : Asn1Decodable<Asn1Sequence, OtherPrimeInfo> {

                @Throws(Asn1Exception::class)
                override fun doDecode(src: Asn1Sequence): OtherPrimeInfo = runRethrowing {
                    val prime = src.nextChild().asPrimitive().decodeToAsn1Integer()
                    val exponent = src.nextChild().asPrimitive().decodeToAsn1Integer()
                    val coefficient = src.nextChild().asPrimitive().decodeToAsn1Integer()
                    require(src.hasMoreChildren() == false) { "Superfluous Data in OtherPrimeInfos" }
                    OtherPrimeInfo(prime, exponent, coefficient)
                }

            }
        }

        companion object : PemDecodable<Asn1Sequence, RSA>(
            EB_STRINGS.GENERIC_PRIVATE_KEY_PKCS8 to checkedAsFn(CryptoPrivateKey.Companion::decodeFromDer),
            EB_STRINGS.RSA_PRIVATE_KEY_PKCS1 to checkedAsFn(RSA.FromPKCS1::decodeFromDer)
        ) {
            override fun doDecode(src: Asn1Sequence): RSA =
                checkedAs(CryptoPrivateKey.doDecode(src))

            val oid: ObjectIdentifier = KnownOIDs.rsaEncryption
        }

        object FromPKCS1 : Asn1Decodable<Asn1Sequence, RSA> {
            @Throws(Asn1Exception::class)
            override fun doDecode(src: Asn1Sequence): RSA = doDecode(src, null)

            /**
             * PKCS1 decoding of an ASN.1 private key, optionally supporting attributes for later PKCS#8 encoding
             */
            @Throws(Asn1Exception::class)
            fun doDecode(src: Asn1Sequence, attributes: List<Asn1Element>? = null): RSA = runRethrowing {
                val version = src.nextChild().asPrimitive().decodeToInt()
                require(version == 0 || version == 1) { "RSA Private key VERSION must be 0 or 1" }
                val modulus = src.nextChild().asPrimitive().decodeToAsn1Integer()
                val publicExponent = src.nextChild().asPrimitive().decodeToAsn1Integer()
                val privateExponent = src.nextChild().asPrimitive().decodeToBigInteger()
                val prime1 = src.nextChild().asPrimitive().decodeToBigInteger()
                val prime2 = src.nextChild().asPrimitive().decodeToBigInteger()
                val exponent1 = src.nextChild().asPrimitive().decodeToBigInteger()
                val exponent2 = src.nextChild().asPrimitive().decodeToBigInteger()
                val coefficient = src.nextChild().asPrimitive().decodeToBigInteger()

                val otherPrimeInfos: List<OtherPrimeInfo>? = if (src.hasMoreChildren()) {
                    require(version == 1) { "OtherPrimeInfos is present. RSA private key version must be 1" }
                    src.nextChild().asSequence().children.map { OtherPrimeInfo.decodeFromTlv(it.asSequence()) }
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
     * Attributes are never SEC-1 encoded, but are relevant when PKCS#8-encoding a private key.
     */
    sealed class EC(
        val privateKey: BigInteger,
        attributes: List<Asn1Element>? = null
    ) : CryptoPrivateKey(attributes) {

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
                    if (this@EC is EC.WithPublicKey) {
                        if (encodeCurve) +Asn1.ExplicitlyTagged(0uL) { +curve.oid }
                        if (encodePublicKey) +Asn1.ExplicitlyTagged(1uL) { +Asn1.BitString(publicKey.iosEncoded) }
                    }
                }
            }
        }

        class WithPublicKey
        /** @throws IllegalArgumentException in case invalid parameters are provided*/
        @Throws(IllegalArgumentException::class)
        private constructor(
            curve: ECCurve?,
            val encodeCurve: Boolean,
            privateKey: BigInteger,
            publicKey: CryptoPublicKey.EC?,
            val encodePublicKey: Boolean,
            attributes: List<Asn1Element>? = null
        ) : EC(privateKey, attributes), CryptoPrivateKey.WithPublicKey<CryptoPublicKey.EC> {

            /** @throws IllegalArgumentException in case invalid parameters are provided*/
            @Throws(IllegalArgumentException::class)
            constructor(
                privateKey: BigInteger,
                encodeCurve: Boolean,
                publicKey: CryptoPublicKey.EC,
                encodePublicKey: Boolean,
                attributes: List<Asn1Element>? = null
            ) : this(null, encodeCurve, privateKey, publicKey, encodePublicKey, attributes)

            /** @throws IllegalArgumentException in case invalid parameters are provided*/
            @Throws(IllegalArgumentException::class)
            constructor(
                privateKey: BigInteger,
                encodeCurve: Boolean,
                curve: ECCurve,
                encodePublicKey: Boolean,
                attributes: List<Asn1Element>? = null
            ) : this(curve, encodeCurve, privateKey, null, encodePublicKey, attributes)


            init {
                require(publicKey != null || curve != null) { "PublicKey or curve must be set" }
                if (publicKey != null && curve != null) require(publicKey.curve == curve) { "Curve and public key must match!" }
                publicKey?.let { pub ->
                    require(
                        privateKey.times(pub.curve.generator).asPublicKey() == pub
                    ) { "Public key must match the private key!" }
                }
            }

            /** [CryptoPublicKey.EC] matching this private key. */
            override val publicKey: CryptoPublicKey.EC = publicKey ?: curve?.let { crv ->
                privateKey.times(crv.generator).asPublicKey(preferCompressed = true)
            }!!
            val curve get() = publicKey.curve

            override fun toString(): String {
                return "EC private key for public key $publicKey"
            }

            override val privateKeyBytes: ByteArray
                get() = privateKey.toByteArray().ensureSize(curve.scalarLength.bytes)
        }

        class WithoutPublicKey constructor(
            privateKey: BigInteger,
            attributes: List<Asn1Element>? = null,
            private val curveOrderLengthInBytes: Int
        ) : EC(privateKey, attributes) {

            /**
             * Creates a new [CryptoPrivateKey.EC.WithPublicKey] based on the passed curve.
             *
             */
            fun withCurve(curve: ECCurve, encodeCurve: Boolean = true, encodePublicKey: Boolean = true) =
                CryptoPrivateKey.EC.WithPublicKey(
                    privateKey,
                    encodeCurve,
                    curve.also { require(it.scalarLength.bytes.toInt() == curveOrderLengthInBytes) },
                    encodePublicKey,
                    attributes
                )

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
            EB_STRINGS.GENERIC_PRIVATE_KEY_PKCS8 to checkedAsFn(CryptoPrivateKey.Companion::decodeFromDer),
            EB_STRINGS.EC_PRIVATE_KEY_SEC1 to checkedAsFn(EC.FromSEC1::decodeFromDer)
        ) {
            val oid: ObjectIdentifier = KnownOIDs.ecPublicKey

            @Throws(Asn1Exception::class)
            override fun doDecode(src: Asn1Sequence): EC =
                checkedAs(CryptoPublicKey.doDecode(src))

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
                predefinedCurve: ECCurve? = null,
                attributes: List<Asn1Element>? = null
            ): EC = runRethrowing {
                val version = src.nextChild().asPrimitive().decodeToInt()
                require(version == 1) { "EC public key version must be 1" }
                val privateKeyOctets = src.nextChild().asOctetString().content

                //Params and publicKey are both optional, but may only occur once. so we need to run `decode` potentially twice and record state
                //DataAndKey class enables this without code duplication
                val additionalData = DataAndKey()
                //try once
                if (src.hasMoreChildren()) {
                    additionalData.decode(src.nextChild(), predefinedCurve)
                }
                //try twice
                if (src.hasMoreChildren()) {
                    additionalData.decode(src.nextChild(), predefinedCurve)
                }


                val crv = additionalData.publicKey?.curve
                if (crv == null)
                    EC.WithoutPublicKey(
                        BigInteger.fromByteArray(privateKeyOctets, Sign.POSITIVE),
                        attributes,
                        privateKeyOctets.size
                    )
                else {
                    additionalData.publicKey?.let { require(crv == it.curve) }

                    if (additionalData.publicKey != null)
                        EC.WithPublicKey(
                            BigInteger.fromByteArray(privateKeyOctets, Sign.POSITIVE),
                            additionalData.encodeCurve,
                            additionalData.publicKey!!,
                            encodePublicKey = true,
                            attributes
                        )
                    else
                        EC.WithPublicKey(
                            BigInteger.fromByteArray(privateKeyOctets, Sign.POSITIVE),
                            additionalData.encodeCurve,
                            crv,
                            encodePublicKey = false,
                            attributes
                        )
                }
            }

            private fun Asn1ExplicitlyTagged.decodeECParams(): ObjectIdentifier {
                require(children.size == 1) { "Only a single EC parameter is allowed" }
                return ObjectIdentifier.decodeFromTlv(nextChild().asPrimitive())
            }

            //Params and publicKey are both optional, but may only occur once. so we need to run `decode` potentially twice and record state
            //DataAndKey class enables this without code duplication
            private class DataAndKey(
                var params: ObjectIdentifier? = null,
                var publicKey: CryptoPublicKey.EC? = null,
                var encodeCurve: Boolean = false
            ) {
                fun decode(src: Asn1Element, outerCurve: ECCurve?) {
                    val tagged = src.asExplicitlyTagged()
                    when (tagged.tag.tagValue) {
                        0uL -> tagged.decodeECParams().also {
                            require(params == null) { "EC parameters may only occur once" }
                            params = it
                        }

                        1uL -> {
                            require(publicKey == null) { "EC public key may only occur once" }
                            val crv =
                                params?.let { params -> ECCurve.entries.first { it.oid == params } }
                            encodeCurve = (crv != null)
                            val asAsn1BitString = tagged.nextChild().asPrimitive().asAsn1BitString()
                            if (crv != null && outerCurve != null) require(crv == outerCurve) { "PKCS#8 and SEC1 curve mismatch!" }

                            val actualCurve = crv ?: outerCurve
                            publicKey =
                                if (actualCurve != null)
                                    CryptoPublicKey.EC.fromAnsiX963Bytes(actualCurve, asAsn1BitString.rawBytes)
                                else null
                        }
                    }
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
        override fun doDecode(src: Asn1Sequence): CryptoPrivateKey = runRethrowing {
            //PKCS8 here
            require(src.nextChild().asPrimitive().decodeToInt() == 0) { "PKCS#8 Private Key VERSION must be 0" }
            val algorithmID = src.nextChild().asSequence()
            val algIdentifier = ObjectIdentifier.decodeFromTlv(algorithmID.nextChild().asPrimitive())
            val algParams = algorithmID.nextChild().asPrimitive()
            require(algorithmID.hasMoreChildren() == false) { "Superfluous Algorithm ID data encountered" }
            val privateKeyStructure = src.nextChild().asEncapsulatingOctetString().let {
                val seq = it.nextChild().asSequence()
                require(it.hasMoreChildren() == false) { "Superfluous private key data encountered" }
                seq
            }
            val attributes: List<Asn1Element>? =
                if (src.hasMoreChildren()) src.nextChild().asStructure().assertTag(0uL).children
                else null
            return if (algIdentifier == RSA.oid) {
                algParams.readNull()
                RSA.FromPKCS1.doDecode(privateKeyStructure, attributes)
            } else if (algIdentifier == EC.oid) {
                val predefinedCurve = ECCurve.entries.first { it.oid == ObjectIdentifier.decodeFromTlv(algParams) }
                EC.FromSEC1.doDecode(privateKeyStructure, predefinedCurve, attributes).let {
                    when (it) {
                        is EC.WithPublicKey -> it.also { require(it.curve == predefinedCurve) }
                        //@iaik-jheher how can this work, if we set encodeCurve= true? somehting seems off!
                        is EC.WithoutPublicKey -> it.withCurve(predefinedCurve)
                    }
                }
            } else throw IllegalArgumentException("Unknown Algorithm: $algIdentifier")
        }
    }
}

/**
 * Representation of an encrypted private key structure as per [RFC 5208](https://datatracker.ietf.org/doc/html/rfc5208)
 * As of November 2024, We do not ship decryption functionality
 */
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

    companion object : PemDecodable<Asn1Sequence, EncryptedPrivateKey>(
        EB_STRINGS.ENCRYPTED_PRIVATE_KEY to checkedAsFn(Companion::decodeFromDer)
    ) {

        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Sequence): EncryptedPrivateKey = runRethrowing {
            EncryptedPrivateKey(
                ObjectIdentifier.decodeFromTlv(src.nextChild().asPrimitive()),
                src.nextChild().asPrimitive().asOctetString().content
            ).also {
                require(!src.hasMoreChildren()) { "Superfluous data in EncryptedPrivateKey encountered" }
            }
        }
    }

    /**
     * Convenience wrapper to decrypt this private key.
     * Actual decryption must happen in [decryptFn], which gets passed [encryptionAlgorithm] an [encryptedData].
     * [decryptFn] may throw anything, as it is executed inside a [catching] block.
     */
    fun decrypt(decryptFn: (ObjectIdentifier, ByteArray) -> ByteArray): KmmResult<CryptoPrivateKey> = catching {
        CryptoPrivateKey.decodeFromDer(decryptFn(encryptionAlgorithm, encryptedData))
    }
}
