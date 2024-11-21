package at.asitplus.signum.indispensable

import at.asitplus.signum.ecmath.times
import at.asitplus.signum.indispensable.CryptoPublicKey.EC.Companion.asPublicKey
import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.encoding.*

/**
 * PKCS#8 Representation of a private key structure as per [RFC 5208](https://datatracker.ietf.org/doc/html/rfc5208)
 */
sealed class CryptoPrivateKey<T : CryptoPublicKey>(
    /**
     * optional attributes relevant when PKCS#8-encoding a private key
     */
    val attributes: List<Asn1Element>?
) : PemEncodable<Asn1Sequence>, Identifiable {

    /**
     * [CryptoPublicKey] matching this private key. Never null for RSA.
     * Maybe `null` for EC, if the curve is not specified (e.g. when decoding from SEC1 decoding and neither curve nor key are present)
     */
    abstract val publicKey: T?

    override val ebString = CryptoPrivateKey.ebString

    /**
     * Encodes the plain key, i.e. PKCS#1 for RSA and SEC1 for EC
     */
    abstract fun plainEncode(): Asn1Sequence

    /**
     * PKCS#1 RSA Private key representation as per [RFC 8017](https://datatracker.ietf.org/doc/html/rfc8017/#appendix-A.1.2) augmented with optional [attributes].
     * Attributes are never SEC-1 encoded, but are relevant when PKCS#8-encoding a private key.
     */
    class RSA(
        val modulus: Asn1Integer,
        val publicExponent: Asn1Integer,
        val privateExponent: Asn1Integer,
        val prime1: Asn1Integer,
        val prime2: Asn1Integer,
        val exponent1: Asn1Integer,
        val exponent2: Asn1Integer,
        val coefficient: Asn1Integer,
        val otherPrimeInfos: List<OtherPrimeInfo>?,
        attributes: List<Asn1Element>? = null
    ) : CryptoPrivateKey<CryptoPublicKey.RSA>(attributes) {

        override val oid = RSA.oid

        /**
         * The [CryptoPublicKey.RSA] matching this private key
         */
        override val publicKey = CryptoPublicKey.RSA(modulus, publicExponent)

        private inner class PlainPemEncodable : PemEncodable<Asn1Sequence> {
            override val ebString = RSA.ebString
            override fun encodeToTlv() = this@RSA.pkcs1Encode()
        }

        private val innerPemEncodable = PlainPemEncodable()

        /**
         * Encodes this private key into a PKCS#1 PEM-encoded pricate key
         */
        fun pemEncodePkcs1() = innerPemEncodable.encodeToPEM()

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
            override fun encodeToTlv() = Asn1.Sequence {
                +prime
                +exponent
                +coefficient
            }

            companion object : Asn1Decodable<Asn1Sequence, OtherPrimeInfo> {
                override fun doDecode(src: Asn1Sequence): OtherPrimeInfo {
                    val prime = src.nextChild().asPrimitive().decodeToAsn1Integer()
                    val exponent = src.nextChild().asPrimitive().decodeToAsn1Integer()
                    val coefficient = src.nextChild().asPrimitive().decodeToAsn1Integer()
                    require(src.hasMoreChildren() == false) { "Superfluous Data in OtherPrimeInfos" }
                    return OtherPrimeInfo(prime, exponent, coefficient)
                }

            }
        }

        /**
         * @see pkcs1Encode
         */
        override fun plainEncode() = pkcs1Encode()

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
        fun pkcs1Encode() = Asn1.Sequence {
            if (otherPrimeInfos != null) +Asn1.Int(1)
            else +Asn1.Int(0)
            +modulus
            +publicExponent
            +privateExponent
            +prime1
            +prime2
            +exponent1
            +exponent2
            +coefficient
            otherPrimeInfos?.let {
                +Asn1.Sequence {
                    it.forEach { info -> +info }
                }
            }
        }

        companion object : PemDecodable<Asn1Sequence, RSA> {

            val oid: ObjectIdentifier = KnownOIDs.rsaEncryption
            override val ebString = "RSA PRIVATE KEY"

            override fun doDecode(src: Asn1Sequence): RSA = pkcs1Decode(src, null)

            fun plainDecode(src: Asn1Sequence) = pkcs1Decode(src, null)

            /**
             * PKCS1 decoding of an ASN.1 private key, optionally supporting attributes for later PKCS#8 encoding
             */
            fun pkcs1Decode(src: Asn1Sequence, attributes: List<Asn1Element>? = null): RSA {
                val version = src.nextChild().asPrimitive().decodeToInt()
                require(version == 0 || version == 1) { "RSA Private key VERSION must be 0 or 1" }
                val modulus = src.nextChild().asPrimitive().decodeToAsn1Integer()
                val publicExponent = src.nextChild().asPrimitive().decodeToAsn1Integer()
                val privateExponent = src.nextChild().asPrimitive().decodeToAsn1Integer()
                val prime1 = src.nextChild().asPrimitive().decodeToAsn1Integer()
                val prime2 = src.nextChild().asPrimitive().decodeToAsn1Integer()
                val exponent1 = src.nextChild().asPrimitive().decodeToAsn1Integer()
                val exponent2 = src.nextChild().asPrimitive().decodeToAsn1Integer()
                val coefficient = src.nextChild().asPrimitive().decodeToAsn1Integer()

                val otherPrimeInfos: List<OtherPrimeInfo>? = if (src.hasMoreChildren()) {
                    require(version == 1) { "OtherPrimeInfos is present. RSA private key version must be 1" }
                    src.nextChild().asSequence().children.map { OtherPrimeInfo.decodeFromTlv(it.asSequence()) }
                } else {
                    require(version == 0) { "OtherPrimeInfos is present. RSA private key version must be 0" }
                    null
                }
                return RSA(
                    modulus,
                    publicExponent,
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
    class EC(
        val curve: ECCurve?,
        val privateKeyBytes: ByteArray,
        val encodeCurve: Boolean,
        publicKey: CryptoPublicKey.EC?,
        attributes: List<Asn1Element>? = null
    ) :
        CryptoPrivateKey<CryptoPublicKey.EC>(attributes) {

        override val oid = EC.oid

        private val intRepresentation = Asn1Integer.decodeFromAsn1ContentBytes(privateKeyBytes)

        private inner class PlainPemEncodable : PemEncodable<Asn1Sequence> {
            override val ebString = EC.ebString
            override fun encodeToTlv() = this@EC.sec1Encode()
        }

        private val innerPemEncodable = PlainPemEncodable()

        /**
         * Encodes this private key into a SEC1 PEM-encoded pricate key
         */
        fun pemEncodeSec1() = innerPemEncodable.encodeToPEM()

        /**
         * [CryptoPublicKey.EC] matching this private key. May be null if this private key was parsed from SEC1 without
         * any curve or public key infos
         */
        override val publicKey: CryptoPublicKey.EC? = publicKey ?: curve?.let { crv ->
            intRepresentation.toBigInteger().times(crv.generator).asPublicKey(preferCompressed = true)
        }


        override fun toString() = "EC private key${
            publicKey?.let {
                " for public key $it"
            } ?: curve?.let { " for curve $it" } ?: " ${privateKeyBytes.size * 8} bit"
        }"

        companion object : PemDecodable<Asn1Sequence, EC> {

            override val ebString = "EC PRIVATE KEY"
            val oid: ObjectIdentifier = KnownOIDs.ecPublicKey

            override fun doDecode(src: Asn1Sequence): EC = sec1decode(src, attributes = null)

            /**
             * SEC1 V2 decoding optionally supporting attributes for later PKCS#8 encoding
             */
            fun sec1decode(
                src: Asn1Sequence,
                predefinedCurve: ECCurve? = null,
                attributes: List<Asn1Element>? = null
            ): EC {

                fun Asn1ExplicitlyTagged.decodeECParams(): ObjectIdentifier {
                    require(children.size == 1) { "Only a single EC parameter is allowed" }
                    return ObjectIdentifier.decodeFromTlv(nextChild().asPrimitive())
                }

                val version = src.nextChild().asPrimitive().decodeToInt()
                require(version == 1) { "EC public key version must be 1" }
                val privateKeyOctets = src.nextChild().asPrimitiveOctetString().content
                var params: ObjectIdentifier? = null
                var publicKey: CryptoPublicKey.EC? = null

                var encodeCurve = false
                //TODO remove duplicated code
                if (src.hasMoreChildren()) {
                    val tagged = src.nextChild().asExplicitlyTagged()
                    when (tagged.tag.tagValue) {
                        0uL -> tagged.decodeECParams().also {
                            require(params == null) { "EC parameters may only occur once" }
                            params = it
                        }

                        1uL -> {
                            require(publicKey == null) { "EC public key may only occur once" }
                            val parsedCurve =
                                params?.let { params -> ECCurve.entries.first { it.oid == params } }
                            predefinedCurve?.let { pre ->
                                parsedCurve?.let { inner ->
                                    require(inner == pre) { "EC Curve OID mismatch" }
                                }
                            }
                            val crv = parsedCurve ?: predefinedCurve
                            val asAsn1BitString = tagged.nextChild().asPrimitive().asAsn1BitString()
                            publicKey = if (crv != null)
                                CryptoPublicKey.EC.fromAnsiX963Bytes(crv, asAsn1BitString.rawBytes)
                            else CryptoPublicKey.fromIosEncoded(asAsn1BitString.rawBytes) as CryptoPublicKey.EC
                        }
                    }
                }

                if (src.hasMoreChildren()) {
                    val tagged = src.nextChild().asExplicitlyTagged()
                    when (tagged.tag.tagValue) {
                        0uL -> tagged.decodeECParams().also {
                            require(params == null) { "EC parameters may only occur once" }
                            params = it
                        }

                        1uL -> {
                            require(publicKey == null) { "EC public key may only occur once" }
                            val parsedCurve =
                                params?.let { params -> ECCurve.entries.first { it.oid == params } }
                            predefinedCurve?.let { pre ->
                                parsedCurve?.let { inner ->
                                    require(inner == pre) { "EC Curve OID mismatch" }
                                }
                            }
                            parsedCurve.let { encodeCurve = true }
                            val crv = parsedCurve ?: predefinedCurve
                            val asAsn1BitString = tagged.nextChild().asPrimitive().asAsn1BitString()
                            publicKey = if (crv != null)
                                CryptoPublicKey.EC.fromAnsiX963Bytes(crv, asAsn1BitString.rawBytes)
                            else CryptoPublicKey.fromIosEncoded(asAsn1BitString.rawBytes) as CryptoPublicKey.EC
                        }
                    }
                }

                return EC(
                    curve = publicKey?.curve,
                    privateKeyBytes = privateKeyOctets,
                    encodeCurve = encodeCurve,
                    publicKey = publicKey,
                    attributes
                )
            }
        }

        /**
         * @see sec1Encode
         */
        override fun plainEncode() = sec1Encode()

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
        fun sec1Encode() = Asn1.Sequence {
            +Asn1.Int(1)
            +Asn1PrimitiveOctetString(privateKeyBytes)
            if (encodeCurve) curve?.let { +Asn1.ExplicitlyTagged(0uL) { +it.oid } }
            publicKey?.let { +Asn1.ExplicitlyTagged(1uL) { +Asn1.BitString(it.iosEncoded) } }
        }

    }


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
     */
    override fun encodeToTlv() = Asn1.Sequence {
        +Asn1.Int(0)
        +Asn1.Sequence {
            when (this@CryptoPrivateKey) {
                is RSA -> {
                    +RSA.oid
                    +Asn1.Null()
                }

                is EC -> {
                    +EC.oid
                    require(curve != null) { "Cannot PKCS#8-encode an EC key without curve. Re-create it and specify a curve!" }
                    +curve.oid
                }
            }
        }
        +Asn1.OctetStringEncapsulating {
            +plainEncode()
        }
        attributes?.let {
            +(Asn1.SetOf {
                it.forEach { attr -> +attr }
            } withImplicitTag 0uL)
        }
    }

    companion object : PemDecodable<Asn1Sequence, CryptoPrivateKey<*>> {
        override val ebString = "PRIVATE KEY"
        override fun doDecode(src: Asn1Sequence): CryptoPrivateKey<*> {
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
                RSA.pkcs1Decode(privateKeyStructure, attributes)
            } else if (algIdentifier == EC.oid) {
                val predefinedCurve = ECCurve.entries.first { it.oid == ObjectIdentifier.decodeFromTlv(algParams) }
                EC.sec1decode(privateKeyStructure, predefinedCurve, attributes)
            } else throw IllegalArgumentException("Unknown Algorithm: $algIdentifier")

        }

    }
}