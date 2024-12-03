package at.asitplus.signum.indispensable

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.ecmath.times
import at.asitplus.signum.indispensable.CryptoPublicKey.EC.Companion.asPublicKey
import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.encoding.*
import at.asitplus.signum.indispensable.misc.ANSIECPrefix

/**
 * PKCS#8 Representation of a private key structure as per [RFC 5208](https://datatracker.ietf.org/doc/html/rfc5208)
 */
sealed interface CryptoPrivateKey<T : CryptoPublicKey>
    : PemEncodable<Asn1Sequence>, Identifiable {

    /**
     * optional attributes relevant when PKCS#8-encoding a private key
     */
    val attributes: List<Asn1Element>?

    sealed interface WithPublicKey<T : CryptoPublicKey> : PemEncodable<Asn1Sequence>, Identifiable {
        /**
         * [CryptoPublicKey] matching this private key. Never null for RSA.
         * Maybe `null` for EC, if the curve is not specified (e.g. when decoding from SEC1 decoding and neither curve nor key are present)
         */
        abstract val publicKey: T

        companion object : PemDecodable<Asn1Sequence, CryptoPrivateKey<*>> {
            override val ebString = CryptoPrivateKey.ebString

            override fun doDecode(src: Asn1Sequence): CryptoPrivateKey<*> = CryptoPrivateKey.doDecode(src)
        }
    }

    override val ebString: String
        get() = CryptoPrivateKey.ebString

    /**
     * PKCS#1 RSA Private key representation as per [RFC 8017](https://datatracker.ietf.org/doc/html/rfc8017/#appendix-A.1.2) augmented with optional [attributes].
     * Attributes are never SEC-1 encoded, but are relevant when PKCS#8-encoding a private key.
     */
    class RSA(
        /**
         * The [CryptoPublicKey.RSA] matching this private key
         */
        override val publicKey: CryptoPublicKey.RSA,
        val privateExponent: Asn1Integer,
        val prime1: Asn1Integer,
        val prime2: Asn1Integer,
        val exponent1: Asn1Integer,
        val exponent2: Asn1Integer,
        val coefficient: Asn1Integer,
        val otherPrimeInfos: List<OtherPrimeInfo>?,
        override val attributes: List<Asn1Element>? = null
    ) : CryptoPrivateKey<CryptoPublicKey.RSA>, WithPublicKey<CryptoPublicKey.RSA> {

        override val oid = RSA.oid

        private inner class PlainPemEncodable : PemEncodable<Asn1Sequence> {
            override val ebString = RSA.ebString
            override fun encodeToTlv() = this@RSA.pkcs1Encode()
        }

        private val innerPemEncodable = PlainPemEncodable()

        /**
         * Encodes this private key into a PKCS#1 PEM-encoded private key
         */
        fun encodeToPkcs1PEM() = innerPemEncodable.encodeToPEM()

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

        @Throws(Asn1Exception::class)
        fun pkcs1Encode() = runRethrowing {
            Asn1.Sequence {
                if (otherPrimeInfos != null) +Asn1.Int(1) else +Asn1.Int(0)
                +publicKey.n
                +publicKey.e
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
        }

        companion object : PemDecodable<Asn1Sequence, RSA> {

            val oid: ObjectIdentifier = KnownOIDs.rsaEncryption
            override val ebString = "RSA PRIVATE KEY"

            @Throws(Asn1Exception::class)
            override fun doDecode(src: Asn1Sequence): RSA = pkcs1Decode(src, null)

            @Throws(Asn1Exception::class)
            fun plainDecode(src: Asn1Sequence) = pkcs1Decode(src, null)

            /**
             * PKCS1 decoding of an ASN.1 private key, optionally supporting attributes for later PKCS#8 encoding
             */
            @Throws(Asn1Exception::class)
            fun pkcs1Decode(src: Asn1Sequence, attributes: List<Asn1Element>? = null): RSA = runRethrowing {
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
        val privateKeyBytes: ByteArray,
        override val attributes: List<Asn1Element>? = null
    ) : CryptoPrivateKey<CryptoPublicKey.EC> {


        override val oid = EC.oid

        internal val intRepresentation = Asn1Integer.decodeFromAsn1ContentBytes(privateKeyBytes)

        private inner class PlainPemEncodable : PemEncodable<Asn1Sequence> {
            override val ebString = EC.ebString
            override fun encodeToTlv() = this@EC.sec1Encode()
        }

        private val innerPemEncodable = PlainPemEncodable()

        /**
         * Encodes this private key into a SEC1 PEM-encoded private key
         */
        fun pemEncodeSec1() = innerPemEncodable.encodeToPEM()

        class WithPublicKey private constructor(
            curve: ECCurve?,
            val encodeCurve: Boolean,
            privateKeyBytes: ByteArray,
            publicKey: CryptoPublicKey.EC?,
            val encodePublicKey: Boolean,
            attributes: List<Asn1Element>? = null
        ) : EC(privateKeyBytes, attributes), CryptoPrivateKey.WithPublicKey<CryptoPublicKey.EC> {

            constructor(
                privateKeyBytes: ByteArray,
                encodeCurve: Boolean,
                publicKey: CryptoPublicKey.EC,
                encodePublicKey: Boolean,
                attributes: List<Asn1Element>? = null
            ) : this(null, encodeCurve, privateKeyBytes, publicKey, encodePublicKey, attributes)

            constructor(
                privateKeyBytes: ByteArray,
                encodeCurve: Boolean,
                curve: ECCurve,
                encodePublicKey: Boolean,
                attributes: List<Asn1Element>? = null
            ) : this(curve, encodeCurve, privateKeyBytes, null, encodePublicKey, attributes)


            init {
                require(publicKey != null || curve != null) { "PublicKey or curve must be set" }
                if (publicKey != null && curve != null) require(publicKey.curve == curve) { "Curve and public key must match!" }
            }

            /**
             * [CryptoPublicKey.EC] matching this private key. May be null if this private key was parsed from SEC1 without
             * any curve or public key infos
             */
            override val publicKey: CryptoPublicKey.EC = publicKey ?: curve?.let { crv ->
                intRepresentation.toBigInteger().times(crv.generator).asPublicKey(preferCompressed = true)
            }!!


            val curve = curve ?: this.publicKey.curve

            override fun toString(): String {
                return "EC private key for public key $publicKey"
            }
        }

        class WithoutPublicKey constructor(
            privateKeyBytes: ByteArray,
            attributes: List<Asn1Element>? = null
        ) : EC(privateKeyBytes, attributes) {

            /**
             * Creates a new [CryptoPrivateKey.EC.WithPublicKey] based on the passed curve.
             *
             */
            fun withCurve(curve: ECCurve, encodeCurve: Boolean = true, encodePublicKey: Boolean = true) =
                CryptoPrivateKey.EC.WithPublicKey(
                    privateKeyBytes,
                    encodeCurve,
                    curve,
                    encodePublicKey,
                    attributes
                )
        }


        companion object : PemDecodable<Asn1Sequence, EC> {

            override val ebString = "EC PRIVATE KEY"
            val oid: ObjectIdentifier = KnownOIDs.ecPublicKey

            @Throws(Asn1Exception::class)
            override fun doDecode(src: Asn1Sequence): EC = sec1decode(src, attributes = null)

            internal fun iosDecodeInternal(keyBytes: ByteArray): CryptoPrivateKey.EC.WithPublicKey {
                val crv = ECCurve.fromIosEncodedPrivateKeyLength(keyBytes.size)
                    ?: throw IllegalArgumentException("Unknown curve in iOS raw key")
                return EC.WithPublicKey(
                    keyBytes.sliceArray(crv.iosEncodedPublicKeyLength..<keyBytes.size),
                    encodeCurve = false,
                    encodePublicKey = true,
                    publicKey = CryptoPublicKey.fromIosEncoded(keyBytes.sliceArray(0..<crv.iosEncodedPublicKeyLength)) as CryptoPublicKey.EC
                )
            }

            /**
             * SEC1 V2 decoding optionally supporting attributes for later PKCS#8 encoding
             */
            @Throws(Asn1Exception::class)
            fun sec1decode(
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


                val crv = additionalData.publicKey?.curve ?: predefinedCurve
                if (crv == null && additionalData.publicKey == null)
                    EC.WithoutPublicKey(
                        privateKeyBytes = privateKeyOctets,
                        attributes
                    )
                else {
                    if (crv != null && additionalData.publicKey != null) require(crv == additionalData.publicKey!!.curve)
                    if (additionalData.publicKey != null)
                        EC.WithPublicKey(
                            privateKeyOctets,
                            additionalData.encodeCurve,
                            additionalData.publicKey!!,
                            encodePublicKey = true,
                            attributes
                        )
                    else
                        EC.WithPublicKey(
                            privateKeyOctets,
                            additionalData.encodeCurve,
                            crv!!,
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
                fun decode(src: Asn1Element, predefinedCurve: ECCurve?) {
                    val tagged = src.asExplicitlyTagged()
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
                            parsedCurve?.let { encodeCurve = true }
                            val crv = parsedCurve ?: predefinedCurve
                            val asAsn1BitString = tagged.nextChild().asPrimitive().asAsn1BitString()
                            publicKey = if (crv != null)
                                CryptoPublicKey.EC.fromAnsiX963Bytes(crv, asAsn1BitString.rawBytes)
                            else CryptoPublicKey.fromIosEncoded(asAsn1BitString.rawBytes) as CryptoPublicKey.EC
                        }
                    }
                }
            }
        }

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

        @Throws(Asn1Exception::class)
        fun sec1Encode() = runRethrowing {
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
                    is RSA -> +pkcs1Encode()
                    is EC -> +sec1Encode()
                }
            }
            attributes?.let {
                +(Asn1.SetOf {
                    it.forEach { attr -> +attr }
                } withImplicitTag 0uL)
            }
        }
    }

    companion object : PemDecodable<Asn1Sequence, CryptoPrivateKey<*>> {

        /**
         * Inspects the EB string and:
         * * PKCS#8-decodes in [CryptoPrivateKey.ebString] is encountered
         * * PKCS#1-decodes in [RSA.ebString] is encountered
         * * SEC1-decodes in [EC.ebString] is encountered
         * * throws otherwise
         *
         */
        @Throws(Throwable::class)
        override fun binaryDecodePayload(ebString: String, src: ByteArray): CryptoPrivateKey<*> =
            when (ebString) {
                CryptoPrivateKey.ebString -> super.binaryDecodePayload(ebString, src)
                EC.ebString -> EC.binaryDecodePayload(ebString, src)
                RSA.ebString -> RSA.binaryDecodePayload(ebString, src)
                else -> throw IllegalArgumentException("Unrecognized EB string: $ebString")
            }

        override val ebString = "PRIVATE KEY"

        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Sequence): CryptoPrivateKey<*> = runRethrowing {
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

        /**
         * Tries to decode a private key as exported from iOS.
         * EC keys are exported [as padded raw bytes](https://developer.apple.com/documentation/security/seckeycopyexternalrepresentation(_:_:)?language=objc).
         * RSA keys are exported using PKCS#1 encoding
         */
        fun fromIosEncoded(keyBytes: ByteArray): KmmResult<CryptoPrivateKey.WithPublicKey<*>> = catching {
            if (keyBytes.first() == ANSIECPrefix.UNCOMPRESSED.prefixByte) CryptoPrivateKey.EC.iosDecodeInternal((keyBytes))
            else CryptoPrivateKey.RSA.pkcs1Decode(Asn1Element.parse(keyBytes).asSequence())

        }

    }
}

/**
 * Representation of an encrypted private key structure as per [RFC 5208](https://datatracker.ietf.org/doc/html/rfc5208)
 * As of November 2024, We do not ship decryption functionality
 */
class EncryptedPrivateKey(val encryptionAlgorithm: ObjectIdentifier, val encryptedData: ByteArray) :
    PemEncodable<Asn1Sequence> {

    override val ebString = EncryptedPrivateKey.ebString

    @Throws(Asn1Exception::class)
    override fun encodeToTlv(): Asn1Sequence = runRethrowing {
        Asn1.Sequence {
            +encryptionAlgorithm
            +Asn1.OctetString(encryptedData)
        }
    }

    companion object : PemDecodable<Asn1Sequence, EncryptedPrivateKey> {
        override val ebString: String = "ENCRYPTED PRIVATE KEY"

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
    fun decrypt(decryptFn: (ObjectIdentifier, ByteArray) -> ByteArray): KmmResult<CryptoPrivateKey<*>> = catching {
        CryptoPrivateKey.decodeFromDer(decryptFn(encryptionAlgorithm, encryptedData))
    }
}
