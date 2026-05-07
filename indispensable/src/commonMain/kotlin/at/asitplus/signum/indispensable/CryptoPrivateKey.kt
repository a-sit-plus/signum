package at.asitplus.signum.indispensable

import at.asitplus.KmmResult
import at.asitplus.awesn1.Asn1BitString
import at.asitplus.awesn1.Asn1Decodable
import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Encodable
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.Asn1Primitive
import at.asitplus.awesn1.Asn1Sequence
import at.asitplus.awesn1.Asn1StructuralException
import at.asitplus.awesn1.Identifiable
import at.asitplus.awesn1.KnownOIDs
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.PemBlock
import at.asitplus.awesn1.decodeRethrowing
import at.asitplus.awesn1.ecPublicKey
import at.asitplus.awesn1.rsaEncryption
import at.asitplus.awesn1.crypto.Pkcs1RsaOtherPrimeInfo
import at.asitplus.awesn1.crypto.Pkcs1RsaPrivateKeyInfo
import at.asitplus.awesn1.crypto.Pkcs8PrivateKeyInfo
import at.asitplus.awesn1.crypto.Sec1EcPrivateKeyInfo
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.encoding.asAsn1BitString
import at.asitplus.awesn1.encoding.parse
import at.asitplus.awesn1.runRethrowing
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.Der
import at.asitplus.awesn1.toAsn1Integer
import at.asitplus.awesn1.toBigInteger
import at.asitplus.catching
import at.asitplus.signum.ecmath.times
import at.asitplus.signum.indispensable.CryptoPublicKey.EC.Companion.asPublicKey
import at.asitplus.signum.indispensable.misc.ANSIECPrefix
import at.asitplus.signum.internals.ensureSize
import at.asitplus.signum.internals.orLazy
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import kotlinx.serialization.KSerializer

data class RsaPrivateKeyContent(
    val publicKey: CryptoPublicKey.RSA,
    val privateKey: BigInteger,
    val prime1: BigInteger,
    val prime2: BigInteger,
    val prime1exponent: BigInteger,
    val prime2exponent: BigInteger,
    val crtCoefficient: BigInteger,
    val otherPrimeInfos: List<CryptoPrivateKey.RSA.PrimeInfo>?,
    val attributes: Set<Asn1Element>?,
) {
    init {
        val n = publicKey.n.toBigInteger()
        val e = publicKey.e.toBigInteger()
        val primeInfo1 = CryptoPrivateKey.RSA.PrimeInfo(prime = prime2, exponent = prime2exponent, coefficient = BigInteger.ONE)
        val primeInfo2 = CryptoPrivateKey.RSA.PrimeInfo(prime = prime1, exponent = prime1exponent, coefficient = crtCoefficient)

        var product = BigInteger.ONE
        (sequenceOf(primeInfo1, primeInfo2) + (otherPrimeInfos?.asSequence() ?: sequenceOf()))
            .forEachIndexed { i, info ->
                val pminusone = info.prime - BigInteger.ONE
                require(product.times(info.coefficient).mod(info.prime) == BigInteger.ONE) {
                    "t_$i != (r_0 * ... * r_${i - 1})^(-1) mod r_$i"
                }
                product *= info.prime
                require(info.exponent == privateKey.mod(pminusone)) { "d_$i != d mod (p_$i - 1)" }
                require(e.multiply(info.exponent).mod(pminusone) == BigInteger.ONE)
            }
        require(product == n) { "p1 * p2 * ... * pk != n" }
    }
}

data class RsaPkcs1Source(
    val pkcs1Representation: Pkcs1RsaPrivateKeyInfo,
    val attributes: Set<Asn1Element>?,
)

data class EcPrivateKeyContent(
    val privateKey: BigInteger,
    val publicKey: CryptoPublicKey.EC?,
    val publicKeyBytes: Asn1BitString?,
    val encodeCurve: Boolean,
    val encodePublicKey: Boolean,
    val curveOrderLengthInBytes: Int,
    val attributes: Set<Asn1Element>?,
)

data class EcSec1Source(
    val sec1Representation: Sec1EcPrivateKeyInfo,
    val curveFromPkcs8: ECCurve?,
    val attributes: Set<Asn1Element>?,
)

/**
 * PKCS#8 representation of a private key. Equality checks remain based on cryptographic Signum properties.
 */
sealed interface CryptoPrivateKey : DerPemEncodable<Pkcs8PrivateKeyInfo>, Identifiable {

    sealed interface WithPublicKey<T : CryptoPublicKey> : CryptoPrivateKey {
        val publicKey: T
    }

    val attributes: Set<Asn1Element>?

    val asPKCS8: DerPemEncodable<Pkcs8PrivateKeyInfo> get() = this

    override val pemLabel: String get() = Companion.canonicalPemLabel

    class RSA private constructor(
        private val providedContent: RsaPrivateKeyContent?,
        private val providedPkcs1Source: RsaPkcs1Source?,
        private val providedPkcs8Representation: Pkcs8PrivateKeyInfo?,
    ) : CryptoPrivateKey, WithPublicKey<CryptoPublicKey.RSA> {

        constructor(
            publicKey: CryptoPublicKey.RSA,
            privateKey: BigInteger,
            prime1: BigInteger,
            prime2: BigInteger,
            prime1exponent: BigInteger,
            prime2exponent: BigInteger,
            crtCoefficient: BigInteger,
            otherPrimeInfos: List<PrimeInfo>?,
            attributes: Set<Asn1Element>? = null,
        ) : this(
            RsaPrivateKeyContent(
                publicKey = publicKey,
                privateKey = privateKey,
                prime1 = prime1,
                prime2 = prime2,
                prime1exponent = prime1exponent,
                prime2exponent = prime2exponent,
                crtCoefficient = crtCoefficient,
                otherPrimeInfos = otherPrimeInfos,
                attributes = attributes,
            ),
            null,
            null,
        )

        internal constructor(asn1Representation: Pkcs8PrivateKeyInfo) : this(null, null, asn1Representation)

        internal constructor(
            pkcs1Representation: Pkcs1RsaPrivateKeyInfo,
            attributes: Set<Asn1Element>? = null,
        ) : this(null, RsaPkcs1Source(pkcs1Representation, attributes), null)

        override val oid: ObjectIdentifier get() = Companion.oid

        private val content: RsaPrivateKeyContent by providedContent orLazy {
            val source = providedPkcs1Source ?: RsaPkcs1Source(
                requireNotNull(providedPkcs8Representation).decodeRsaPrivateKey(),
                providedPkcs8Representation.attributes,
            )
            source.pkcs1Representation.toSignumContent(source.attributes)
        }

        override val attributes: Set<Asn1Element>? by lazy {
            providedContent?.attributes
                ?: providedPkcs8Representation?.attributes
                ?: providedPkcs1Source?.attributes
        }

        val pkcs1Representation: Pkcs1RsaPrivateKeyInfo by providedPkcs1Source?.pkcs1Representation orLazy {
            providedPkcs8Representation?.decodeRsaPrivateKey() ?: content.toPkcs1Representation()
        }

        override val asn1Representation: Pkcs8PrivateKeyInfo by providedPkcs8Representation orLazy {
            Pkcs8PrivateKeyInfo.rsa(pkcs1Representation, attributes)
        }

        val asPKCS1: DerPemEncodable<Pkcs1RsaPrivateKeyInfo> = object : DerPemEncodable<Pkcs1RsaPrivateKeyInfo> {
            override val pemLabel: String get() = RSA_PRIVATE_KEY_PEM_LABEL
            override val asn1Representation: Pkcs1RsaPrivateKeyInfo get() = pkcs1Representation
        }

        override val publicKey: CryptoPublicKey.RSA get() = content.publicKey
        val privateKey: BigInteger get() = content.privateKey
        val prime1: BigInteger get() = content.prime1
        val prime2: BigInteger get() = content.prime2
        val prime1exponent: BigInteger get() = content.prime1exponent
        val prime2exponent: BigInteger get() = content.prime2exponent
        val crtCoefficient: BigInteger get() = content.crtCoefficient
        val otherPrimeInfos: List<PrimeInfo>? get() = content.otherPrimeInfos

        override fun equals(other: Any?): Boolean {
            if (other !is RSA) return false
            return publicKey.equalsCryptographically(other.publicKey)
        }

        override fun hashCode() = publicKey.hashCode()

        override fun toString() = "RSA private key for public key $publicKey"

        data class PrimeInfo(
            val prime: BigInteger,
            val exponent: BigInteger,
            val coefficient: BigInteger,
        ) : DerEncodable<Pkcs1RsaOtherPrimeInfo> {
            override val asn1Representation: Pkcs1RsaOtherPrimeInfo
                get() = Pkcs1RsaOtherPrimeInfo(
                    prime = positive(prime),
                    exponent = positive(exponent),
                    coefficient = positive(coefficient),
                )

            companion object : DerDecodable<Pkcs1RsaOtherPrimeInfo, PrimeInfo> {
                override fun decodeFromTlv(
                    serializer: KSerializer<Pkcs1RsaOtherPrimeInfo>,
                    src: Asn1Element,
                    der: Der,
                ): PrimeInfo =
                    der.decodeFromTlv(serializer, src).let {
                        PrimeInfo(it.prime.toBigInteger(), it.exponent.toBigInteger(), it.coefficient.toBigInteger())
                    }
            }
        }

        companion object : DerPemDecodable<Pkcs8PrivateKeyInfo, RSA> {
            override val canonicalPemLabel: String = PRIVATE_KEY_PEM_LABEL
            override val validPemLabels: Set<String> = setOf(PRIVATE_KEY_PEM_LABEL, RSA_PRIVATE_KEY_PEM_LABEL)
            val oid: ObjectIdentifier = KnownOIDs.rsaEncryption

            override fun decodeFromTlv(
                serializer: KSerializer<Pkcs8PrivateKeyInfo>,
                src: Asn1Element,
                der: Der,
            ): RSA {
                val decoded = der.decodeFromTlv(serializer, src)
                require(decoded.algorithmOid == oid) { "Expected RSA private key, got ${decoded.algorithmOid}" }
                return RSA(decoded)
            }

            override fun decodeFromPemBlockPayload(
                serializer: KSerializer<Pkcs8PrivateKeyInfo>,
                src: PemBlock,
                der: Der,
            ): RSA =
                when (src.pemLabel) {
                    RSA_PRIVATE_KEY_PEM_LABEL -> FromPKCS1.decodeFromDer(src.payload, der)
                    else -> decodeFromDer(serializer, src.payload, der)
                }
        }

        object FromPKCS1 {
            fun decodeFromTlv(
                src: Asn1Element,
                der: Der = DER,
            ): RSA = RSA(der.decodeFromTlv(Pkcs1RsaPrivateKeyInfo.serializer(), src))

            fun decodeFromDer(bytes: ByteArray, der: Der = DER): RSA =
                decodeFromTlv(Asn1Element.parse(bytes), der)
        }
    }

    sealed class EC private constructor(
        private val providedContent: EcPrivateKeyContent?,
        private val providedSec1Source: EcSec1Source?,
        private val providedPkcs8Representation: Pkcs8PrivateKeyInfo?,
    ) : CryptoPrivateKey {

        override val oid: ObjectIdentifier get() = Companion.oid

        protected val content: EcPrivateKeyContent by providedContent orLazy {
            val source = providedSec1Source ?: requireNotNull(providedPkcs8Representation).let {
                EcSec1Source(it.decodeEcPrivateKey(), it.algorithmParameters?.let(::decodeEcCurve), it.attributes)
            }
            source.sec1Representation.toSignumContent(source.curveFromPkcs8, source.attributes)
        }

        override val attributes: Set<Asn1Element>? by lazy {
            providedContent?.attributes
                ?: providedPkcs8Representation?.attributes
                ?: providedSec1Source?.attributes
        }

        val privateKey: BigInteger get() = content.privateKey

        abstract val privateKeyBytes: ByteArray

        val sec1Representation: Sec1EcPrivateKeyInfo by providedSec1Source?.sec1Representation orLazy {
            providedPkcs8Representation?.decodeEcPrivateKey() ?: content.toSec1Representation()
        }

        override val asn1Representation: Pkcs8PrivateKeyInfo by providedPkcs8Representation orLazy {
            Pkcs8PrivateKeyInfo.ec(sec1Representation, curveOidForPkcs8(), attributes)
        }

        val asSEC1: DerPemEncodable<Sec1EcPrivateKeyInfo> = object : DerPemEncodable<Sec1EcPrivateKeyInfo> {
            override val pemLabel: String get() = EC_PRIVATE_KEY_PEM_LABEL
            override val asn1Representation: Sec1EcPrivateKeyInfo get() = sec1Representation
        }

        protected abstract fun curveOidForPkcs8(): ObjectIdentifier?

        override fun equals(other: Any?): Boolean {
            if (other !is EC) return false
            return privateKey == other.privateKey
        }

        override fun hashCode() = privateKey.hashCode()

        class WithPublicKey private constructor(
            providedContent: EcPrivateKeyContent?,
            providedSec1Source: EcSec1Source?,
            providedPkcs8Representation: Pkcs8PrivateKeyInfo?,
        ) : EC(providedContent, providedSec1Source, providedPkcs8Representation),
            CryptoPrivateKey.WithPublicKey<CryptoPublicKey.EC>,
            KeyAgreementPrivateValue.ECDH {

            constructor(
                privateKey: BigInteger,
                publicKey: CryptoPublicKey.EC,
                encodeCurve: Boolean,
                encodePublicKey: Boolean,
                attributes: Set<Asn1Element>? = null,
            ) : this(
                EcPrivateKeyContent(
                    privateKey = privateKey,
                    publicKey = publicKey,
                    publicKeyBytes = null,
                    encodeCurve = encodeCurve,
                    encodePublicKey = encodePublicKey,
                    curveOrderLengthInBytes = publicKey.curve.scalarLength.bytes.toInt(),
                    attributes = attributes,
                ),
                null,
                null,
            ) {
                require(publicKey.publicPoint == privateKey.times(publicKey.curve.generator)) {
                    "Public key must match the private key!"
                }
            }

            constructor(
                privateKey: BigInteger,
                curve: ECCurve,
                encodeCurve: Boolean,
                encodePublicKey: Boolean,
                attributes: Set<Asn1Element>? = null,
            ) : this(
                privateKey,
                curve.generator.times(privateKey).asPublicKey(preferCompressed = true),
                encodeCurve,
                encodePublicKey,
                attributes,
            )

            internal constructor(source: EcSec1Source) : this(null, source, null)
            internal constructor(asn1Representation: Pkcs8PrivateKeyInfo) : this(null, null, asn1Representation)

            override val publicKey: CryptoPublicKey.EC by content.publicKey orLazy {
                val curve = curve
                content.publicKeyBytes?.let {
                    CryptoPublicKey.EC.fromAnsiX963Bytes(curve, it.rawBytes)
                } ?: curve.generator.times(privateKey).asPublicKey(preferCompressed = true)
            }

            val curve: ECCurve get() = publicKey.curve
            val encodeCurve: Boolean get() = content.encodeCurve
            val encodePublicKey: Boolean get() = content.encodePublicKey

            override val privateKeyBytes: ByteArray
                get() = privateKey.toByteArray().ensureSize(curve.scalarLength.bytes)

            override val publicValue get() = publicKey

            override fun curveOidForPkcs8(): ObjectIdentifier = curve.oid

            override fun toString() = "EC private key for public key $publicKey"
        }

        class WithoutPublicKey private constructor(
            providedContent: EcPrivateKeyContent?,
            providedSec1Source: EcSec1Source?,
        ) : EC(providedContent, providedSec1Source, null) {

            constructor(
                privateKey: BigInteger,
                publicKeyBytes: Asn1BitString?,
                attributes: Set<Asn1Element>? = null,
                curveOrderLengthInBytes: Int,
            ) : this(
                EcPrivateKeyContent(
                    privateKey = privateKey,
                    publicKey = null,
                    publicKeyBytes = publicKeyBytes,
                    encodeCurve = false,
                    encodePublicKey = publicKeyBytes != null,
                    curveOrderLengthInBytes = curveOrderLengthInBytes,
                    attributes = attributes,
                ),
                null,
            )

            internal constructor(source: EcSec1Source) : this(null, source)

            val publicKeyBytes: Asn1BitString? get() = content.publicKeyBytes

            private val curveOrderLengthInBytes: Int get() = content.curveOrderLengthInBytes

            fun withCurve(
                curve: ECCurve,
                encodeCurve: Boolean = true,
                encodePublicKey: Boolean = (this.publicKeyBytes != null),
            ): WithPublicKey {
                require(curve.scalarLength.bytes.toInt() == curveOrderLengthInBytes) {
                    "Encoded private key was padded to $curveOrderLengthInBytes bytes, but curve $curve needs padding to ${curve.scalarLength.bytes.toInt()} bytes"
                }
                return if (publicKeyBytes != null) {
                    WithPublicKey(
                        privateKey,
                        CryptoPublicKey.EC.fromAnsiX963Bytes(curve, publicKeyBytes!!.rawBytes),
                        encodeCurve,
                        encodePublicKey,
                        attributes,
                    )
                } else {
                    WithPublicKey(privateKey, curve, encodeCurve, encodePublicKey, attributes)
                }
            }

            override fun equals(other: Any?): Boolean {
                if (this === other) return true
                if (other !is WithoutPublicKey) return false
                if (!super.equals(other)) return false
                return curveOrderLengthInBytes == other.curveOrderLengthInBytes
            }

            override fun hashCode(): Int = 31 * super.hashCode() + curveOrderLengthInBytes

            override val privateKeyBytes: ByteArray
                get() = privateKey.toByteArray().ensureSize(curveOrderLengthInBytes)

            override fun curveOidForPkcs8(): ObjectIdentifier? =
                throw Asn1StructuralException("Cannot PKCS#8-encode an EC key without curve. Use withCurve()!")
        }

        companion object : DerPemDecodable<Pkcs8PrivateKeyInfo, EC> {
            override val canonicalPemLabel: String = PRIVATE_KEY_PEM_LABEL
            override val validPemLabels: Set<String> = setOf(PRIVATE_KEY_PEM_LABEL, EC_PRIVATE_KEY_PEM_LABEL)
            val oid: ObjectIdentifier = KnownOIDs.ecPublicKey

            override fun decodeFromTlv(
                serializer: KSerializer<Pkcs8PrivateKeyInfo>,
                src: Asn1Element,
                der: Der,
            ): EC {
                val decoded = der.decodeFromTlv(serializer, src)
                require(decoded.algorithmOid == oid) { "Expected EC private key, got ${decoded.algorithmOid}" }
                return fromPkcs8Representation(decoded)
            }

            override fun decodeFromPemBlockPayload(
                serializer: KSerializer<Pkcs8PrivateKeyInfo>,
                src: PemBlock,
                der: Der,
            ): EC =
                when (src.pemLabel) {
                    EC_PRIVATE_KEY_PEM_LABEL -> FromSEC1.decodeFromDer(src.payload, der)
                    else -> decodeFromDer(serializer, src.payload, der)
                }

            private fun fromPkcs8Representation(representation: Pkcs8PrivateKeyInfo): EC {
                val curve = representation.algorithmParameters?.let(::decodeEcCurve)
                return when {
                    curve != null -> WithPublicKey(representation)
                    representation.decodeEcPrivateKey().parameters != null -> WithPublicKey(representation)
                    else -> WithoutPublicKey(EcSec1Source(representation.decodeEcPrivateKey(), null, representation.attributes))
                }
            }

            internal fun iosDecodeInternal(keyBytes: ByteArray): CryptoPrivateKey.EC.WithPublicKey {
                val crv = ECCurve.fromIosEncodedPrivateKeyLength(keyBytes.size)
                    ?: throw IllegalArgumentException("Unknown curve in iOS raw key")
                return WithPublicKey(
                    BigInteger.fromByteArray(
                        keyBytes.sliceArray(crv.iosEncodedPublicKeyLength..<keyBytes.size),
                        Sign.POSITIVE,
                    ),
                    encodeCurve = false,
                    encodePublicKey = true,
                    publicKey = CryptoPublicKey.fromIosEncoded(
                        keyBytes.sliceArray(0..<crv.iosEncodedPublicKeyLength)
                    ) as CryptoPublicKey.EC,
                )
            }
        }

        object FromSEC1 {
            fun decodeFromTlv(
                src: Asn1Element,
                der: Der = DER,
            ): EC = fromSec1(der.decodeFromTlv(Sec1EcPrivateKeyInfo.serializer(), src), null)

            fun decodeFromDer(bytes: ByteArray, der: Der = DER): EC =
                decodeFromTlv(Asn1Element.parse(bytes), der)

            fun fromSec1(
                representation: Sec1EcPrivateKeyInfo,
                attributes: Set<Asn1Element>? = null,
            ): EC {
                val source = EcSec1Source(representation, representation.parameters?.let(ECCurve::withOid), attributes)
                return if (source.curveFromPkcs8 != null) WithPublicKey(source) else WithoutPublicKey(source)
            }
        }
    }

    companion object : DerPemDecodable<Pkcs8PrivateKeyInfo, CryptoPrivateKey> {
        const val PRIVATE_KEY_PEM_LABEL: String = "PRIVATE KEY"
        const val RSA_PRIVATE_KEY_PEM_LABEL: String = "RSA PRIVATE KEY"
        const val EC_PRIVATE_KEY_PEM_LABEL: String = "EC PRIVATE KEY"

        override val canonicalPemLabel: String = PRIVATE_KEY_PEM_LABEL
        override val validPemLabels: Set<String> =
            setOf(PRIVATE_KEY_PEM_LABEL, RSA_PRIVATE_KEY_PEM_LABEL, EC_PRIVATE_KEY_PEM_LABEL)

        override fun decodeFromTlv(
            serializer: KSerializer<Pkcs8PrivateKeyInfo>,
            src: Asn1Element,
            der: Der,
        ): CryptoPrivateKey {
            val decoded = der.decodeFromTlv(serializer, src)
            require(decoded.version == 1) { "PKCS#8 Private Key VERSION must be 1" }
            return when (decoded.algorithmOid) {
                RSA.oid -> RSA(decoded)
                EC.oid -> EC.decodeFromTlv(Pkcs8PrivateKeyInfo.serializer(), src, der)
                else -> throw IllegalArgumentException("Unknown Algorithm: ${decoded.algorithmOid}")
            }
        }

        override fun decodeFromPemBlockPayload(
            serializer: KSerializer<Pkcs8PrivateKeyInfo>,
            src: PemBlock,
            der: Der,
        ): CryptoPrivateKey =
            when (src.pemLabel) {
                RSA_PRIVATE_KEY_PEM_LABEL -> RSA.FromPKCS1.decodeFromDer(src.payload, der)
                EC_PRIVATE_KEY_PEM_LABEL -> EC.FromSEC1.decodeFromDer(src.payload, der)
                else -> decodeFromDer(serializer, src.payload, der)
            }

        fun fromIosEncoded(keyBytes: ByteArray): KmmResult<CryptoPrivateKey.WithPublicKey<*>> = catching {
            if (keyBytes.first() == ANSIECPrefix.UNCOMPRESSED.prefixByte) {
                CryptoPrivateKey.EC.iosDecodeInternal(keyBytes)
            } else {
                CryptoPrivateKey.RSA.FromPKCS1.decodeFromTlv(Asn1Element.parse(keyBytes)) as CryptoPrivateKey.WithPublicKey<*>
            }
        }
    }
}

/** Representation of an encrypted private key structure as per RFC 5208. */
class EncryptedPrivateKey(val encryptionAlgorithm: ObjectIdentifier, val encryptedData: ByteArray) :
    Asn1Encodable<Asn1Sequence> {

    @Throws(Asn1Exception::class)
    override fun encodeToTlv(): Asn1Sequence = runRethrowing {
        Asn1.Sequence {
            +encryptionAlgorithm
            +Asn1.OctetString(encryptedData)
        }
    }

    companion object : Asn1Decodable<Asn1Sequence, EncryptedPrivateKey> {
        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Sequence): EncryptedPrivateKey = src.decodeRethrowing {
            EncryptedPrivateKey(
                ObjectIdentifier.decodeFromTlv(next().asPrimitive()),
                next().asPrimitive().asOctetString().content,
            )
        }
    }
}

private fun Pkcs1RsaPrivateKeyInfo.toSignumContent(attributes: Set<Asn1Element>?): RsaPrivateKeyContent =
    RsaPrivateKeyContent(
        publicKey = CryptoPublicKey.RSA(modulus, publicExponent),
        privateKey = privateExponent.toBigInteger(),
        prime1 = prime1.toBigInteger(),
        prime2 = prime2.toBigInteger(),
        prime1exponent = exponent1.toBigInteger(),
        prime2exponent = exponent2.toBigInteger(),
        crtCoefficient = coefficient.toBigInteger(),
        otherPrimeInfos = otherPrimeInfos?.map {
            CryptoPrivateKey.RSA.PrimeInfo(it.prime.toBigInteger(), it.exponent.toBigInteger(), it.coefficient.toBigInteger())
        },
        attributes = attributes,
    )

private fun RsaPrivateKeyContent.toPkcs1Representation(): Pkcs1RsaPrivateKeyInfo =
    Pkcs1RsaPrivateKeyInfo(
        rawVersion = Asn1Integer(if (otherPrimeInfos != null) 1 else 0),
        modulus = publicKey.n,
        publicExponent = publicKey.e,
        privateExponent = positive(privateKey),
        prime1 = positive(prime1),
        prime2 = positive(prime2),
        exponent1 = positive(prime1exponent),
        exponent2 = positive(prime2exponent),
        coefficient = positive(crtCoefficient),
        otherPrimeInfos = otherPrimeInfos?.map { it.asn1Representation },
    )

private fun Sec1EcPrivateKeyInfo.toSignumContent(
    curveFromPkcs8: ECCurve?,
    attributes: Set<Asn1Element>?,
): EcPrivateKeyContent {
    require(version == 1) { "EC public key version must be 1" }
    val curve = parameters?.let(ECCurve::withOid) ?: curveFromPkcs8
    val privateValue = BigInteger.fromByteArray(privateKey, Sign.POSITIVE)
    return if (curve != null) {
        EcPrivateKeyContent(
            privateKey = privateValue,
            publicKey = publicKey?.let { CryptoPublicKey.EC.fromAnsiX963Bytes(curve, it.rawBytes) }
                ?: curve.generator.times(privateValue).asPublicKey(preferCompressed = true),
            publicKeyBytes = publicKey,
            encodeCurve = parameters != null,
            encodePublicKey = publicKey != null,
            curveOrderLengthInBytes = privateKey.size,
            attributes = attributes,
        )
    } else {
        EcPrivateKeyContent(
            privateKey = privateValue,
            publicKey = null,
            publicKeyBytes = publicKey,
            encodeCurve = false,
            encodePublicKey = publicKey != null,
            curveOrderLengthInBytes = privateKey.size,
            attributes = attributes,
        )
    }
}

private fun EcPrivateKeyContent.toSec1Representation(): Sec1EcPrivateKeyInfo =
    Sec1EcPrivateKeyInfo(
        version = 1,
        privateKey = privateKey.toByteArray().ensureSize(curveOrderLengthInBytes.toUInt()),
        parameters = publicKey?.curve?.oid?.takeIf { encodeCurve },
        publicKey = when {
            publicKey != null && encodePublicKey -> Asn1.BitString(publicKey.iosEncoded).asAsn1BitString()
            publicKey == null && encodePublicKey -> publicKeyBytes
            else -> null
        },
    )

private fun decodeEcCurve(element: Asn1Element): ECCurve =
    ECCurve.withOid(ObjectIdentifier.decodeFromTlv(element as Asn1Primitive))

private fun positive(value: BigInteger): Asn1Integer.Positive =
    value.toAsn1Integer() as Asn1Integer.Positive
