package at.asitplus.signum.indispensable.sign

import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.Identifiable
import at.asitplus.awesn1.KnownOIDs
import at.asitplus.awesn1.crypto.Pkcs1RsaPublicKeyInfo
import at.asitplus.awesn1.crypto.Pkcs1RsaPublicKeyInfo.Companion.rsa
import at.asitplus.awesn1.crypto.SubjectPublicKeyInfo
import at.asitplus.awesn1.ecPublicKey
import at.asitplus.awesn1.readOid
import at.asitplus.awesn1.rsaEncryption
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.decodeFromDer
import at.asitplus.awesn1.toAsn1Integer
import at.asitplus.catching
import at.asitplus.io.UVarInt
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.ECPoint
import at.asitplus.signum.indispensable.KeyAgreementPublicValue
import at.asitplus.signum.indispensable.PublicKeyFormatProvider
import at.asitplus.signum.indispensable.fromIosEncodedPublicKeyLength
import at.asitplus.signum.indispensable.misc.ANSIECPrefix
import at.asitplus.signum.indispensable.misc.ANSIECPrefix.Companion.hasPrefix
import at.asitplus.signum.internals.orLazy
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import kotlinx.serialization.SerialName
import kotlinx.serialization.encodeToByteArray

/** RSA Public key */
class RSAPublicKey private constructor(
    providedAsn1Representation: SubjectPublicKeyInfo?,
    providedContent: Content?,
) : CryptoPublicKey() {

    private data class Content(val n: Asn1Integer.Positive, val e: Asn1Integer.Positive) {
        constructor(info: Pkcs1RsaPublicKeyInfo) :
                this(info.modulus as Asn1Integer.Positive, info.publicExponent as Asn1Integer.Positive)
    }

    @Throws(IllegalArgumentException::class)
    constructor(
        /** modulus */
        n: Asn1Integer.Positive,

        /** public exponent */
        e: Asn1Integer.Positive,
    ) : this(null, Content(n, e))

    constructor(asn1Representation: SubjectPublicKeyInfo) : this(asn1Representation, null)

    override val asn1Representation: SubjectPublicKeyInfo by providedAsn1Representation orLazy {
        SubjectPublicKeyInfo.rsa(n, e)
    }

    private val content: Content by providedContent orLazy {
        Content(Pkcs1RsaPublicKeyInfo.of(asn1Representation))
    }

    /** modulus */
    val n get() = content.n

    /** public exponent */
    val e get() = content.e

    val bits = n.bitLength().let { Size.of(it) ?: throw IllegalArgumentException("Unsupported key size $it bits") }

    @Deprecated(message = "Use a BigInteger-capable constructor instead", level = DeprecationLevel.ERROR)
    constructor(n: ByteArray, e: Int) : this(
        Asn1Integer.fromUnsignedByteArray(n),
        Asn1Integer(e) as Asn1Integer.Positive
    )

    constructor(n: Asn1Integer, e: Asn1Integer) : this(n as Asn1Integer.Positive, e as Asn1Integer.Positive)
    constructor(n: BigInteger, e: BigInteger) : this(n.toAsn1Integer(), e.toAsn1Integer())
    constructor(n: BigInteger, e: UInt) : this(n.toAsn1Integer(), Asn1Integer(e))

    override val oid get() = Companion.oid

    /** enum of supported RSA key sizes. For sanity checks! */
    enum class Size(val number: UInt) {
        RSA_512(512u),
        RSA_1024(1024u),
        RSA_2048(2048u),
        RSA_3027(3072u),
        RSA_4096(4096u),
        RSA_8192(8192u);

        companion object : Identifiable {
            fun of(numBits: UInt) = entries.find { it.number == numBits }

            override val oid = KnownOIDs.rsaEncryption
        }
    }

    override val didCodec get() = DID_KEY_CODEC
    override val didKeyBytes get() = pkcsEncoded

    /**
     * PKCS#1 encoded RSA Public Key
     */
    val pkcsEncoded by lazy {
        DER.encodeToByteArray(Pkcs1RsaPublicKeyInfo(n, e))
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is RSAPublicKey) return false
        return n == other.n && e == other.e
    }

    override fun hashCode(): Int {
        var result = n.hashCode()
        result = 31 * result + e.hashCode()
        return result
    }

    override fun toString(): String = "RSA(n=$n, e=$e)"

    companion object : Identifiable {
        val DID_KEY_CODEC = UVarInt(0x1205u)
        /**
         * decodes a PKCS#1-encoded RSA key
         *
         * @throws Asn1Exception all sorts of exceptions on invalid input
         */
        @Throws(Asn1Exception::class)
        fun fromPKCS1encoded(input: ByteArray): RSAPublicKey =
            RSAPublicKey(null,
                Content(DER.decodeFromDer<Pkcs1RsaPublicKeyInfo>(input)))

        fun fromIosEncoded(input: ByteArray) = fromPKCS1encoded(input)

        // on companion to prevent platform signature clashes with JVM
        @Suppress("NOTHING_TO_INLINE")
        inline operator fun invoke(n: BigInteger, e: Int) =
            RSAPublicKey(n, e.also { require(it > 0) }.toUInt())

        override val oid = KnownOIDs.rsaEncryption
    }
}

/**
 * ECDSA public key representation
 * The properties and constructor params are exactly what their names suggest
 * @see Companion.asPublicKey
 */
@SerialName("EC")
class ECDSAPublicKey private constructor(
    providedAsn1Representation: SubjectPublicKeyInfo?,
    providedContent: Content?,
) : CryptoPublicKey(), KeyAgreementPublicValue.ECDH {

    private data class Content(
        val publicPoint: ECPoint.Normalized,
        val preferCompressedRepresentation: Boolean,
    )

    constructor(asn1Representation: SubjectPublicKeyInfo) : this(asn1Representation, null)

    override fun asCryptoPublicKey() = this

    override val asn1Representation: SubjectPublicKeyInfo by providedAsn1Representation orLazy {
        SubjectPublicKeyInfo.ec(curve.oid, toAnsiX963Encoded(useCompressed = false))
    }

    private val content: Content by providedContent orLazy {
        val parameters = asn1Representation.algorithmIdentifier.parameters
        requireNotNull(parameters) { "No EC params found" }
        val curveOid = parameters.asPrimitive().readOid()
        val curve = ECCurve.entries.find { it.oid == curveOid }
            ?: throw Asn1Exception("Curve not supported: $curveOid")
        if (asn1Representation.subjectPublicKey.numPaddingBits != 0.toByte()) {
            throw Asn1Exception("EC key must consist of full octets")
        }
        if (!asn1Representation.subjectPublicKey.bitCarryingBytes.hasPrefix(ANSIECPrefix.UNCOMPRESSED)) {
            throw Asn1Exception("EC key not prefixed with 0x04")
        }
        fromAnsiX963Bytes(curve, asn1Representation.subjectPublicKey.bitCarryingBytes).content
    }

    val publicPoint get() = content.publicPoint
    val preferCompressedRepresentation get() = content.preferCompressedRepresentation

    val curve get() = publicPoint.curve
    val x get() = publicPoint.x
    val xBytes get() = publicPoint.xBytes
    val y get() = publicPoint.y
    val yBytes get() = publicPoint.yBytes
    val yCompressed get() = publicPoint.yCompressed

    override val oid get() = Companion.oid

    /**
     * ANSI X9.63 Encoding as used by iOS
     */
    fun toAnsiX963Encoded(useCompressed: Boolean = preferCompressedRepresentation): ByteArray =
        when (useCompressed) {
            true -> ANSIECPrefix.forSign(yCompressed) + xBytes
            false -> ANSIECPrefix.UNCOMPRESSED + xBytes + yBytes
        }

    override val didCodec get() = when (this.curve) {
        ECCurve.SECP_256_R_1 -> DID_KEY_CODEC_P256
        ECCurve.SECP_384_R_1 -> DID_KEY_CODEC_P384
        ECCurve.SECP_521_R_1 -> DID_KEY_CODEC_P521
    }
    override val didKeyBytes get() = toAnsiX963Encoded(useCompressed = true)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as ECDSAPublicKey

        return (this.publicPoint == other.publicPoint)
    }

    override fun hashCode() =
        publicPoint.hashCode()

    companion object : Identifiable {

        val DID_KEY_CODEC_P256 = UVarInt(0x1200u)
        val DID_KEY_CODEC_P384 = UVarInt(0x1201u)
        val DID_KEY_CODEC_P521 = UVarInt(0x1202u)

        fun ECPoint.asPublicKey(preferCompressed: Boolean = false): ECDSAPublicKey {
            return ECDSAPublicKey(null,
                Content(this.normalize(), preferCompressed))
        }

        /** Decodes key from big-endian X and sign of Y */
        @Suppress("NOTHING_TO_INLINE")
        inline fun fromCompressed(curve: ECCurve, x: ByteArray, sign: Sign) =
            ECPoint.fromCompressed(curve, x, sign).asPublicKey(true)

        /** Decodes key from big-endian X and sign of Y */
        @Suppress("NOTHING_TO_INLINE")
        inline fun fromCompressed(curve: ECCurve, x: ByteArray, usePositiveY: Boolean) =
            ECPoint.fromCompressed(curve, x, usePositiveY).asPublicKey(true)

        /** Decodes key from big-endian X and big-endian Y */
        @Suppress("NOTHING_TO_INLINE")
        inline fun fromUncompressed(curve: ECCurve, x: ByteArray, y: ByteArray) =
            ECPoint.fromUncompressed(curve, x, y).asPublicKey(false)

        @Deprecated(
            "Explicitly specify what you want",
            ReplaceWith("fromCompressed(curve, x, usePositiveY)"),
            DeprecationLevel.ERROR
        )
        @Suppress("NOTHING_TO_INLINE")
        inline operator fun invoke(curve: ECCurve, x: ByteArray, usePositiveY: Boolean) =
            fromCompressed(curve, x, usePositiveY)

        @Deprecated(
            "Explicitly specify what you want",
            ReplaceWith("fromUncompressed(curve, x, y)"),
            DeprecationLevel.ERROR
        )
        @Suppress("NOTHING_TO_INLINE")
        inline operator fun invoke(curve: ECCurve, x: ByteArray, y: ByteArray) =
            fromUncompressed(curve, x, y)

        /** Decodes a key from its ANSI X9.63 representation */
        @Throws(Throwable::class)
        fun fromAnsiX963Bytes(curve: ECCurve, src: ByteArray): ECDSAPublicKey {
            val numBytes = curve.coordinateLength.bytes.toInt()

            val prefix = catching { ANSIECPrefix.fromPrefixByte(src[0]) }
                .getOrElse { throw IllegalArgumentException("Invalid X9.63 EC key format") }

            if (prefix.isUncompressed) {
                require(src.size == (2 * numBytes + 1))
                val x = src.copyOfRange(1, numBytes + 1)
                val y = src.copyOfRange(numBytes + 1, 2 * numBytes + 1)
                return fromUncompressed(curve, x, y)
            } else {
                require(src.size == (numBytes + 1))
                val x = src.copyOfRange(1, src.size)
                return fromCompressed(curve, x, prefix.compressionSign)
            }
        }

        fun fromIosEncoded(src: ByteArray) =
            fromAnsiX963Bytes(
                ECCurve.fromIosEncodedPublicKeyLength(src.size)
                    ?: throw IllegalArgumentException("Unknown curve in iOS raw key"),
                src)

        override val oid = KnownOIDs.ecPublicKey

    }
}

// @ServiceProvider
object IndispensablePublicKeyFormatsProvider : PublicKeyFormatProvider {
    override fun decodeFromAsn1(publicKeyInfo: SubjectPublicKeyInfo) = when(publicKeyInfo.algorithmOid) {
        ECDSAPublicKey.oid -> ECDSAPublicKey(publicKeyInfo)
        RSAPublicKey.oid -> RSAPublicKey(publicKeyInfo)
        else -> null
    }

    override fun decodeFromDidKey(codec: UVarInt, keyBytes: ByteArray) = when(codec) {
        RSAPublicKey.DID_KEY_CODEC ->
            RSAPublicKey.fromPKCS1encoded(keyBytes)
        ECDSAPublicKey.DID_KEY_CODEC_P256, UVarInt(0x1290u) ->
            ECDSAPublicKey.fromAnsiX963Bytes(ECCurve.SECP_256_R_1, keyBytes)
        ECDSAPublicKey.DID_KEY_CODEC_P384, UVarInt(0x1291u), UVarInt(8u) ->
            ECDSAPublicKey.fromAnsiX963Bytes(ECCurve.SECP_384_R_1, keyBytes)
        ECDSAPublicKey.DID_KEY_CODEC_P521, UVarInt(0x1292u) ->
            ECDSAPublicKey.fromAnsiX963Bytes(ECCurve.SECP_521_R_1, keyBytes)
        else -> null
    }
}
