package at.asitplus.signum.indispensable.sign

import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.SubjectPublicKeyInfo
import at.asitplus.catching
import at.asitplus.io.UVarInt
import at.asitplus.io.UVarInt.Companion.varint
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.agree.KeyAgreementPublicValue
import at.asitplus.signum.indispensable.misc.ANSIECPrefix
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import kotlinx.serialization.SerialName

/** RSA Public key */
class RsaPublicKey(
    /** modulus */
    val n: Asn1Integer.Positive,
    /** public exponent */
    val e: Asn1Integer.Positive,
) : CryptoPublicKey {

    @SignumInternals override val sourceRepresentation = SourceRepresentationStorage()

    override val additionalProperties = mutableMapOf<String, String>()

    val bits = n.bitLength().let { Size.of(it) ?: throw IllegalArgumentException("Unsupported key size $it bits") }

    @Deprecated(message = "Use a BigInteger-capable constructor instead", level = DeprecationLevel.ERROR)
    constructor(n: ByteArray, e: Int) : this(
        Asn1Integer.fromUnsignedByteArray(n),
        Asn1Integer(e) as Asn1Integer.Positive
    )

    constructor(n: Asn1Integer, e: Asn1Integer) : this(n as Asn1Integer.Positive, e as Asn1Integer.Positive)
    constructor(n: BigInteger, e: BigInteger) : this(n.toAsn1Integer(), e.toAsn1Integer())
    constructor(n: BigInteger, e: UInt) : this(n.toAsn1Integer(), Asn1Integer(e))

    /** enum of supported RSA key sizes. For sanity checks! */
    enum class Size(val number: UInt) {
        RSA_512(512u),
        RSA_1024(1024u),
        RSA_2048(2048u),
        RSA_3027(3072u),
        RSA_4096(4096u),
        RSA_8192(8192u);

        companion object {
            fun of(numBits: UInt) = entries.find { it.number == numBits }

            val oid = KnownOIDs.rsaEncryption
        }
    }

    override val didCodec get() = DID_KEY_CODEC
    override val didKeyBytes get() = this@RsaPublicKey.asn1.pkcs1.toDer()

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is RsaPublicKey) return false
        return n == other.n && e == other.e
    }

    override fun hashCode(): Int {
        var result = n.hashCode()
        result = 31 * result + e.hashCode()
        return result
    }

    override fun toString(): String = "RSA(n=$n, e=$e)"

    companion object {
        val DID_KEY_CODEC = 0x1205u.varint

        @Deprecated("Use from pkcs1 directly", replaceWith = ReplaceWith("fromAsn1.PKCS1(input)"))
        fun fromIosEncoded(input: ByteArray) = fromAsn1.PKCS1(input)

        // on companion to prevent platform signature clashes with JVM
        @Suppress("NOTHING_TO_INLINE")
        inline operator fun invoke(n: BigInteger, e: Int) =
            RsaPublicKey(n, e.also { require(it > 0) }.toUInt())

        val oid = KnownOIDs.rsaEncryption
    }
}

/**
 * ECDSA public key representation
 * The properties and constructor params are exactly what their names suggest
 * @see Companion.asPublicKey
 */
@SerialName("EC")
class EcdsaPublicKey(
    val publicPoint: ECPoint.Normalized,
    val preferCompressedRepresentation: Boolean,
) : CryptoPublicKey, KeyAgreementPublicValue.ECDH {

    @SignumInternals override val sourceRepresentation = SourceRepresentationStorage()

    override val additionalProperties = mutableMapOf<String, String>()

    override fun asCryptoPublicKey() = this

    val curve get() = publicPoint.curve
    val x get() = publicPoint.x
    val xBytes get() = publicPoint.xBytes
    val y get() = publicPoint.y
    val yBytes get() = publicPoint.yBytes
    val yCompressed get() = publicPoint.yCompressed

    /** ANSI X9.63 encoding (as used in the X.509 signatureValue) */
    // TODO: should this end up being a source format?
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

        other as EcdsaPublicKey

        return (this.publicPoint == other.publicPoint)
    }

    override fun hashCode() =
        publicPoint.hashCode()

    companion object {

        val DID_KEY_CODEC_P256 = 0x1200u.varint
        val DID_KEY_CODEC_P384 = 0x1201u.varint
        val DID_KEY_CODEC_P521 = 0x1202u.varint

        fun ECPoint.asPublicKey(preferCompressed: Boolean = false): EcdsaPublicKey {
            return EcdsaPublicKey(this.normalize(), preferCompressed)
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

        /** Decodes a key from its ANSI X9.63 representation */
        @Throws(Throwable::class)
        fun fromAnsiX963Bytes(curve: ECCurve, src: ByteArray): EcdsaPublicKey {
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

        @Deprecated("Use SecKeyRef.toCryptoPublicKey instead", ReplaceWith("fromAnsiX963Bytes(ECCurve.fromIosEncodedPublicKeyLength(src.size)!!, src)"))
        fun fromIosEncoded(src: ByteArray) =
            fromAnsiX963Bytes(
                ECCurve.fromIosEncodedPublicKeyLength(src.size)
                    ?: throw IllegalArgumentException("Unknown curve in iOS raw key"),
                src)

        val oid = KnownOIDs.ecPublicKey

    }
}

object IndispensableAsn1PublicKeyFormatsProvider : Asn1PublicKeyFormatProvider {
    override fun encodeToAsn1(value: CryptoPublicKey): SubjectPublicKeyInfo? = when (value) {
        is RsaPublicKey -> value.asn1.toRepresentation()
        is EcdsaPublicKey -> value.asn1.toRepresentation()
        else -> null
    }

    override fun decodeFromAsn1(publicKeyInfo: SubjectPublicKeyInfo) = when(publicKeyInfo.algorithmOid) {
        EcdsaPublicKey.oid -> EcdsaPublicKey.fromAsn1(publicKeyInfo)
        RsaPublicKey.oid -> RsaPublicKey.fromAsn1(publicKeyInfo)
        else -> null
    }

    override fun decodeFromDidKey(codec: UVarInt, keyBytes: ByteArray) = when(codec) {
        RsaPublicKey.DID_KEY_CODEC ->
            RsaPublicKey.fromAsn1.PKCS1(keyBytes)
        EcdsaPublicKey.DID_KEY_CODEC_P256, UVarInt(0x1290u) ->
            EcdsaPublicKey.fromAnsiX963Bytes(ECCurve.SECP_256_R_1, keyBytes)
        EcdsaPublicKey.DID_KEY_CODEC_P384, UVarInt(0x1291u), UVarInt(8u) ->
            EcdsaPublicKey.fromAnsiX963Bytes(ECCurve.SECP_384_R_1, keyBytes)
        EcdsaPublicKey.DID_KEY_CODEC_P521, UVarInt(0x1292u) ->
            EcdsaPublicKey.fromAnsiX963Bytes(ECCurve.SECP_521_R_1, keyBytes)
        else -> null
    }
}
