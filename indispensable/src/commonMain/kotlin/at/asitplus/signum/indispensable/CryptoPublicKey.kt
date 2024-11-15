package at.asitplus.signum.indispensable

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.encoding.Asn1.BitString
import at.asitplus.signum.indispensable.asn1.encoding.Asn1.Null
import at.asitplus.signum.indispensable.io.ByteArrayBase64Serializer
import at.asitplus.signum.indispensable.misc.ANSIECPrefix
import at.asitplus.signum.indispensable.misc.ANSIECPrefix.Companion.hasPrefix
import at.asitplus.io.BaseN
import at.asitplus.io.MultiBase
import at.asitplus.io.UVarInt
import at.asitplus.io.multibaseDecode
import at.asitplus.io.multibaseEncode
import at.asitplus.signum.indispensable.asn1.encoding.*
import at.asitplus.signum.indispensable.misc.ensureSize
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Representation of a public key structure
 */
@Serializable
sealed class CryptoPublicKey : Asn1Encodable<Asn1Sequence>, Identifiable {

    /**
     * This is meant for storing additional properties, which may be relevant for certain use cases.
     * For example, Json Web Keys or Cose Keys may define an arbitrary key IDs.
     * This is not meant for Algorithm parameters! If an algorithm needs parameters, the implementing classes should be extended
     */
    //must be serializable, therefore <String,String>
    val additionalProperties = mutableMapOf<String, String>()

    /**
     * Representation of the key in DID format, EC compression is used if key was compressed on reception
     */
    abstract val didEncoded: String

    /**
     * Representation of the key in the format used by iOS, EC compression is used if key was compressed on reception
     */
    abstract val iosEncoded: ByteArray

    override fun encodeToTlv() = when (this) {
        is EC -> Asn1.Sequence {
            +Asn1.Sequence {
                +oid
                +curve.oid
            }
            +BitString(iosEncoded)
        }

        is RSA -> {
            Asn1.Sequence {
                +Asn1.Sequence {
                    +oid
                    +Null()
                }
                +BitString(iosEncoded)
            }
        }
    }


    companion object : Asn1Decodable<Asn1Sequence, CryptoPublicKey> {
        /**
         * Parses a DID representation of a public key and
         * reconstructs the corresponding [CryptoPublicKey] from it
         * @throws Throwable all sorts of exception on invalid input
         */
        @Throws(Throwable::class)
        fun fromDid(input: String): CryptoPublicKey {
            val bytes = multiKeyRemovePrefix(input)
            var decoded = catching { bytes.multibaseDecode() }.getOrThrow()
                ?: throw IndexOutOfBoundsException("Unsupported multibase encoding")
            val codec = UVarInt.fromByteArray(decoded.sliceArray(0..1)).toULong().let { codec ->
                //workaround our blursed encoding of legacy DID-encoded keys
                if (codec < 0x1200uL) {
                    decoded = BaseN.decode(MultiBase.Base.BASE64.alphabet, BigInteger(64), bytes.substring(1))
                    UVarInt.fromByteArray(decoded.sliceArray(0..1)).toULong()
                } else codec
            }

            val keyBytes = decoded.copyOfRange(2, decoded.size)

            return when (codec) {
                0x1200uL, 0x1290uL ->
                    EC.fromAnsiX963Bytes(ECCurve.SECP_256_R_1, keyBytes)

                0x1201uL, 0x1291uL, 8uL ->
                    EC.fromAnsiX963Bytes(ECCurve.SECP_384_R_1, keyBytes)

                0x1202uL, 0x1292uL ->
                    EC.fromAnsiX963Bytes(ECCurve.SECP_521_R_1, keyBytes)

                0x1205uL ->
                    RSA.fromPKCS1encoded(keyBytes)

                else ->
                    throw IllegalArgumentException("Unknown public key identifier $codec")
            }
        }


        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Sequence): CryptoPublicKey = runRethrowing {
            if (src.children.size != 2) throw Asn1StructuralException("Invalid SPKI Structure!")
            val keyInfo = src.nextChild() as Asn1Sequence
            if (keyInfo.children.size != 2) throw Asn1StructuralException("Superfluous data in  SPKI!")

            when (val oid = (keyInfo.nextChild() as Asn1Primitive).readOid()) {
                EC.oid -> {
                    val curveOid = (keyInfo.nextChild() as Asn1Primitive).readOid()
                    val curve = ECCurve.entries.find { it.oid == curveOid }
                        ?: throw Asn1Exception("Curve not supported: $curveOid")

                    val bitString = (src.nextChild() as Asn1Primitive).asAsn1BitString()
                    if (!bitString.rawBytes.hasPrefix(ANSIECPrefix.UNCOMPRESSED)) throw Asn1Exception("EC key not prefixed with 0x04")
                    val xAndY = bitString.rawBytes.drop(1)
                    val coordLen = curve.coordinateLength.bytes.toInt()
                    val x = xAndY.take(coordLen).toByteArray()
                    val y = xAndY.drop(coordLen).take(coordLen).toByteArray()
                    return EC.fromUncompressed(curve, x, y)
                }

                RSA.oid -> {
                    (keyInfo.nextChild() as Asn1Primitive).readNull()
                    val bitString = (src.nextChild() as Asn1Primitive).asAsn1BitString()
                    val rsaSequence = Asn1Element.parse(bitString.rawBytes) as Asn1Sequence
                    val n = (rsaSequence.nextChild() as Asn1Primitive).decodeToAsn1Integer() as Asn1Integer.Positive
                    val e = (rsaSequence.nextChild() as Asn1Primitive).decodeToAsn1Integer() as Asn1Integer.Positive
                    if (rsaSequence.hasMoreChildren()) throw Asn1StructuralException("Superfluous data in SPKI!")
                    return RSA(n, e)
                }

                else -> throw Asn1Exception("Unsupported Key Type: $oid")

            }
        }

        /**
         * Parses this key from an iOS-encoded one
         */
        @Throws(Throwable::class)
        fun fromIosEncoded(it: ByteArray): CryptoPublicKey =
            when (it[0].toUByte()) {
                ANSIECPrefix.UNCOMPRESSED.prefixUByte -> {
                    val curve = when (it.size) {
                        /** apple does not encode the curve identifier, but it is implied as one of the ios supported curves */
                        65 -> ECCurve.SECP_256_R_1
                        97 -> ECCurve.SECP_384_R_1
                        133 -> ECCurve.SECP_521_R_1
                        else -> throw IllegalArgumentException("Unknown curve in iOS raw key")
                    }
                    EC.fromAnsiX963Bytes(curve, it)
                }

                //TODO: this could be nicer, maybe?
                (BERTags.SEQUENCE or BERTags.CONSTRUCTED) -> RSA.fromPKCS1encoded(it)
                else -> throw IllegalArgumentException("Unsupported Key type")
            }

    }

    /** RSA Public key */
    @ConsistentCopyVisibility
    data class RSA
    @Throws(IllegalArgumentException::class)
    constructor(
        /** modulus */
        val n: Asn1Integer.Positive,

        /** public exponent */
        val e: Asn1Integer.Positive,
    ) : CryptoPublicKey() {

        val bits = n.bitLength().let { Size.of(it) ?: throw IllegalArgumentException("Unsupported key size $it bits") }

        /**
         * @throws IllegalArgumentException in case of illegal input (odd key size, for example)
         */
        @Throws(IllegalArgumentException::class)
        constructor(n: ByteArray, e: ByteArray) : this(Asn1Integer.fromUnsignedByteArray(n), Asn1Integer.fromUnsignedByteArray(e))

        constructor(n: ByteArray, e: Int): this(Asn1Integer.fromUnsignedByteArray(n), Asn1Integer(e) as Asn1Integer.Positive)

        constructor(n: Asn1Integer, e: Asn1Integer): this(n as Asn1Integer.Positive, e as Asn1Integer.Positive)

        override val oid = RSA.oid

        /**
         * enum of supported RSA key sizes. For sanity checks!
         */
        enum class Size(val number: UInt) {
            RSA_512(512u),
            RSA_1024(1024u),
            RSA_2048(2048u),
            RSA_3027(3072u),
            RSA_4096(4096u);

            companion object : Identifiable {
                fun of(numBits: UInt) = entries.find { it.number == numBits }

                override val oid = KnownOIDs.rsaEncryption
            }
        }

        /**
         * Returns `did:key:$MULTIBASE_ENCODING_IDENTIFIER$MULTICODEC_ALGORITHM_IDENTIFIER$BYTES` with all bytes after MULTIBASE_ENCODING_IDENTIFIER in the assigned encoding.
         * The Multicodec identifier for RSA is `0x1205` and the key bytes are represented as PKCS#1 encoding.
         */
        override val didEncoded by lazy {
            "$PREFIX_DID_KEY:" +
                    (UVarInt(0x1205u).encodeToByteArray() + this.pkcsEncoded).multibaseEncode(MultiBase.Base.BASE58_BTC)
        }

        override val iosEncoded by lazy { pkcsEncoded }

        /**
         * PKCS#1 encoded RSA Public Key
         */
        val pkcsEncoded by lazy {
            Asn1.Sequence {
                +Asn1.Int(n)
                +Asn1.Int(e)
            }.derEncoded
        }

        companion object : Identifiable {
            /**
             * decodes a PKCS#1-encoded RSA key
             *
             * @throws Asn1Exception all sorts of exceptions on invalid input
             */
            @Throws(Asn1Exception::class)
            fun fromPKCS1encoded(input: ByteArray): RSA = runRethrowing {
                val conv = Asn1Element.parse(input) as Asn1Sequence
                val n = (conv.nextChild() as Asn1Primitive).decodeToAsn1Integer() as Asn1Integer.Positive
                val e = (conv.nextChild() as Asn1Primitive).decodeToAsn1Integer() as Asn1Integer.Positive
                if (conv.hasMoreChildren()) throw Asn1StructuralException("Superfluous bytes")
                return RSA(n, e)
            }

            override val oid = KnownOIDs.rsaEncryption
        }
    }

    /**
     * EC public key representation
     * The properties and constructor params are exactly what their names suggest
     * @param preferCompressedRepresentation indicates whether to use point compression where applicable
     */
    @Serializable
    @SerialName("EC")
    @ConsistentCopyVisibility
    data class EC private constructor(
        val publicPoint: ECPoint.Normalized,
        val preferCompressedRepresentation: Boolean = true
    ) : CryptoPublicKey() {

        val curve get() = publicPoint.curve
        val x get() = publicPoint.x
        val xBytes get() = publicPoint.xBytes
        val y get() = publicPoint.y
        val yBytes get() = publicPoint.yBytes
        val yCompressed get() = publicPoint.yCompressed

        override val oid = EC.oid

        /**
         * ANSI X9.63 Encoding as used by iOS
         */
        fun toAnsiX963Encoded(useCompressed: Boolean = preferCompressedRepresentation): ByteArray =
            when (useCompressed) {
                true -> ANSIECPrefix.forSign(yCompressed) + xBytes
                false -> ANSIECPrefix.UNCOMPRESSED + xBytes + yBytes
            }

        /**
         * Returns `did:key:$MULTIBASE_ENCODING_IDENTIFIER$MULTICODEC_ALGORITHM_IDENTIFIER$BYTES` with all bytes after MULTIBASE_ENCODING_IDENTIFIER in the assigned encoding
         * Multicodec identifiers '0x120x' are draft identifiers for P-xxx keys with point compression
         *
         * 0x1200 P-256
         * 0x1201 P-384
         * 0x1202 P-512
         *
         * The keybytes are ANSI X9.63 encoded (important for compression)
         */
        override val didEncoded by lazy {
            val codec = when (curve) {
                ECCurve.SECP_256_R_1 -> 0x1200u
                ECCurve.SECP_384_R_1 -> 0x1201u
                ECCurve.SECP_521_R_1 -> 0x1202u
            }
            PREFIX_DID_KEY + ":" + MultiBase.encode(
                MultiBase.Base.BASE58_BTC,
                UVarInt(codec).encodeToByteArray() + this.toAnsiX963Encoded(useCompressed = true)
            )
        }

        override val iosEncoded by lazy { toAnsiX963Encoded(useCompressed = false) }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false

            other as EC

            return (this.publicPoint == other.publicPoint)
        }

        override fun hashCode() =
            publicPoint.hashCode()

        companion object : Identifiable {

            fun ECPoint.asPublicKey(preferCompressed: Boolean = false): EC {
                return EC(this.normalize(), preferCompressed)
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
                ReplaceWith("fromCompressed(curve, x, usePositiveY)")
            )
            @Suppress("NOTHING_TO_INLINE")
            inline operator fun invoke(curve: ECCurve, x: ByteArray, usePositiveY: Boolean) =
                fromCompressed(curve, x, usePositiveY)

            @Deprecated("Explicitly specify what you want", ReplaceWith("fromUncompressed(curve, x, y)"))
            @Suppress("NOTHING_TO_INLINE")
            inline operator fun invoke(curve: ECCurve, x: ByteArray, y: ByteArray) =
                fromUncompressed(curve, x, y)

            /** Decodes a key from its ANSI X9.63 representation */
            @Throws(Throwable::class)
            fun fromAnsiX963Bytes(curve: ECCurve, src: ByteArray): EC {
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

            override val oid = KnownOIDs.ecPublicKey
        }
    }
}

interface SpecializedCryptoPublicKey {
    fun toCryptoPublicKey(): KmmResult<CryptoPublicKey>
}

/** Alias of [equals] provided for convenience (and alignment with [SpecializedCryptoPublicKey]) */
fun CryptoPublicKey.equalsCryptographically(other: CryptoPublicKey) =
    equals(other)

/** Whether the actual underlying key (irrespective of any format-specific metadata) is equal */
fun SpecializedCryptoPublicKey.equalsCryptographically(other: CryptoPublicKey) =
    toCryptoPublicKey().map { it.equalsCryptographically(other) }.getOrElse { false }

/** Whether the actual underlying key (irrespective of any format-specific metadata) is equal */
fun SpecializedCryptoPublicKey.equalsCryptographically(other: SpecializedCryptoPublicKey) =
    toCryptoPublicKey().map { other.equalsCryptographically(it) }.getOrElse { false }

/** Whether the actual underlying key (irrespective of any format-specific metadata) is equal */
fun CryptoPublicKey.equalsCryptographically(other: SpecializedCryptoPublicKey) =
    other.equalsCryptographically(this)


private val PREFIX_DID_KEY = "did:key"

@Throws(Throwable::class)
private fun multiKeyRemovePrefix(keyId: String): String =
    keyId.takeIf { it.startsWith("$PREFIX_DID_KEY:") }?.removePrefix("$PREFIX_DID_KEY:")
        ?: throw IllegalArgumentException("Input does not specify public key")
