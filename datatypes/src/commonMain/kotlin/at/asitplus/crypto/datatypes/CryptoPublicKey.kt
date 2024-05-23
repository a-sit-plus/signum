package at.asitplus.crypto.datatypes

import at.asitplus.crypto.datatypes.asn1.Asn1Decodable
import at.asitplus.crypto.datatypes.asn1.Asn1Element
import at.asitplus.crypto.datatypes.asn1.Asn1Encodable
import at.asitplus.crypto.datatypes.asn1.Asn1Exception
import at.asitplus.crypto.datatypes.asn1.Asn1Primitive
import at.asitplus.crypto.datatypes.asn1.Asn1Sequence
import at.asitplus.crypto.datatypes.asn1.Asn1StructuralException
import at.asitplus.crypto.datatypes.asn1.BERTags
import at.asitplus.crypto.datatypes.asn1.DERTags
import at.asitplus.crypto.datatypes.asn1.Identifiable
import at.asitplus.crypto.datatypes.asn1.KnownOIDs
import at.asitplus.crypto.datatypes.asn1.asn1Sequence
import at.asitplus.crypto.datatypes.asn1.decode
import at.asitplus.crypto.datatypes.asn1.ensureSize
import at.asitplus.crypto.datatypes.asn1.parse
import at.asitplus.crypto.datatypes.asn1.readBitString
import at.asitplus.crypto.datatypes.asn1.readInt
import at.asitplus.crypto.datatypes.asn1.readNull
import at.asitplus.crypto.datatypes.asn1.readOid
import at.asitplus.crypto.datatypes.asn1.runRethrowing
import at.asitplus.crypto.datatypes.io.ByteArrayBase64Serializer
import at.asitplus.crypto.datatypes.io.MultiBase
import at.asitplus.crypto.datatypes.misc.*
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
        is EC -> asn1Sequence {
            sequence {
                append(oid)
                append(curve.oid)
            }
            bitString(iosEncoded)
        }

        is Rsa -> {
            asn1Sequence {
                sequence {
                    append(oid)
                    asn1null()
                }
                bitString(iosEncoded)
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
            val decoded = MultiBase.decode(bytes)
            val codec = UVarInt.fromByteArray(decoded.sliceArray(0..1)).toULong()
            val keyBytes = decoded.copyOfRange(2, decoded.size)

            return when (codec) {
                0x1200uL, 0x1290uL ->
                    EC.fromAnsiX963Bytes(ECCurve.SECP_256_R_1, keyBytes)
                0x1201uL, 0x1291uL ->
                    EC.fromAnsiX963Bytes(ECCurve.SECP_384_R_1, keyBytes)
                0x1202uL, 0x1292uL ->
                    EC.fromAnsiX963Bytes(ECCurve.SECP_521_R_1, keyBytes)

                0x1205uL ->
                    Rsa.fromPKCS1encoded(keyBytes)

                else ->
                    throw IllegalArgumentException("Unknown public key identifier $codec")
            }
        }


        @Throws(Asn1Exception::class)
        override fun decodeFromTlv(src: Asn1Sequence): CryptoPublicKey = runRethrowing {
            if (src.children.size != 2) throw Asn1StructuralException("Invalid SPKI Structure!")
            val keyInfo = src.nextChild() as Asn1Sequence
            if (keyInfo.children.size != 2) throw Asn1StructuralException("Superfluous data in  SPKI!")

            when (val oid = (keyInfo.nextChild() as Asn1Primitive).readOid()) {
                EC.oid -> {
                    val curveOid = (keyInfo.nextChild() as Asn1Primitive).readOid()
                    val curve = ECCurve.entries.find { it.oid == curveOid }
                        ?: throw Asn1Exception("Curve not supported: $curveOid")

                    val bitString = (src.nextChild() as Asn1Primitive).readBitString()
                    if (bitString.rawBytes.first() != ANSIECPrefix.UNCOMPRESSED.prefixByte) throw Asn1Exception("EC key not prefixed with 0x04")
                    val xAndY = bitString.rawBytes.drop(1)
                    val coordLen = curve.coordinateLengthBytes.toInt()
                    val x = xAndY.take(coordLen).toByteArray()
                    val y = xAndY.drop(coordLen).take(coordLen).toByteArray()
                    return EC(curve, x, y)
                }

                Rsa.oid -> {
                    (keyInfo.nextChild() as Asn1Primitive).readNull()
                    val bitString = (src.nextChild() as Asn1Primitive).readBitString()
                    val rsaSequence = Asn1Element.parse(bitString.rawBytes) as Asn1Sequence
                    val n = (rsaSequence.nextChild() as Asn1Primitive).decode(BERTags.INTEGER) { it }
                    val e = (rsaSequence.nextChild() as Asn1Primitive).readInt()
                    if (rsaSequence.hasMoreChildren()) throw Asn1StructuralException("Superfluous data in SPKI!")
                    return Rsa(n, e)
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
                DERTags.DER_SEQUENCE -> Rsa.fromPKCS1encoded(it)
                else -> throw IllegalArgumentException("Unsupported Key type")
            }
    }

    /**
     * RSA Public key
     */
    @Serializable
    data class Rsa
    @Throws(IllegalArgumentException::class)
    private constructor(
        /**
         * RSA key size
         */
        val bits: Size,

        /**
         * modulus
         */
        @Serializable(with = ByteArrayBase64Serializer::class) val n: ByteArray,

        /**
         * public exponent
         */
        val e: Int,
    ) : CryptoPublicKey() {

        init {
            val computed = Size.of(n)
            if (bits != computed) throw IllegalArgumentException("Provided number of bits (${bits.number}) does not match computed number of bits (${computed.number})")
        }

        @Throws(IllegalArgumentException::class)
        private constructor(params: RsaParams) : this(
            params.size,
            params.n,
            params.e
        )

        /**
         * @throws IllegalArgumentException in case of illegal input (odd key size, for example)
         */
        @Throws(IllegalArgumentException::class)
        constructor(n: ByteArray, e: Int) : this(sanitizeRsaInputs(n, e))

        override val oid = Rsa.oid

        /**
         * enum of supported RSA key sized. For sanity checks!
         */
        enum class Size(val number: UInt) {
            RSA_512(512u),
            RSA_1024(1024u),
            RSA_2048(2048u),
            RSA_3027(3072u),
            RSA_4096(4096u);

            companion object : Identifiable {
                fun of(numBits: UInt) = entries.find { it.number == numBits }

                @Throws(IllegalArgumentException::class)
                fun of(n: ByteArray): Size {
                    val nTruncSize = n.dropWhile { it == 0.toByte() }.size
                    return entries.find { nTruncSize == (it.number.toInt() / 8) }
                        ?: throw IllegalArgumentException("Unsupported key size $nTruncSize")
                }

                override val oid = KnownOIDs.rsaEncryption
            }
        }

        /**
         * Returns `did:key:$MULTIBASE_ENCODING_IDENTIFIER$MULTICODEC_ALGORITHM_IDENTIFIER$BYTES` with all bytes after MULTIBASE_ENCODING_IDENTIFIER in the assigned encoding.
         * The Multicodec identifier for RSA is `0x1205` and the key bytes are represented as PKCS#1 encoding.
         */
        override val didEncoded by lazy {
            PREFIX_DID_KEY + ":" + MultiBase.encode(
                MultiBase.Base.BASE58_BTC,
                UVarInt(0x1205u).encodeToByteArray() + this.pkcsEncoded
            )
        }

        override val iosEncoded by lazy { pkcsEncoded }

        /**
         * PKCS#1 encoded RSA Public Key
         */
        val pkcsEncoded by lazy {
            asn1Sequence {
                append(
                    Asn1Primitive(
                        BERTags.INTEGER,
                        n.ensureSize(bits.number / 8u)
                            .let { if (it.first() == 0x00.toByte()) it else byteArrayOf(0x00, *it) })
                )
                int(e)
            }.derEncoded
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null) return false
            if (this::class != other::class) return false

            other as Rsa

            return pkcsEncoded.contentEquals(other.pkcsEncoded)
        }

        override fun hashCode(): Int {
            var result = bits.hashCode()
            result = 31 * result + n.contentHashCode()
            result = 31 * result + e.hashCode()
            return result
        }

        companion object : Identifiable {
            /**
             * decodes a PKCS#1-encoded RSA key
             *
             * @throws Asn1Exception all sorts of exceptions on invalid input
             */
            @Throws(Asn1Exception::class)
            fun fromPKCS1encoded(input: ByteArray): Rsa = runRethrowing {
                val conv = Asn1Element.parse(input) as Asn1Sequence
                val n = (conv.nextChild() as Asn1Primitive).decode(BERTags.INTEGER) { it }
                val e = (conv.nextChild() as Asn1Primitive).readInt()
                if (conv.hasMoreChildren()) throw Asn1StructuralException("Superfluous bytes")
                return Rsa(Size.of(n), n, e)
            }

            override val oid = KnownOIDs.rsaEncryption
        }
    }

    /**
     * EC public key representation
     * The properties and constructor params are exactly what their names suggest
     * @param useCompressedRepresentation indicates whether to use point compression where applicable
     */
    @Serializable
    @SerialName("EC")
    data class EC private constructor(
        val publicPoint: ECPoint,
        var useCompressedRepresentation: Boolean,
    ) : CryptoPublicKey() {

        /**
         * Constructor for compressed keys
         */
        constructor(
            curve: ECCurve,
            x: ByteArray,
            sign: Sign,
        ) : this(ECPoint.fromCompressed(curve, x, sign), true)

        /** Constructor for compressed keys */
        constructor(
            curve: ECCurve,
            x: ByteArray,
            usePositiveY: Boolean,
        ) : this(ECPoint.fromCompressed(curve, x, usePositiveY), true)

        /**
         * Constructor for uncompressed keys
         */
        constructor(
            curve: ECCurve,
            x: ByteArray,
            y: ByteArray,
        ) : this(ECPoint.fromUncompressed(curve, x, y), false)

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
        fun toAnsiX963Encoded(): ByteArray =
            when (useCompressedRepresentation) {
                true -> {
                    byteArrayOf(
                        ANSIECPrefix.forSign(yCompressed).prefixByte,
                        *xBytes
                    )
                }

                false -> byteArrayOf(
                    ANSIECPrefix.UNCOMPRESSED.prefixByte,
                    *xBytes,
                    *yBytes
                )
            }

        /**
         * Returns `did:key:$MULTIBASE_ENCODING_IDENTIFIER$MULTICODEC_ALGORITHM_IDENTIFIER$BYTES` with all bytes after MULTIBASE_ENCODING_IDENTIFIER in the assigned encoding
         * We use '0x129x' to identify uncompressed EC keys of their respective size, these are not officially used identifiers.
         * Multicodec identifiers '0x120x' are draft identifiers for P-xxx keys with point compression
         *
         * 0x1200 P-256
         * 0x1201 P-384
         * 0x1202 P-512
         *
         * 0x1290 P-256
         * 0x1291 P-384
         * 0x1292 P-512
         *
         * The keybytes are ANSI X9.63 encoded (important for compression)
         */
        override val didEncoded by lazy {
            val codec = when (curve) {
                ECCurve.SECP_256_R_1 -> if (useCompressedRepresentation) 0x1200u else 0x1290u
                ECCurve.SECP_384_R_1 -> if (useCompressedRepresentation) 0x1201u else 0x1291u
                ECCurve.SECP_521_R_1 -> if (useCompressedRepresentation) 0x1202u else 0x1292u
            }
            PREFIX_DID_KEY + ":" + MultiBase.encode(
                MultiBase.Base.BASE58_BTC,
                UVarInt(codec).encodeToByteArray() + this.toAnsiX963Encoded()
            )
        }

        override val iosEncoded by lazy { toAnsiX963Encoded() }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false

            other as EC

            return (this.publicPoint == other.publicPoint)
        }

        override fun hashCode() =
            publicPoint.hashCode()

        companion object : Identifiable {

            /**
             * Decodes a key from its ANSI X9.63 representation
             */
            @Throws(Throwable::class)
            fun fromAnsiX963Bytes(curve: ECCurve, src: ByteArray): EC {
                val numBytes = curve.coordinateLength.bytes.toInt()

                val prefix = runCatching { ANSIECPrefix.fromPrefixByte(src[0]) }
                    .getOrElse { throw IllegalArgumentException("Invalid X9.63 EC key format") }

                if (prefix.isUncompressed) {
                    require(src.size == (2*numBytes + 1))
                    val x = src.copyOfRange(1, numBytes+1)
                    val y = src.copyOfRange(numBytes+1, 2*numBytes+1)
                    return EC(curve, x, y)
                } else {
                    require(src.size == (numBytes + 1))
                    val x = src.copyOfRange(1, src.size)
                    return EC(curve, x, prefix.compressionSign)
                }
            }

            override val oid = KnownOIDs.ecPublicKey
        }
    }
}


//Helper typealias, for helper sanitization function. Enables passing all params along constructors for constructor chaining
private typealias RsaParams = Triple<ByteArray, Int, CryptoPublicKey.Rsa.Size>

private val RsaParams.n get() = first
private val RsaParams.e get() = second
private val RsaParams.size get() = third

/**
 * Sanitizes RSA parameters and maps it to the correct [CryptoPublicKey.Rsa.Size] enum
 * This function lives here and returns a typealiased Triple to allow for constructor chaining.
 * If we were to change the primary constructor, we'd need to write a custom serializer
 */
@Throws(IllegalArgumentException::class)
private fun sanitizeRsaInputs(n: ByteArray, e: Int): RsaParams = n.dropWhile { it == 0.toByte() }.toByteArray()
    .let { Triple(byteArrayOf(0, *it), e, CryptoPublicKey.Rsa.Size.of(it)) }


private val PREFIX_DID_KEY = "did:key"
@Throws(Throwable::class)
private fun multiKeyRemovePrefix(keyId: String): String =
    keyId.takeIf { it.startsWith("$PREFIX_DID_KEY:") }?.removePrefix("$PREFIX_DID_KEY:")
        ?: throw IllegalArgumentException("Input does not specify public key")