package at.asitplus.crypto.datatypes

import at.asitplus.crypto.datatypes.asn1.*
import at.asitplus.crypto.datatypes.io.ByteArrayBase64Serializer
import at.asitplus.crypto.datatypes.io.MultibaseHelper
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient

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
     * Multibase KID
     */
    @Transient
    abstract val keyId: String

    /**
     * Representation of this key in the same ways as iOS would encode it natively
     */
    @Transient
    abstract val iosEncoded: ByteArray

    override fun encodeToTlv() = when (this) {
        is Ec -> asn1Sequence {
            sequence {
                oid { oid }
                oid { curve.oid }
            }
            bitString {
                (byteArrayOf(BERTags.OCTET_STRING.toByte()) + x.ensureSize(curve.coordinateLengthBytes) + y.ensureSize(
                    curve.coordinateLengthBytes
                ))
            }
        }

        is Rsa -> {
            asn1Sequence {
                sequence {
                    oid { oid }
                    asn1null()
                }
                bitString(asn1Sequence {
                    append {
                        Asn1Primitive(
                            BERTags.INTEGER,
                            n.ensureSize(bits.number / 8u)
                                .let { if (it.first() == 0x00.toByte()) it else byteArrayOf(0x00, *it) })
                    }
                    int { e }
                })
            }
        }
    }

    companion object : Asn1Decodable<Asn1Sequence, CryptoPublicKey> {


        /**
         * Parses a KID and reconstructs a [CryptoPublicKey] from it
         *
         * @throws Throwable all sorts of exception on invalid input
         */
        fun fromKeyId(it: String): CryptoPublicKey? {
            val strippedKey = MultibaseHelper.stripKeyId(it)
            return MultibaseHelper.calcPublicKey(strippedKey)
        }

        override fun decodeFromTlv(src: Asn1Sequence): CryptoPublicKey {
            if (src.children.size != 2) throw IllegalArgumentException("Invalid SPKI Structure!")
            val keyInfo = src.nextChild() as Asn1Sequence
            if (keyInfo.children.size != 2) throw IllegalArgumentException("Superfluous data in  SPKI!")

            when (val oid = (keyInfo.nextChild() as Asn1Primitive).readOid()) {
                Ec.oid -> {
                    val curveOid = (keyInfo.nextChild() as Asn1Primitive).readOid()
                    val curve = EcCurve.entries.find { it.oid == curveOid }
                        ?: throw IllegalArgumentException("Curve not supported: $curveOid")

                    val bitString = (src.nextChild() as Asn1Primitive).readBitString()
                    val xAndY = bitString.drop(1).toByteArray()
                    val coordLen = curve.coordinateLengthBytes.toInt()
                    val x = xAndY.take(coordLen).toByteArray()
                    val y = xAndY.drop(coordLen).take(coordLen).toByteArray()
                    return Ec.fromCoordinates(curve, x, y)
                }

                Rsa.oid -> {
                    (keyInfo.nextChild() as Asn1Primitive).readNull()
                    val bitString = (src.nextChild() as Asn1Primitive).readBitString()
                    val rsaSequence = Asn1Element.parse(bitString) as Asn1Sequence
                    val n = (rsaSequence.nextChild() as Asn1Primitive).decode(BERTags.INTEGER) { it }
                    val e = (rsaSequence.nextChild() as Asn1Primitive).readInt()
                    if (rsaSequence.hasMoreChildren()) throw IllegalArgumentException("Superfluous data in SPKI!")
                    return Rsa(n, e)
                }

                else -> throw IllegalArgumentException("Unsupported Key Type: $oid")

            }
        }

        /**
         * Parses this key from an iOS-encoded one
         */
        fun fromIosEncoded(it: ByteArray): CryptoPublicKey =
            when (it[0].toInt()) {
                0x04 -> Ec.fromAnsiX963Bytes(it)
                DERTags.DER_SEQUENCE.toInt() -> Rsa.fromPKCS1encoded(it)
                else -> throw IllegalArgumentException("Unsupported Key type")
            }
    }

    /**
     * RSA Public key
     */
    @Serializable
    data class Rsa private constructor(
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

        private constructor(triple: Triple<ByteArray, Int, Size>) : this(
            triple.third,
            triple.first,
            triple.second
        )

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
                fun of(n: ByteArray): Size {
                    val nTruncSize = n.dropWhile { it == 0.toByte() }.size
                    return entries.find { nTruncSize == (it.number.toInt() / 8) }
                        ?: throw IllegalArgumentException("Unsupported key size $nTruncSize")
                }

                override val oid = KnownOIDs.rsaEncryption
            }
        }

        @Transient
        override val keyId by lazy { MultibaseHelper.calcKeyId(this) }

        /**
         * PKCS#1 encoded RSA Public Key
         */
        @Transient
        override val iosEncoded = asn1Sequence {
            append {
                Asn1Primitive(BERTags.INTEGER,
                    n.ensureSize(bits.number / 8u)
                        .let { if (it.first() == 0x00.toByte()) it else byteArrayOf(0x00, *it) })
            }
            int { e }
        }.derEncoded

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null) return false
            if (this::class != other::class) return false

            other as Rsa

            return iosEncoded.contentEquals(other.iosEncoded)
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
             * @throws Throwable all sorts of exceptions on invalid input
             */
            fun fromPKCS1encoded(input: ByteArray): Rsa {
                val conv = Asn1Element.parse(input) as Asn1Sequence
                val n = (conv.nextChild() as Asn1Primitive).decode(BERTags.INTEGER) { it }
                val e = (conv.nextChild() as Asn1Primitive).readInt()
                if (conv.hasMoreChildren()) throw IllegalArgumentException("Superfluous bytes")
                return Rsa(Size.of(n), n, e)
            }

            override val oid = KnownOIDs.rsaEncryption
        }
    }

    /**
     * EC public key representation
     * The properties and constructor params are exactly what their names suggest
     */
    @Serializable
    @SerialName("EC")
    data class Ec(
        val curve: EcCurve,
        @Serializable(with = ByteArrayBase64Serializer::class) val x: ByteArray,
        @Serializable(with = ByteArrayBase64Serializer::class) val y: ByteArray,
    ) : CryptoPublicKey() {

        override val oid = Ec.oid

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false

            other as Ec

            if (curve != other.curve) return false
            if (!iosEncoded.contentEquals(other.iosEncoded)) return false

            return true
        }

        override fun hashCode(): Int {
            var result = curve.hashCode()
            result = 31 * result + x.contentHashCode()
            result = 31 * result + y.contentHashCode()
            return result
        }

        companion object : Identifiable {
            /**
             * Decodes a key from the provided parameters
             */
            fun fromCoordinates(curve: EcCurve, x: ByteArray, y: ByteArray): Ec =
                Ec(curve = curve, x = x, y = y)

            /**
             * Decodes a key from its ANSI X9.63 representation
             */
            fun fromAnsiX963Bytes(src: ByteArray): CryptoPublicKey {
                if (src[0] != 0x04.toByte()) throw IllegalArgumentException("No EC key")
                val curve = EcCurve.entries
                    .find { 2 * it.coordinateLengthBytes.toInt() == src.size - 1 }
                    ?: throw IllegalArgumentException("Unknown Curve")
                val numBytes = curve.coordinateLengthBytes.toInt()
                val x = src.drop(1).take(numBytes).toByteArray()
                val y = src.drop(1).drop(numBytes).take(numBytes).toByteArray()
                return Ec(curve = curve, x = x, y = y)
            }

            override val oid = KnownOIDs.ecPublicKey
        }

        /**
         * ANSI X9.63 Encoding as used by iOS
         */
        @Transient
        override val iosEncoded =
            curve.coordinateLengthBytes.let { byteArrayOf(0x04.toByte()) + x.ensureSize(it) + y.ensureSize(it) }

        @Transient
        override val keyId = MultibaseHelper.calcKeyId(curve, x, y)
    }
}

private fun sanitizeRsaInputs(n: ByteArray, e: Int) = n.dropWhile { it == 0.toByte() }.toByteArray()
    .let { Triple(byteArrayOf(0, *it), e, CryptoPublicKey.Rsa.Size.of(it)) }

fun Asn1TreeBuilder.subjectPublicKey(block: () -> CryptoPublicKey) = apply { elements += block().encodeToTlv() }