package at.asitplus.crypto.datatypes

import at.asitplus.crypto.datatypes.asn1.*
import at.asitplus.crypto.datatypes.io.ByteArrayBase64Serializer
import at.asitplus.crypto.datatypes.io.MultibaseHelper
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient

@Serializable
sealed class CryptoPublicKey : Asn1Encodable<Asn1Sequence> {

    //must be serializable, therefore <String,String>
    val additionalProperties = mutableMapOf<String, String>()

    @Transient
    abstract val keyId: String

    @Transient
    abstract val iosEncoded: ByteArray

    override fun encodeToTlv() = when (this) {
        is Ec -> asn1Sequence {
            sequence {
                oid { KnownOIDs.ecPublicKey }
                when (curve) {
                    EcCurve.SECP_256_R_1 -> oid { KnownOIDs.prime256v1 }
                    EcCurve.SECP_384_R_1 -> oid { KnownOIDs.secp384r1 }
                    EcCurve.SECP_521_R_1 -> oid { KnownOIDs.secp521r1 }
                }
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
                    oid { KnownOIDs.rsaEncryption }
                    asn1null()
                }
                bitString(asn1Sequence {
                    append {
                        Asn1Primitive(
                            BERTags.INTEGER,
                            n.ensureSize(bits.number / 8u)
                                .let { if (it.first() == 0x00.toByte()) it else byteArrayOf(0x00, *it) })
                    }
                    append { Asn1Primitive(BERTags.INTEGER, e) }
                })
            }
        }
    }

    companion object : Asn1Decodable<Asn1Sequence, CryptoPublicKey> {

        fun fromKeyId(it: String): CryptoPublicKey? {
            val (xCoordinate, yCoordinate) = MultibaseHelper.calcEcPublicKeyCoords(it)
                ?: return null
            val curve = EcCurve.entries.find { it.coordinateLengthBytes.toInt() == xCoordinate.size } ?: return null
            return Ec(curve = curve, x = xCoordinate, y = yCoordinate)
        }

        override fun decodeFromTlv(src: Asn1Sequence): CryptoPublicKey {
            if (src.children.size != 2) throw IllegalArgumentException("Invalid SPKI Structure!")
            val keyInfo = src.nextChild() as Asn1Sequence
            if (keyInfo.children.size != 2) throw IllegalArgumentException("Superfluous data in  SPKI!")

            val oid = (keyInfo.nextChild() as Asn1Primitive).readOid()

            if (oid == KnownOIDs.ecPublicKey) {
                val curveOid = (keyInfo.nextChild() as Asn1Primitive).readOid()
                val curve = when (curveOid) {
                    KnownOIDs.prime256v1 -> at.asitplus.crypto.datatypes.EcCurve.SECP_256_R_1
                    KnownOIDs.secp384r1 -> at.asitplus.crypto.datatypes.EcCurve.SECP_384_R_1
                    KnownOIDs.secp521r1 -> at.asitplus.crypto.datatypes.EcCurve.SECP_521_R_1
                    else -> throw IllegalArgumentException("Curve not supported: $curveOid")
                }
                val bitString = (src.nextChild() as Asn1Primitive).readBitString()
                val xAndY = bitString.drop(1).toByteArray()
                val coordLen = curve.coordinateLengthBytes.toInt()
                val x = xAndY.take(coordLen).toByteArray()
                val y = xAndY.drop(coordLen).take(coordLen).toByteArray()
                return Ec.fromCoordinates(curve, x, y)
            } else if (oid == KnownOIDs.rsaEncryption) {
                (keyInfo.nextChild() as Asn1Primitive).readNull()
                val bitString = (src.nextChild() as Asn1Primitive).readBitString()
                val rsaSequence = Asn1Element.parse(bitString) as Asn1Sequence
                val n = (rsaSequence.nextChild() as Asn1Primitive).decode(BERTags.INTEGER) { it }
                val e = (rsaSequence.nextChild() as Asn1Primitive).decode(BERTags.INTEGER) { it }
                if (rsaSequence.hasMoreChildren()) throw IllegalArgumentException("Superfluous data in SPKI!")
                return Rsa(n, e)
            } else {
                throw IllegalArgumentException("Unsupported Key Type: $oid")
            }
        }

        fun fromIosEncoded(it: ByteArray): CryptoPublicKey =
            when (it[0].toInt()) {
                0x04 -> Ec.fromAnsiX963Bytes(it)
                DERTags.DER_SEQUENCE.toInt() -> Rsa.fromPKCS1encoded(it)
                else -> throw IllegalArgumentException("Unsupported Key type")
            }
    }

    @Serializable
    data class Rsa private constructor(
        val bits: Size,
        @Serializable(with = ByteArrayBase64Serializer::class) val n: ByteArray,
        val e: ByteArray,
    ) : CryptoPublicKey() {

        private constructor(triple: Triple<ByteArray, ByteArray, Size>) : this(
            triple.third,
            triple.first,
            triple.second
        )

        constructor(n: ByteArray, e: ByteArray) : this(sanitizeRsaInputs(n, e))

        enum class Size(val number: UInt) {
            RSA_512(512u),
            RSA_1024(1024u),
            RSA_2048(2048u),
            RSA_3027(3072u),
            RSA_4096(4096u);


            companion object {
                fun of(numBits: UInt) = entries.find { it.number == numBits }
                fun of(n: ByteArray) = entries.find { n.size <= (it.number.toInt() / 8 + 1) }
                    ?: throw IllegalArgumentException("Unsupported key size ${n.size}")
            }
        }

        @Transient
        override val keyId by lazy { MultibaseHelper.calcKid(this) }

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
            append { Asn1Primitive(BERTags.INTEGER, e) }
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

        companion object {
            fun fromPKCS1encoded(input: ByteArray): Rsa {
                val conv = Asn1Element.parse(input) as Asn1Sequence
                val n = (conv.nextChild() as Asn1Primitive).decode(BERTags.INTEGER) { it }
                val e = (conv.nextChild() as Asn1Primitive).decode(BERTags.INTEGER) { it }
                if (conv.hasMoreChildren()) throw IllegalArgumentException("Superfluous bytes")
                return Rsa(Size.of(n), n, e)
            }
        }
    }

    @Serializable
    @SerialName("EC")
    data class Ec(
        val curve: EcCurve,
        @Serializable(with = ByteArrayBase64Serializer::class) val x: ByteArray,
        @Serializable(with = ByteArrayBase64Serializer::class) val y: ByteArray,
    ) : CryptoPublicKey() {
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

        companion object {
            fun fromCoordinates(curve: EcCurve, x: ByteArray, y: ByteArray): Ec =
                Ec(curve = curve, x = x, y = y)

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

private fun sanitizeRsaInputs(n: ByteArray, e: ByteArray) = n.dropWhile { it == 0.toByte() }.toByteArray()
    .let { Triple(it, e.dropWhile { it == 0.toByte() }.toByteArray(), CryptoPublicKey.Rsa.Size.of(it)) }