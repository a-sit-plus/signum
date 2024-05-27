package at.asitplus.crypto.datatypes

import at.asitplus.crypto.datatypes.asn1.Identifiable
import at.asitplus.crypto.datatypes.asn1.KnownOIDs
import at.asitplus.crypto.datatypes.asn1.ObjectIdentifier
import at.asitplus.crypto.datatypes.misc.BitLength
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import com.ionspin.kotlin.bignum.integer.toBigInteger
import com.ionspin.kotlin.bignum.modular.ModularBigInteger
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

inline fun UInt.ceilDiv(other: UInt) =
    (floorDiv(other)) + (if (rem(other) != 0u) 1u else 0u)

/**
 * EC Curve Class [jwkName] really does use established JWK curve names
 */
@Serializable(with = ECCurveSerializer::class)
enum class ECCurve(
    val jwkName: String,
    override val oid: ObjectIdentifier,
) : Identifiable {

    SECP_256_R_1("P-256", KnownOIDs.prime256v1),
    SECP_384_R_1("P-384", KnownOIDs.secp384r1),
    SECP_521_R_1("P-521", KnownOIDs.secp521r1);

    val IDENTITY: ECPoint by lazy {
        ECPoint.General.unsafeFromXYZ(this, coordinateCreator.ZERO, coordinateCreator.ONE, coordinateCreator.ZERO)
    }

    /** the number of bits/bytes needed to store scalar multipliers (such as private keys) in unsigned form */
    inline val scalarLength get() = BitLength.of(order)

    /** the number of bits/bytes needed to store point coordinates (such as public key coordinates) in unsigned form */
    inline val coordinateLength get() = BitLength.of(modulus)

    @Deprecated("Use scalarLength to express private key lengths", ReplaceWith("scalarLength.bits"))
    /** the number of bits needed to store a private key in unsigned form */
    inline val keyLengthBits: UInt get() = scalarLength.bits

    @Deprecated("Use coordinateLength.bytes", ReplaceWith("coordinateLength.bytes"))
    /** the number of bytes needed to store a public key coordinate in unsigned form */
    inline val coordinateLengthBytes: UInt get() = coordinateLength.bytes

    @Deprecated("use scalarLength to express raw signature size", ReplaceWith("scalarLength.bytes * 2u"))
    /** the number of bytes needed to store a raw signature (r and s concatenated) over this curve */
    inline val signatureLengthBytes: UInt get() = scalarLength.bytes*2u

    internal val coordinateCreator by lazy { ModularBigInteger.creatorForModulo(this.modulus) }
    internal val scalarCreator by lazy { ModularBigInteger.creatorForModulo(this.order) }
    
    /**
     * p: Prime modulus of the underlying prime field
     * See https://www.secg.org/sec2-v2.pdf
     */
    val modulus: BigInteger by lazy {
        when (this) {
            SECP_256_R_1 ->
                "FFFFFFFF 00000001 00000000 00000000 00000000 FFFFFFFF FFFFFFFF FFFFFFFF"

            SECP_384_R_1 ->
                "FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE" +
                "FFFFFFFF 00000000 00000000 FFFFFFFF"

            SECP_521_R_1 ->
                    "01FF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF" +
                "FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF" +
                "FFFFFFFF"

        }.replace(" ", "").toBigInteger(16)
    }

    /**
     * a: Curve equation coefficient
     * See https://www.secg.org/sec2-v2.pdf
     */
    val a: ModularBigInteger by lazy {
        when (this) {
            SECP_256_R_1 ->
                "FFFFFFFF 00000001 00000000 00000000 00000000 FFFFFFFF FFFFFFFF FFFFFFFC"

            SECP_384_R_1 ->
                "FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE" +
                "FFFFFFFF 00000000 00000000 FFFFFFFC"

            SECP_521_R_1 ->
                    "01FF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF" +
                "FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF" +
                "FFFFFFFC"
        }.let {
            coordinateCreator.parseString(string = it.replace(" ", ""), base = 16)
        }
    }

    /**
     * b: Curve equation coefficient
     * See https://www.secg.org/sec2-v2.pdf
     */
    val b: ModularBigInteger by lazy {
        when (this) {
            SECP_256_R_1 ->
                "5AC635D8 AA3A93E7 B3EBBD55 769886BC 651D06B0 CC53B0F6 3BCE3C3E 27D2604B"

            SECP_384_R_1 ->
                "B3312FA7 E23EE7E4 988E056B E3F82D19 181D9C6E FE814112 0314088F 5013875A" +
                "C656398D 8A2ED19D 2A85C8ED D3EC2AEF"

            SECP_521_R_1 ->
                    "0051 953EB961 8E1C9A1F 929A21A0 B68540EE A2DA725B 99B315F3 B8B48991" +
                "8EF109E1 56193951 EC7E937B 1652C0BD 3BB1BF07 3573DF88 3D2C34F1 EF451FD4" +
                "6B503F00"
        }.let {
            coordinateCreator.parseString(string = it.replace(" ", ""), base = 16)
        }
    }

    /**
     * G: Generator of cyclic curve subgroup
     * See https://www.secg.org/sec2-v2.pdf
     */
    val generator: ECPoint.Normalized by lazy {
        when (this) {
            SECP_256_R_1 ->
                      "04 6B17D1F2 E12C4247 F8BCE6E5 63A440F2 77037D81 2DEB33A0" +
                "F4A13945 D898C296 4FE342E2 FE1A7F9B 8EE7EB4A 7C0F9E16 2BCE3357" +
                "6B315ECE CBB64068 37BF51F5"
            SECP_384_R_1 ->
                     "04 AA87CA22 BE8B0537 8EB1C71E F320AD74 6E1D3B62 8BA79B98" +
               "59F741E0 82542A38 5502F25D BF55296C 3A545E38 72760AB7 3617DE4A" +
               "96262C6F 5D9E98BF 9292DC29 F8F41DBD 289A147C E9DA3113 B5F0B8C0" +
               "0A60B1CE 1D7E819D 7A431D7C 90EA0E5F"
            SECP_521_R_1 ->
                     "04 00C6858E 06B70404 E9CD9E3E CB662395 B4429C64 8139053F" +
               "B521F828 AF606B4D 3DBAA14B 5E77EFE7 5928FE1D C127A2FF A8DE3348" +
               "B3C1856A 429BF97E 7E31C2E5 BD660118 39296A78 9A3BC004 5C8A5FB4" +
               "2C7D1BD9 98F54449 579B4468 17AFBD17 273E662C 97EE7299 5EF42640" +
               "C550B901 3FAD0761 353C7086 A272C240 88BE9476 9FD16650"
        }.replace(" ","").chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            .let { CryptoPublicKey.EC.fromAnsiX963Bytes(this, it).publicPoint }
    }

    /**
     * n: Order of (the cyclic subgroup generated by) G
     * See https://www.secg.org/sec2-v2.pdf
     */
    val order: BigInteger by lazy {
        when(this) {
            SECP_256_R_1 ->
                "FFFFFFFF 00000000 FFFFFFFF FFFFFFFF BCE6FAAD A7179E84 F3B9CAC2" +
                "FC632551"
            SECP_384_R_1 ->
                "FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF C7634D81" +
                "F4372DDF 581A0DB2 48B0A77A ECEC196A CCC52973"
            SECP_521_R_1 ->
                "01FF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF" +
                "FFFFFFFF FFFFFFFA 51868783 BF2F966B 7FCC0148 F709A5D0 3BB5C9B8" +
                "899C47AE BB6FB71E 91386409"
        }.replace (" ", "").toBigInteger(16)
    }

    /**
     * h: Cofactor of the cyclic subgroup generated by G
     * See https://www.secg.org/sec2-v2.pdf
     */
    val cofactor: Int get() =
        when(this) {
            SECP_256_R_1 -> 1
            SECP_384_R_1 -> 1
            SECP_521_R_1 -> 1
        }

    companion object {
        fun of(bits: UInt) = entries.find { it.scalarLength.bits == bits }
    }

}

object ECCurveSerializer : KSerializer<ECCurve> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("EcCurveSerializer", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: ECCurve) {
        encoder.encodeString(value.jwkName)
    }

    override fun deserialize(decoder: Decoder): ECCurve {
        val decoded = decoder.decodeString()
        return ECCurve.entries.firstOrNull { it.jwkName == decoded }
            ?: throw SerializationException("Unsupported EC Curve Type $decoded")
    }

}
