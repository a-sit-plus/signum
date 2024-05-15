package at.asitplus.crypto.datatypes

import at.asitplus.crypto.datatypes.asn1.Identifiable
import at.asitplus.crypto.datatypes.asn1.KnownOIDs
import at.asitplus.crypto.datatypes.asn1.ObjectIdentifier
import com.ionspin.kotlin.bignum.integer.BigInteger
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

/**
 * EC Curve Class [jwkName] really does use established JWK curve names
 */
@Serializable(with = ECCurveSerializer::class)
enum class ECCurve(
    val jwkName: String,
    val keyLengthBits: UInt,
    val coordinateLengthBytes: UInt = keyLengthBits / 8u,
    val signatureLengthBytes: UInt = coordinateLengthBytes * 2u,
    override val oid: ObjectIdentifier,
) : Identifiable {

    SECP_256_R_1("P-256", 256u, oid = KnownOIDs.prime256v1),
    SECP_384_R_1("P-384", 384u, oid = KnownOIDs.secp384r1),
    SECP_521_R_1("P-521", 521u, 66u, oid = KnownOIDs.secp521r1);

    val modCreator by lazy { ModularBigInteger.creatorForModulo(this.modulus) }
    
    /**
     * See https://www.secg.org/sec2-v2.pdf
     */
    val modulus: BigInteger by lazy {
        when (this) {
            SECP_256_R_1 ->
                "FFFFFFFF 00000001 00000000 00000000 00000000 FFFFFFFF FFFFFFFF FFFFFFFF"
                    .replace(" ", "")
                    .toBigInteger(16)

            SECP_384_R_1 ->
                "FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFFFF 00000000 00000000 FFFFFFFF"
                    .replace(" ", "")
                    .toBigInteger(16)

            SECP_521_R_1 ->
                "01FF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF"
                    .replace(" ", "")
                    .toBigInteger(16)

        }
    }

    /**
     * See https://www.secg.org/sec2-v2.pdf
     */
    val a: ModularBigInteger by lazy {
        val aString = when (this) {
            SECP_256_R_1 ->
                "FFFFFFFF 00000001 00000000 00000000 00000000 FFFFFFFF FFFFFFFF FFFFFFFC"
                    .replace(" ", "")

            SECP_384_R_1 ->
                "FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFFFF 00000000 00000000 FFFFFFFC"
                    .replace(" ", "")

            SECP_521_R_1 ->
                "01FF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFC"
                    .replace(" ", "")
        }
        modCreator.parseString(string = aString, base = 16)
    }

    /**
     * See https://www.secg.org/sec2-v2.pdf
     */
    val b: ModularBigInteger by lazy {
        val bString = when (this) {
            SECP_256_R_1 ->
                "5AC635D8 AA3A93E7 B3EBBD55 769886BC 651D06B0 CC53B0F6 3BCE3C3E 27D2604B"
                    .replace(" ", "")

            SECP_384_R_1 ->
                "B3312FA7 E23EE7E4 988E056B E3F82D19 181D9C6E FE814112 0314088F 5013875A C656398D 8A2ED19D 2A85C8ED D3EC2AEF"
                    .replace(" ", "")

            SECP_521_R_1 ->
                "0051 953EB961 8E1C9A1F 929A21A0 B68540EE A2DA725B 99B315F3 B8B48991 8EF109E1 56193951 EC7E937B 1652C0BD 3BB1BF07 3573DF88 3D2C34F1 EF451FD4 6B503F00"
                    .replace(" ", "")
        }
        modCreator.parseString(string = bString, base = 16)
    }

    companion object {
        fun of(bits: UInt) = entries.find { it.keyLengthBits == bits }
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
